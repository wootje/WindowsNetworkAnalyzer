# Deterministic Linux-compatible contract tests; no Windows security policy is touched.
$ErrorActionPreference='Stop'
Set-StrictMode -Version Latest
Add-Type -TypeDefinition @'
using System;
namespace NrCapture {
    public static class Native {
        public static UInt32 Flags=4;
        public static int Writes=0;
        public static bool FailWrites=false;
        public static UInt32 GetFlags(Guid guid) { return Flags; }
        public static void SetFlags(Guid guid, UInt32 flags) {
            if (FailWrites) throw new Exception("Simulated policy refusal");
            Writes++; Flags=(flags==0 ? 4U : flags);
        }
        public static string GetDevicePath(string drive) { return null; }
    }
}
'@
. (Join-Path (Split-Path -Parent $PSScriptRoot) 'WindowsCapture.ps1')
function Assert-Equal($Expected,$Actual,[string]$Message) {
    if ($Expected -cne $Actual) { throw "$Message. Expected <$Expected>, actual <$Actual>" }
}
function Assert-True([bool]$Actual,[string]$Message) { if (-not $Actual) { throw $Message } }
function Assert-Throws([scriptblock]$Action,[string]$Message) {
    $didThrow=$false
    try { & $Action | Out-Null } catch { $didThrow=$true }
    if (-not $didThrow) { throw ('Expected exception: '+$Message) }
}
function Test-NrAdministrator { return $true }
function Get-NrSecurityLogNewestId { return 42L }
function Get-NrDeviceMap { return @{ '\Device\HarddiskVolume2'='C:' } }

$testDirectory=Join-Path ([IO.Path]::GetTempPath()) ('NrCaptureTests-'+[guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $testDirectory | Out-Null
$oldComputer=$env:COMPUTERNAME
$oldSystemRoot=$env:SystemRoot
$env:SystemRoot='D:\Windows'
$env:COMPUTERNAME='NR-Test-Computer'
try {
    # Disabled, success-only, failure-only and already-enabled policies must all survive.
    foreach ($original in @(0,1,2,3,4)) {
        [NrCapture.Native]::Flags=[uint32]$original
        $backup=Join-Path $testDirectory ('recovery-'+$original+'.json')
        $session=Start-NrWfpCapture -RecoveryPath $backup
        Assert-Equal 3 ([int][NrCapture.Native]::Flags) 'Capture must enable both audit bits'
        Assert-Equal 42L $session.LastRecordId 'Cursor initialized before enabling'
        $saved=Get-Content -LiteralPath $backup -Raw | ConvertFrom-Json
        Assert-Equal $original ([int]$saved.OriginalFlags) 'Backup retains original flags'
        Assert-Throws { Start-NrWfpCapture -RecoveryPath (Join-Path $testDirectory 'second.json') } 'Nested captures are rejected'
        Stop-NrWfpCapture -Session $session
        Assert-Equal ($original -band 3) ([int][NrCapture.Native]::Flags -band 3) 'Original policy restored'
        Assert-True (-not (Test-Path -LiteralPath $backup)) 'Recovery file removed only after restore'
        Assert-True $session.Stopped 'Session marked stopped'
        Stop-NrWfpCapture -Session $session
        Assert-True ($null -eq $script:NrCaptureMutex) 'Mutex released after stop'
    }

    # A policy changed by another administrator is preserved and recovery stays reviewable.
    [NrCapture.Native]::Flags=4
    $backup=Join-Path $testDirectory 'concurrent.json'
    $session=Start-NrWfpCapture -RecoveryPath $backup
    [NrCapture.Native]::Flags=1
    Assert-Throws { Stop-NrWfpCapture -Session $session } 'Concurrent policy change must not be overwritten'
    Assert-Equal 1 ([int][NrCapture.Native]::Flags) 'Concurrent policy retained'
    Assert-True (Test-Path -LiteralPath $backup) 'Recovery retained on conflict'
    Assert-True ($null -eq $script:NrCaptureMutex) 'Mutex released on restoration failure'
    [NrCapture.Native]::Flags=3
    Restore-NrWfpAuditPolicy -RecoveryPath $backup | Out-Null
    Assert-Equal 4 ([int][NrCapture.Native]::Flags) 'Manual recovery restores disabled state'

    # If starting fails before mutation, do not leave a mutex or bogus recovery behind.
    [NrCapture.Native]::Flags=4
    [NrCapture.Native]::FailWrites=$true
    $backup=Join-Path $testDirectory 'refused.json'
    Assert-Throws { Start-NrWfpCapture -RecoveryPath $backup } 'Policy refusal surfaces'
    [NrCapture.Native]::FailWrites=$false
    Assert-True ($null -eq $script:NrCaptureMutex) 'Mutex released after failed start'
    Assert-True (-not (Test-Path -LiteralPath $backup)) 'Prepared backup removed when original policy remained'

    # Backup from a different computer must not change current policy.
    $bad=Join-Path $testDirectory 'wrong-computer.json'
    @{Format='NetwerkRapport-WfpAuditRecovery-v1';ComputerName='Elsewhere';Subcategory='0cce9226-69ae-11d9-bed3-505054503030';OriginalFlags=4;EnabledFlags=3} |
        ConvertTo-Json | Set-Content -LiteralPath $bad
    Assert-Throws { Restore-NrWfpAuditPolicy -RecoveryPath $bad } 'Foreign recovery rejected'

    $observed=([datetime]'2026-09-14T12:00:00Z').ToUniversalTime()
    $table=@{
        '1234'=[pscustomobject]@{ProcessName='camera.exe';ProcessPath='C:\Apps\camera.exe';ProcessStart=$observed.AddMinutes(-2);Services=@('CameraService');ServiceDetails=@([pscustomobject]@{Name='CameraService';DisplayName='Camera Service';Description='Fixture camera service';State='Running';StartMode='Auto'})}
        '1235'=[pscustomobject]@{ProcessName='new-owner.exe';ProcessPath='C:\Apps\new-owner.exe';ProcessStart=$observed.AddSeconds(1);Services=@('Unrelated')}
        '1236'=[pscustomobject]@{ProcessName='wrong-path.exe';ProcessPath='C:\Apps\wrong-path.exe';ProcessStart=$observed.AddMinutes(-5);Services=@('Wrong')}
    }
    $map=@{'\Device\HarddiskVolume2'='C:'}
    function New-EventFixture([int]$Id,[string]$Direction,[string]$Process='1234',[string]$Protocol='17',[string]$Source='10.10.10.10',[string]$Destination='1.1.1.1') {
        $event=[pscustomobject]@{
            Id=$Id; RecordId=99L; TimeCreated=$observed
            XmlText="<Event><EventData><Data Name='ProcessID'>$Process</Data><Data Name='Application'>\Device\HarddiskVolume2\Apps\camera.exe</Data><Data Name='Direction'>$Direction</Data><Data Name='SourceAddress'>$Source</Data><Data Name='SourcePort'>56789</Data><Data Name='DestAddress'>$Destination</Data><Data Name='DestPort'>443</Data><Data Name='Protocol'>$Protocol</Data></EventData></Event>"
        }
        $event | Add-Member -MemberType ScriptMethod -Name ToXml -Value { return $this.XmlText }
        return $event
    }
    $event=New-EventFixture 5156 '%%14593'
    $row=Convert-NrWfpEvent -Event $event -ProcessTable $table -DeviceMap $map
    Assert-Equal 'UDP' $row.Protocol 'UDP protocol'
    Assert-Equal 'Outbound' $row.Direction 'Outbound direction'
    Assert-Equal '10.10.10.10' $row.LocalAddress 'Outbound local address'
    Assert-Equal '1.1.1.1' $row.RemoteAddress 'Outbound remote address'
    Assert-Equal 443 $row.RemotePort 'Remote UDP destination port'
    Assert-Equal 'C:\Apps\camera.exe' $row.ProcessPath 'Device path normalized'
    Assert-Equal 'CameraService' $row.Services[0] 'Service associated after start-time check'
    Assert-Equal $true $row.Allowed '5156 means allowed at audit layer'
    Assert-Equal 'MatchedLiveProcess' $row.AttributionStatus 'Live process attribution is structured'
    Assert-Equal 'Camera Service' $row.ServiceDetails[0].DisplayName 'Service display name is retained in capture row'
    Assert-Equal 'Fixture camera service' $row.ServiceDetails[0].Description 'Service description is retained in capture row'
    Assert-True ($row.ProcessEvidence -match 'WFP event path matches') 'Strong WFP path evidence is explicit'
    Assert-True ($row.ServiceEvidence -match 'does not identify which hosted service') 'Service membership does not claim connection ownership'

    $event=New-EventFixture 5157 '%%14592' '0x4D2' '6' '2001:4860:4860::8888' 'fe80::1234'
    $row=Convert-NrWfpEvent -Event $event -ProcessTable $table -DeviceMap $map
    Assert-Equal 'TCP' $row.Protocol 'TCP protocol'
    Assert-Equal 'Inbound' $row.Direction 'Inbound direction'
    Assert-Equal 'fe80::1234' $row.LocalAddress 'Inbound IPv6 local address uses destination'
    Assert-Equal '2001:4860:4860::8888' $row.RemoteAddress 'Inbound IPv6 remote address uses source'
    Assert-Equal 56789 $row.RemotePort 'Inbound remote port uses source port'
    Assert-Equal 1234L $row.ProcessId 'Hexadecimal PID parsed'
    Assert-Equal $false $row.Allowed '5157 is blocked attempt'

    foreach ($processNumber in @('1235','1236','9999')) {
        $event=New-EventFixture 5156 '%%14593' $processNumber
        $row=Convert-NrWfpEvent -Event $event -ProcessTable $table -DeviceMap $map
        Assert-Equal 'camera.exe' $row.ProcessName 'Retain event identity after exit, PID reuse or path mismatch'
        Assert-Equal '' $row.ProcessStartTimeUtc 'Do not attach unrelated process start time'
        Assert-Equal 0 $row.Services.Count 'Do not attach services from reused or mismatched PID'
        Assert-Equal 0 $row.ServiceDetails.Count 'Service descriptions are also excluded from unmatched processes'
        Assert-Equal 'WfpEventPathOnly' $row.AttributionStatus 'WFP event retains event-only attribution after process exit or mismatch'
    }
    $event=New-EventFixture 5156 '%%UNKNOWN'
    Assert-Throws { Convert-NrWfpEvent -Event $event -ProcessTable $table -DeviceMap $map } 'Unknown direction is not guessed'

    # Native well-known process IDs remain meaningful without a live process table.
    $identity=Resolve-NrProcessIdentity -ProcessId 4 -ObservedUtc $observed -ProcessTable @{} -AuditPath '-'
    Assert-Equal 'System' $identity.ProcessName 'System PID recognized without live process record'
    Assert-Equal 'SystemProcess' $identity.AttributionStatus 'System process fallback is structured'
    Assert-True ($identity.ProcessEvidence -match 'does not identify the driver') 'System fallback does not invent a kernel component'
    $identity=Resolve-NrProcessIdentity -ProcessId 0 -ObservedUtc $observed -ProcessTable @{}
    Assert-Equal 'System / unassigned' $identity.ProcessName 'PID zero does not become an invented application'
    Assert-Equal 'Unassigned' $identity.AttributionStatus 'PID zero is not a verified process'
    $identity=Resolve-NrProcessIdentity -ProcessId 1234 -ObservedUtc $observed -ProcessTable $table -AuditPath '-'
    Assert-Equal 'camera.exe' $identity.ProcessName 'Missing WFP application marker is not treated as a real path'

    $event=New-EventFixture 5156 '%%14593'
    $event.XmlText=$event.XmlText.Replace('\Device\HarddiskVolume2\Apps\camera.exe','-')
    $row=Convert-NrWfpEvent -Event $event -ProcessTable $table -DeviceMap $map
    Assert-Equal 'MatchedLiveProcess' $row.AttributionStatus 'Missing WFP path can still match PID and process start'
    Assert-True ($row.ProcessEvidence -match 'recorded this PID in the WFP event') 'Missing WFP path evidence retains the actual event source'
    Assert-True ($row.ProcessEvidence -notmatch 'socket') 'WFP PID-only attribution is not mislabeled as a socket snapshot'
    Assert-True ($row.Attribution -match 'event path unavailable') 'Missing event path remains explicit'

    # Service association comes from service ProcessId, not matching display names.
    function Get-CimInstance([string]$ClassName,[string]$Filter,[string[]]$Property) {
        if ($ClassName -eq 'Win32_Process' -and ($Property -contains 'CommandLine' -or $Property -contains '*')) { throw 'Command lines must not be requested' }
        if ($ClassName -eq 'Win32_Service') {
            return @(
                [pscustomobject]@{ProcessId=44;Name='OneService';DisplayName='First Service';Description='First service purpose';State='Running';StartMode='Auto'},
                [pscustomobject]@{ProcessId=44;Name='AnotherService'},
                [pscustomobject]@{ProcessId=45;Name='SeparateService'}
            )
        }
        if ($ClassName -eq 'Win32_Process') {
            return @(
                [pscustomobject]@{ProcessId=44;Name='host.exe';ExecutablePath='C:\Apps\host.exe';CreationDate=$observed.AddMinutes(-1)},
                [pscustomobject]@{ProcessId=45;Name='restricted.exe';ExecutablePath=$null;CreationDate=$null}
            )
        }
        throw 'Unexpected CIM class: '+$ClassName
    }
    $processFixture=Get-NrProcessTable
    Assert-Equal 2 $processFixture.Count 'All process rows retained'
    Assert-Equal 'OneService,AnotherService' ($processFixture['44'].Services -join ',') 'Multiple services linked to correct owning process'
    Assert-Equal 'SeparateService' $processFixture['45'].Services[0] 'Protected process retains independently observed service association'
    Assert-Equal '' $processFixture['45'].ProcessPath 'Unknown protected process path remains empty'
    Assert-True ($null -eq $processFixture['45'].ProcessStart) 'Unknown protected process start remains unknown'
    Assert-Equal 'First Service' $processFixture['44'].ServiceDetails[0].DisplayName 'Readable service name preserved'
    Assert-Equal 'First service purpose' $processFixture['44'].ServiceDetails[0].Description 'Windows service description preserved'
    Assert-Equal 'Running' $processFixture['44'].ServiceDetails[0].State 'Windows service state preserved'
    Assert-Equal 'Auto' $processFixture['44'].ServiceDetails[0].StartMode 'Windows service start mode preserved'
    Assert-Equal '' $processFixture['44'].ServiceDetails[1].Description 'Missing service description remains empty'
    Assert-Equal 'Win32_Process' $processFixture['44'].ProcessSource 'Primary process provider recorded'
    $identity=Resolve-NrProcessIdentity -ProcessId 45 -ObservedUtc $observed -ProcessTable $processFixture
    Assert-Equal 'Unavailable' $identity.AttributionStatus 'Missing process start time prevents live attribution'
    Assert-Equal 0 $identity.ServiceDetails.Count 'Current service metadata is not attached without process time verification'
    Assert-True ($identity.ProcessEvidence -match 'start time is unavailable') 'Protected process attribution failure is explained'

    # A WFP event can provide a path when the verified live process path is hidden.
    $hiddenTable=@{'56'=[pscustomobject]@{ProcessName='hidden.exe';ProcessPath='';ProcessStart=$observed.AddMinutes(-1);Services=@();ServiceDetails=@();ServiceQueryStatus='Unavailable'}}
    $identity=Resolve-NrProcessIdentity -ProcessId 56 -ObservedUtc $observed -ProcessTable $hiddenTable -AuditPath 'C:\Apps\hidden.exe'
    Assert-Equal 'MatchedLiveProcess' $identity.AttributionStatus 'PID and start can match while executable path is restricted'
    Assert-True ($identity.ProcessEvidence -match 'could not be read for an independent comparison') 'Unavailable executable path is not described as independently verified'
    Assert-True ($identity.ServiceEvidence -match 'query was unavailable') 'Unavailable service query differs from no services observed'

    # If CIM is unavailable, Get-Process is a fallback with the same PID/time guard.
    function Get-CimInstance([string]$ClassName,[string]$Filter,[string[]]$Property) { throw 'Simulated CIM failure' }
    function Get-Process {
        $restricted=[pscustomobject]@{Id=91;ProcessName='restricted'}
        $restricted | Add-Member ScriptProperty Path { throw 'Access denied to executable path' }
        $restricted | Add-Member ScriptProperty StartTime { throw 'Access denied to process start time' }
        return @(
            [pscustomobject]@{Id=90;ProcessName='fallback';Path='C:\Apps\fallback.exe';StartTime=$observed.AddMinutes(-2)},
            $restricted,
            [pscustomobject]@{Id=92;ProcessName='replacement';Path='C:\Apps\replacement.exe';StartTime=$observed.AddSeconds(1)}
        )
    }
    $fallbackTable=Get-NrProcessTable
    Assert-Equal 3 $fallbackTable.Count 'Get-Process fallback retains available and protected process rows'
    Assert-Equal 'Get-Process' $fallbackTable['90'].ProcessSource 'Fallback provider recorded'
    Assert-Equal 'fallback.exe' $fallbackTable['90'].ProcessName 'Fallback executable basename comes from readable path'
    Assert-Equal '' $fallbackTable['91'].ProcessPath 'Denied fallback path remains unknown'
    Assert-True ($null -eq $fallbackTable['91'].ProcessStart) 'Denied fallback start time remains unknown'
    $identity=Resolve-NrProcessIdentity -ProcessId 90 -ObservedUtc $observed -ProcessTable $fallbackTable
    Assert-Equal 'MatchedLiveProcess' $identity.AttributionStatus 'Fallback process instance verified using start time'
    Assert-True ($identity.ProcessEvidence -match 'source: Get-Process') 'Fallback evidence names provider'
    Assert-True ($identity.ServiceEvidence -match 'query was unavailable') 'Failed service CIM query is not reported as no hosted services'
    $identity=Resolve-NrProcessIdentity -ProcessId 92 -ObservedUtc $observed -ProcessTable $fallbackTable
    Assert-Equal 'Unavailable' $identity.AttributionStatus 'Fallback cannot assign a reused PID'
    Assert-True ($identity.ProcessEvidence -match 'started after this observation') 'PID reuse rejection explained'
    Assert-Equal '' $identity.ProcessName 'New fallback PID owner not attached to old connection'
    Remove-Item Function:Get-Process


    # Native UDP table never supplies the missing remote endpoint.
    $script:fixtureSocketCreated=$observed.AddMinutes(-1)
    function Get-NetTCPConnection { return [pscustomobject]@{OwningProcess=1234;LocalAddress='10.10.10.10';LocalPort=50111;RemoteAddress='1.1.1.1';RemotePort=443;State='Established';CreationTime=$script:fixtureSocketCreated} }
    function Get-NetUDPEndpoint { return [pscustomobject]@{OwningProcess=1234;LocalAddress='0.0.0.0';LocalPort=50112} }
    $rows=@(Get-NrConnectionSnapshot -ProcessTable $table)
    Assert-Equal 2 $rows.Count 'TCP and UDP local endpoint captured'
    Assert-Equal '' $rows[1].RemoteAddress 'UDP snapshot must not invent remote IP'
    Assert-Equal 0 $rows[1].RemotePort 'UDP snapshot must not invent remote port'
    Assert-True ($null -eq $rows[1].Allowed) 'UDP snapshot does not assert firewall verdict'
    Assert-Equal ($observed.AddMinutes(-1).ToString('o')) $rows[0].SocketCreatedUtc 'Available OS socket creation time retained separately'
    Assert-True ($rows[0].FirstSeenUtc -ne $rows[0].SocketCreatedUtc) 'Observation time is not invented from socket creation time'
    Assert-Equal '' $rows[1].SocketCreatedUtc 'Absent socket creation metadata remains unknown'
    Assert-Equal '' (Get-NrSocketCreationTime ([pscustomobject]@{CreationTime=[datetime]::MinValue})) 'Sentinel socket creation time omitted'
    Assert-Equal '' (Get-NrSocketCreationTime ([pscustomobject]@{CreationTime='not a date'})) 'Invalid socket creation time omitted'

    # A socket is read, its owner exits, and Windows reuses the PID before the
    # process query. Refreshing the process table after BOTH socket queries and
    # comparing start time with the pre-query timestamp prevents wrong attribution.
    $script:ordering=New-Object 'System.Collections.Generic.List[string]'
    $script:replacementStart=[datetime]::MinValue
    function Get-NetTCPConnection {
        $script:ordering.Add('TCP')
        $script:replacementStart=[datetime]::UtcNow.AddTicks(1)
        return [pscustomobject]@{OwningProcess=7000;LocalAddress='10.10.10.10';LocalPort=50111;RemoteAddress='1.1.1.1';RemotePort=443;State='Established'}
    }
    function Get-NetUDPEndpoint {
        $script:ordering.Add('UDP')
        return [pscustomobject]@{OwningProcess=7000;LocalAddress='0.0.0.0';LocalPort=50112}
    }
    function Get-NrProcessTable {
        $script:ordering.Add('Processes')
        return @{'7000'=[pscustomobject]@{ProcessName='replacement.exe';ProcessPath='C:\Apps\replacement.exe';ProcessStart=$script:replacementStart;Services=@('ReplacementService')}}
    }
    $rows=@(Get-NrConnectionSnapshot)
    Assert-Equal 'TCP,UDP,Processes' ($script:ordering -join ',') 'Process table refreshed after socket snapshots'
    Assert-Equal 2 $rows.Count 'Both sockets retained despite uncertain process identity'
    foreach ($row in $rows) {
        Assert-Equal '' $row.ProcessName 'Do not attribute previous socket to replacement PID owner'
        Assert-Equal '' $row.ProcessPath 'Do not attach replacement process path'
        Assert-Equal 0 $row.Services.Count 'Do not attach replacement process services'
    }

    # WFP must establish the upper event cursor before refreshing processes. An
    # event outside that bound must never be matched to an older process table.
    $script:ordering.Clear()
    $script:readerQuery=''
    $script:wfpFixture=New-EventFixture 5156 '%%14593' '1234'
    $script:wfpFixture.RecordId=39L
    $script:wfpFixture | Add-Member -MemberType ScriptMethod -Name Dispose -Value { }
    function Get-NrSecurityLogNewestId { $script:ordering.Add('Cursor'); return 42L }
    function Get-NrSecurityLogInformation { return [pscustomobject]@{OldestRecordNumber=1L} }
    function Get-NrProcessTable {
        $script:ordering.Add('Processes')
        return @{'1234'=[pscustomobject]@{ProcessName='camera.exe';ProcessPath='C:\Apps\camera.exe';ProcessStart=$observed.AddSeconds(1);Services=@('ReusedService')}}
    }
    function New-NrSecurityEventReader([string]$XPath) {
        $script:ordering.Add('Reader'); $script:readerQuery=$XPath
        $fakeReader=[pscustomobject]@{Index=0}
        $fakeReader | Add-Member -MemberType ScriptMethod -Name ReadEvent -Value {
            $this.Index++
            if ($this.Index -eq 1) { return $script:wfpFixture }
            return $null
        }
        $fakeReader | Add-Member -MemberType ScriptMethod -Name Dispose -Value { }
        return $fakeReader
    }
    $session=[pscustomobject]@{Stopped=$false;LastRecordId=30L;Warnings=(New-Object 'System.Collections.Generic.List[string]');DeviceMap=$map;EventsRead=0L;ParseFailures=0L;ReadsAtLimit=0L}
    $rows=@(Read-NrWfpCapture -Session $session)
    Assert-Equal 'Cursor,Processes,Reader' ($script:ordering -join ',') 'WFP cursor bounded before current process query'
    Assert-True ($script:readerQuery -match 'EventRecordID > 30 and EventRecordID <= 42') 'WFP query excludes events newer than its process observation window'
    Assert-Equal 1 $rows.Count 'WFP fixture is read'
    Assert-Equal 39L $session.LastRecordId 'WFP cursor advances to consumed event'
    Assert-Equal 'camera.exe' $rows[0].ProcessName 'Event application survives PID reuse'
    Assert-Equal '' $rows[0].ProcessStartTimeUtc 'Same-path reused PID gets no previous/new process start time'
    Assert-Equal 0 $rows[0].Services.Count 'Same-path reused PID gets no current service association'
    # Independent network-context sources may fail without hiding successful ones.
    function Get-NetAdapter([switch]$IncludeHidden) {
        return [pscustomobject]@{InterfaceIndex=9;Name='Ethernet';InterfaceDescription='Fixture NIC';Status='Up';LinkSpeed='1 Gbps'}
    }
    function Get-NetIPAddress {
        return [pscustomobject]@{InterfaceIndex=9;InterfaceAlias='Ethernet';AddressFamily='IPv4';IPAddress='10.10.10.10';PrefixLength=24;AddressState='Preferred';PrefixOrigin='Dhcp';SuffixOrigin='Dhcp'}
    }
    function Get-DnsClientServerAddress {
        return [pscustomobject]@{InterfaceIndex=9;InterfaceAlias='Ethernet';AddressFamily=2;ServerAddresses=@('10.10.10.1')}
    }
    function Get-NetRoute {
        return @(
            [pscustomobject]@{InterfaceIndex=9;InterfaceAlias='Ethernet';AddressFamily='IPv4';DestinationPrefix='0.0.0.0/0';NextHop='10.10.10.1';RouteMetric=10;Protocol='Dhcp';State='Alive'},
            [pscustomobject]@{InterfaceIndex=9;InterfaceAlias='Ethernet';AddressFamily='IPv4';DestinationPrefix='10.10.10.0/24';NextHop='0.0.0.0';RouteMetric=256;Protocol='Local';State='Alive'}
        )
    }
    function Get-NetFirewallProfile([string]$PolicyStore) {
        if ($PolicyStore -ne 'ActiveStore') { throw 'Effective profile policy must be queried' }
        return [pscustomobject]@{Name='Private';Enabled='True';DefaultInboundAction='Block';DefaultOutboundAction='Allow'}
    }
    $context=Get-NrNetworkContext
    Assert-Equal 0 $context.Warnings.Count 'Successful context collects without warnings'
    Assert-Equal 'D:\Windows' $context.SystemRoot 'Actual Windows directory is preserved instead of assuming C drive'
    Assert-Equal 9 $context.Adapters[0].InterfaceIndex 'Adapter maps by interface index'
    Assert-Equal '10.10.10.10' $context.Addresses[0].IPAddress 'Local address context preserved'
    Assert-Equal '10.10.10.1' $context.DnsServers[0].ServerAddresses[0] 'Configured DNS server retained'
    Assert-Equal 1 $context.DefaultRoutes.Count 'Non-default routes are not reported as gateways'
    Assert-Equal '10.10.10.1' $context.DefaultRoutes[0].NextHop 'Default gateway retained'
    Assert-Equal 'Allow' $context.FirewallProfiles[0].DefaultOutboundAction 'Windows firewall defaults are read only'
    function Get-NetAdapter([switch]$IncludeHidden) { throw 'Simulated network adapter access failure' }
    function Get-NetFirewallProfile([string]$PolicyStore) { throw 'Simulated firewall profile access failure' }
    $context=Get-NrNetworkContext
    Assert-Equal 2 $context.Warnings.Count 'Independent context failures are explicit'
    Assert-Equal 0 $context.Adapters.Count 'Failed adapter source is empty rather than fabricated'
    Assert-Equal 1 $context.Addresses.Count 'Address context survives unrelated source failure'
    Assert-Equal 1 $context.DefaultRoutes.Count 'Default route context survives unrelated source failure'
    Write-Output 'PASS: audit recovery, concurrent policy changes, mutex, IPv4/IPv6 direction, blocked/allowed, PID reuse, process evidence, service descriptions, protected-process fallback, socket creation metadata and read-only network context.'
} finally {
    [NrCapture.Native]::FailWrites=$false
    Exit-NrCaptureMutex
    $env:COMPUTERNAME=$oldComputer
    $env:SystemRoot=$oldSystemRoot
    Remove-Item -LiteralPath $testDirectory -Recurse -Force
}
