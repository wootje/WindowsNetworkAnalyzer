# Windows 11 / Windows PowerShell 5.1. Dot-source from NetworkAnalyzer.ps1.
# Captures metadata only. No firewall rules or packet payloads are changed/read.

if (-not (Get-Variable -Name NrCaptureMutex -Scope Script -ErrorAction SilentlyContinue)) {
    $script:NrCaptureMutex = $null
}

function Initialize-NrWindowsNative {
    if ('NrCapture.Native' -as [type]) { return }
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
namespace NrCapture {
    public static class Native {
        [StructLayout(LayoutKind.Sequential)]
        private struct AuditInfo { public Guid Subcategory; public UInt32 Flags; public Guid Category; }
        [StructLayout(LayoutKind.Sequential)]
        private struct Luid { public UInt32 Low; public Int32 High; }
        [StructLayout(LayoutKind.Sequential)]
        private struct TokenPrivileges { public UInt32 Count; public Luid Luid; public UInt32 Attributes; }
        [DllImport("advapi32.dll", SetLastError=true)]
        [return: MarshalAs(UnmanagedType.U1)]
        private static extern bool AuditQuerySystemPolicy([In] Guid[] guids, UInt32 count, out IntPtr policy);
        [DllImport("advapi32.dll", SetLastError=true)]
        [return: MarshalAs(UnmanagedType.U1)]
        private static extern bool AuditSetSystemPolicy([In] AuditInfo[] info, UInt32 count);
        [DllImport("advapi32.dll")] private static extern void AuditFree(IntPtr p);
        [DllImport("advapi32.dll", SetLastError=true)]
        private static extern bool OpenProcessToken(IntPtr process, UInt32 desired, out IntPtr token);
        [DllImport("advapi32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
        private static extern bool LookupPrivilegeValue(string system, string name, out Luid luid);
        [DllImport("advapi32.dll", SetLastError=true)]
        private static extern bool AdjustTokenPrivileges(IntPtr token, bool disableAll,
            ref TokenPrivileges state, UInt32 size, out TokenPrivileges previous, out UInt32 returned);
        [DllImport("kernel32.dll")] private static extern IntPtr GetCurrentProcess();
        [DllImport("kernel32.dll")] private static extern bool CloseHandle(IntPtr handle);
        [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
        private static extern UInt32 QueryDosDevice(string device, StringBuilder target, Int32 max);
        private sealed class Privilege : IDisposable {
            private IntPtr token = IntPtr.Zero;
            private TokenPrivileges previous;
            private bool changed;
            public Privilege() {
                if (!OpenProcessToken(GetCurrentProcess(), 0x28, out token)) throw new Win32Exception();
                try {
                    Luid luid;
                    if (!LookupPrivilegeValue(null, "SeSecurityPrivilege", out luid)) throw new Win32Exception();
                    TokenPrivileges desired = new TokenPrivileges { Count=1, Luid=luid, Attributes=2 };
                    UInt32 returned;
                    if (!AdjustTokenPrivileges(token, false, ref desired,
                            (UInt32)Marshal.SizeOf(typeof(TokenPrivileges)), out previous, out returned))
                        throw new Win32Exception();
                    int error = Marshal.GetLastWin32Error();
                    if (error != 0) throw new Win32Exception(error);
                    changed = true;
                } catch { CloseHandle(token); token=IntPtr.Zero; throw; }
            }
            public void Dispose() {
                if (token != IntPtr.Zero) {
                    if (changed) {
                        TokenPrivileges ignored; UInt32 returned;
                        AdjustTokenPrivileges(token, false, ref previous,
                            (UInt32)Marshal.SizeOf(typeof(TokenPrivileges)), out ignored, out returned);
                    }
                    CloseHandle(token); token=IntPtr.Zero;
                }
            }
        }
        public static UInt32 GetFlags(Guid guid) {
            using (new Privilege()) {
                IntPtr buffer;
                if (!AuditQuerySystemPolicy(new Guid[] {guid}, 1, out buffer)) throw new Win32Exception();
                try { return ((AuditInfo)Marshal.PtrToStructure(buffer, typeof(AuditInfo))).Flags; }
                finally { AuditFree(buffer); }
            }
        }
        public static void SetFlags(Guid guid, UInt32 flags) {
            // Zero is UNCHANGED to AuditSetSystemPolicy; NONE (4) means disabled.
            if (flags == 0) flags=4;
            using (new Privilege()) {
                if (!AuditSetSystemPolicy(new AuditInfo[] {new AuditInfo {Subcategory=guid, Flags=flags}}, 1))
                    throw new Win32Exception();
            }
        }
        public static string GetDevicePath(string drive) {
            StringBuilder sb = new StringBuilder(32768);
            return QueryDosDevice(drive, sb, sb.Capacity)==0 ? null : sb.ToString();
        }
    }
}
'@ -ErrorAction Stop
}

function Test-NrAdministrator {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-NrCaptureProperty {
    param($InputObject, [string]$Name, $Default = $null)
    if ($null -eq $InputObject) { return $Default }
    $property = $InputObject.PSObject.Properties[$Name]
    if ($null -eq $property) { return $Default }
    try { return $property.Value } catch { return $Default }
}

function Get-NrProcessTable {
    # Rebuilt each sampling round: a PID alone is not a stable process identity.
    # Service membership is current host-process context, not proof that one of
    # those services initiated a particular connection. No command lines are read.
    $result = @{}
    $servicesByProcess = @{}
    $serviceQueryStatus = 'Available'
    try {
        foreach ($service in @(Get-CimInstance Win32_Service -Filter 'ProcessId > 0' `
                -Property ProcessId,Name,DisplayName,Description,State,StartMode -ErrorAction Stop)) {
            $key = [string]$service.ProcessId
            if (-not $servicesByProcess.ContainsKey($key)) { $servicesByProcess[$key] = New-Object 'System.Collections.Generic.List[object]' }
            $servicesByProcess[$key].Add([pscustomobject]@{
                Name = [string](Get-NrCaptureProperty $service 'Name' '')
                DisplayName = [string](Get-NrCaptureProperty $service 'DisplayName' '')
                Description = [string](Get-NrCaptureProperty $service 'Description' '')
                State = [string](Get-NrCaptureProperty $service 'State' '')
                StartMode = [string](Get-NrCaptureProperty $service 'StartMode' '')
            })
        }
    } catch {
        $serviceQueryStatus = 'Unavailable'
        Write-Verbose ('Windows services could not be associated: ' + $_.Exception.Message)
    }
    $processRows = @()
    $processSource = 'Win32_Process'
    try {
        $processRows = @(Get-CimInstance Win32_Process -Property ProcessId,Name,ExecutablePath,CreationDate -ErrorAction Stop)
    } catch {
        Write-Verbose ('The CIM process list is unavailable; trying Get-Process: ' + $_.Exception.Message)
        $processSource = 'Get-Process'
        try { $processRows = @(Get-Process -ErrorAction Stop) }
        catch { Write-Warning ('Process list unavailable: ' + $_.Exception.Message) }
    }
    foreach ($processInfo in $processRows) {
        $start = $null
        $processNumber = 0L; $processName = ''; $processPath = ''
        if ($processSource -eq 'Win32_Process') {
            $processNumber = [long](Get-NrCaptureProperty $processInfo 'ProcessId' 0)
            $processName = [string](Get-NrCaptureProperty $processInfo 'Name' '')
            $processPath = [string](Get-NrCaptureProperty $processInfo 'ExecutablePath' '')
            $creation = Get-NrCaptureProperty $processInfo 'CreationDate'
        } else {
            $processNumber = [long](Get-NrCaptureProperty $processInfo 'Id' 0)
            $processName = [string](Get-NrCaptureProperty $processInfo 'ProcessName' '')
            $processPath = [string](Get-NrCaptureProperty $processInfo 'Path' '')
            if ($processPath) { $processName = ($processPath -split '[\\/]')[-1] }
            $creation = Get-NrCaptureProperty $processInfo 'StartTime'
        }
        if ($creation) { try { $start = ([datetime]$creation).ToUniversalTime() } catch { } }
        $key = [string]$processNumber
        $details = @()
        if ($servicesByProcess.ContainsKey($key)) { $details = @($servicesByProcess[$key].ToArray()) }
        $serviceNames = @($details | ForEach-Object { $_.Name })
        $result[$key] = [pscustomobject]@{
            ProcessId = $processNumber
            ProcessName = $processName
            ProcessPath = $processPath
            ProcessStart = $start
            ProcessSource = $processSource
            Services = $serviceNames
            ServiceDetails = $details
            ServiceQueryStatus = $serviceQueryStatus
        }
        if ($processSource -eq 'Get-Process' -and $processInfo -is [IDisposable]) {
            try { $processInfo.Dispose() } catch { }
        }
    }
    return $result
}

function Get-NrDeviceMap {
    Initialize-NrWindowsNative
    $map = @{}
    foreach ($drive in [System.IO.DriveInfo]::GetDrives()) {
        $name = $drive.Name.TrimEnd('\')
        if ($name -match '^[A-Za-z]:$') {
            $device = [NrCapture.Native]::GetDevicePath($name)
            if ($device) { $map[$device] = $name }
        }
    }
    return $map
}

function Convert-NrDevicePath {
    param([AllowEmptyString()][string]$Path, [hashtable]$DeviceMap)
    if (-not $Path) { return '' }
    foreach ($device in @($DeviceMap.Keys | Sort-Object Length -Descending)) {
        if ($Path.StartsWith($device + '\', [StringComparison]::OrdinalIgnoreCase)) {
            return ($DeviceMap[$device] + $Path.Substring($device.Length))
        }
    }
    return $Path
}

function Resolve-NrProcessIdentity {
    param([long]$ProcessId, [datetime]$ObservedUtc, [hashtable]$ProcessTable,
          [string]$AuditPath = '', [hashtable]$DeviceMap = @{}, [switch]$WfpEvent)
    if ($AuditPath -eq '-') { $AuditPath = '' }
    $name = ''; $path = ''; $start = ''; $services = @(); $serviceDetails = @()
    $attribution = 'Process no longer available or access restricted'
    $status = 'Unavailable'
    $evidence = 'Windows supplied a PID, but no live process identity could be safely matched to this observation. The process may have exited, or access may be restricted.'
    $serviceEvidence = 'Service membership could not be established for this observation.'
    if ($AuditPath) {
        $path = Convert-NrDevicePath -Path $AuditPath -DeviceMap $DeviceMap
        $name = ($path -split '[\\/]')[-1]
        $attribution = 'Application path recorded in the WFP event'
        $status = 'WfpEventPathOnly'
        $evidence = 'The executable path and PID were recorded by Windows in this WFP event. No live process instance was matched; current services and process start time are unavailable.'
    }
    $key = [string]$ProcessId
    if ($ProcessTable.ContainsKey($key)) {
        $current = $ProcessTable[$key]
        $timeMatches = ($null -ne $current.ProcessStart -and $current.ProcessStart -le $ObservedUtc)
        $pathMatches = (-not $AuditPath -or -not $current.ProcessPath -or $path.Equals($current.ProcessPath, [StringComparison]::OrdinalIgnoreCase))
        if ($timeMatches -and $pathMatches) {
            if (-not $name) { $name = $current.ProcessName }
            if (-not $path) { $path = $current.ProcessPath }
            $start = $current.ProcessStart.ToString('o')
            $services = @($current.Services)
            $serviceDetails = @(Get-NrCaptureProperty $current 'ServiceDetails' @())
            $status = 'MatchedLiveProcess'
            $provider = [string](Get-NrCaptureProperty $current 'ProcessSource' 'Windows process table')
            if ($AuditPath -and $current.ProcessPath) {
                $attribution = 'WFP path, PID and process start time checked'
                $evidence = 'The WFP event path matches the live executable path; its PID and process start time identify the process instance at the event time.'
            } elseif ($AuditPath) {
                $attribution = 'WFP path retained; PID and process start time checked'
                $evidence = 'WFP recorded the executable path and PID. The live process started before this event, but its executable path could not be read for an independent comparison.'
            } elseif ($WfpEvent) {
                $attribution = 'WFP PID and process start time checked; event path unavailable'
                $evidence = 'Windows recorded this PID in the WFP event; its live process started before the event. The event did not provide an executable path, so any reported path comes from the live process.'
            } else {
                $attribution = 'Windows socket, PID and process start time checked'
                $evidence = 'The Windows socket owner PID matches a live process that started before the socket snapshot. Process metadata was read after the socket table to avoid attaching a later reused PID.'
            }
            $evidence += ' Process metadata source: ' + $provider + '.'
            $serviceQueryStatus = [string](Get-NrCaptureProperty $current 'ServiceQueryStatus' 'Available')
            if ($serviceQueryStatus -eq 'Unavailable') {
                $serviceEvidence = 'The Windows service query was unavailable. Empty service details do not establish that this process hosts no services.'
            } elseif ($services.Count -gt 0) {
                $serviceEvidence = 'These Windows services were observed in this host process during collection. This is process-level context: the connection data does not identify which hosted service initiated this particular connection, and service membership may change over time.'
            } else {
                $serviceEvidence = 'No Windows service was associated with this process in the service snapshot. This does not determine whether the process belongs to a Windows component or a normal application.'
            }
        } elseif ($null -eq $current.ProcessStart) {
            $evidence += ' The current PID exists, but its start time is unavailable, so its metadata was not attached.'
        } elseif (-not $timeMatches) {
            $evidence += ' The current PID owner started after this observation; its metadata was not attached because the PID may have been reused.'
        } elseif (-not $pathMatches) {
            $evidence += ' The current executable path differs from the WFP event path; its metadata was not attached.'
        }
    }
    if ($ProcessId -eq 4 -and -not $name) {
        $name = 'System'; $attribution = 'Windows System (PID 4)'; $status = 'SystemProcess'
        $evidence = 'Windows reports the reserved System process PID 4. This identifies kernel/system activity, but does not identify the driver or Windows component that initiated the connection.'
    } elseif ($ProcessId -eq 0 -and -not $name) {
        $name = 'System / unassigned'; $attribution = 'Windows reports PID 0; no user process associated'; $status = 'Unassigned'
        $evidence = 'Windows reports PID 0 for this endpoint or event. A particular user application cannot be assigned from this record.'
    }
    return [pscustomobject]@{
        ProcessName=$name; ProcessPath=$path; ProcessStartTimeUtc=$start; Services=@($services)
        ServiceDetails=@($serviceDetails); Attribution=$attribution; AttributionStatus=$status
        ProcessEvidence=$evidence; ServiceEvidence=$serviceEvidence
    }
}

function New-NrCaptureRow {
    param([string]$Protocol, [string]$LocalAddress, [int]$LocalPort,
        [string]$RemoteAddress, [int]$RemotePort, [string]$State, [string]$Direction,
        [long]$ProcessId, $Identity, [string]$Source, [datetime]$ObservedUtc,
        $Allowed = $null, [long]$EventRecordId = 0, [string]$SocketCreatedUtc = '')
    [pscustomobject]@{
        Protocol=$Protocol; LocalAddress=$LocalAddress; LocalPort=$LocalPort
        RemoteAddress=$RemoteAddress; RemotePort=$RemotePort; State=$State; Direction=$Direction
        ProcessId=$ProcessId; ProcessName=$Identity.ProcessName; ProcessPath=$Identity.ProcessPath
        ProcessStartTimeUtc=$Identity.ProcessStartTimeUtc; Services=@($Identity.Services)
        ServiceDetails=@(Get-NrCaptureProperty $Identity 'ServiceDetails' @())
        AttributionStatus=[string](Get-NrCaptureProperty $Identity 'AttributionStatus' 'Unavailable')
        ProcessEvidence=[string](Get-NrCaptureProperty $Identity 'ProcessEvidence' '')
        ServiceEvidence=[string](Get-NrCaptureProperty $Identity 'ServiceEvidence' '')
        Source=$Source; FirstSeenUtc=$ObservedUtc.ToString('o'); LastSeenUtc=$ObservedUtc.ToString('o')
        Observations=1; Attribution=$Identity.Attribution; Allowed=$Allowed; EventRecordId=$EventRecordId
        SocketCreatedUtc=$SocketCreatedUtc
    }
}

function Get-NrSocketCreationTime {
    param([Parameter(Mandatory=$true)]$Socket)
    # CreationTime is OS socket metadata, not the time this collector first saw it.
    # Some providers/builds do not expose this property; preserve that uncertainty.
    $property = $Socket.PSObject.Properties['CreationTime']
    if ($null -eq $property -or $null -eq $property.Value) { return '' }
    try {
        $created = ([datetime]$property.Value).ToUniversalTime()
        if ($created.Year -gt 1970 -and $created -le [datetime]::UtcNow.AddMinutes(1)) { return $created.ToString('o') }
    } catch { }
    return ''
}

function Get-NrConnectionSnapshot {
    [CmdletBinding()]
    param([hashtable]$ProcessTable = $null)
    # Capture sockets BEFORE refreshing processes. A later replacement process must
    # not inherit an earlier socket merely because Windows reused the numeric PID.
    # The optional ProcessTable is for controlled callers/fixtures; freshness is then
    # the caller's responsibility. The normal collector always refreshes it here.
    $observed = [datetime]::UtcNow
    $tcpSockets = @(); $udpSockets = @()
    try {
        $tcpSockets = @(Get-NetTCPConnection -ErrorAction Stop)
    } catch { Write-Warning ('TCP snapshot failed: ' + $_.Exception.Message) }
    try {
        $udpSockets = @(Get-NetUDPEndpoint -ErrorAction Stop)
    } catch { Write-Warning ('UDP endpoints could not be read: ' + $_.Exception.Message) }
    if ($null -eq $ProcessTable) { $ProcessTable = Get-NrProcessTable }
    foreach ($socket in $tcpSockets) {
        $identity = Resolve-NrProcessIdentity -ProcessId $socket.OwningProcess -ObservedUtc $observed -ProcessTable $ProcessTable
        New-NrCaptureRow -Protocol TCP -LocalAddress $socket.LocalAddress -LocalPort $socket.LocalPort `
            -RemoteAddress $socket.RemoteAddress -RemotePort $socket.RemotePort -State ([string]$socket.State) `
            -Direction 'Unknown (snapshot)' -ProcessId $socket.OwningProcess -Identity $identity `
            -Source TcpSnapshot -ObservedUtc $observed -SocketCreatedUtc (Get-NrSocketCreationTime -Socket $socket)
    }
    foreach ($socket in $udpSockets) {
        $identity = Resolve-NrProcessIdentity -ProcessId $socket.OwningProcess -ObservedUtc $observed -ProcessTable $ProcessTable
        New-NrCaptureRow -Protocol UDP -LocalAddress $socket.LocalAddress -LocalPort $socket.LocalPort `
            -RemoteAddress '' -RemotePort 0 -State 'Local UDP endpoint; remote destination unavailable' `
            -Direction 'Unknown (local endpoint)' -ProcessId $socket.OwningProcess -Identity $identity `
            -Source UdpEndpoint -ObservedUtc $observed -SocketCreatedUtc (Get-NrSocketCreationTime -Socket $socket)
    }
}

function Get-NrSecurityLogNewestId {
    $event = Get-WinEvent -LogName Security -MaxEvents 1 -ErrorAction Stop
    try { return [long]$event.RecordId } finally { if ($event) { $event.Dispose() } }
}

function Get-NrSecurityLogInformation {
    return [System.Diagnostics.Eventing.Reader.EventLogSession]::GlobalSession.GetLogInformation('Security', [System.Diagnostics.Eventing.Reader.PathType]::LogName)
}

function New-NrSecurityEventReader {
    param([Parameter(Mandatory=$true)][string]$XPath)
    $query = New-Object System.Diagnostics.Eventing.Reader.EventLogQuery('Security', [System.Diagnostics.Eventing.Reader.PathType]::LogName, $XPath)
    $query.ReverseDirection = $false
    return New-Object System.Diagnostics.Eventing.Reader.EventLogReader($query)
}

function Enter-NrCaptureMutex {
    if ($null -ne $script:NrCaptureMutex) { return $false }
    $mutex = New-Object System.Threading.Mutex($false, 'Global\NetwerkRapport-WfpAudit-v1')
    $acquired = $false
    try { $acquired = $mutex.WaitOne(0) }
    catch [System.Threading.AbandonedMutexException] { $acquired = $true }
    if (-not $acquired) { $mutex.Dispose(); throw 'Another Network Analyzer WFP capture or recovery is already running on this computer.' }
    $script:NrCaptureMutex = $mutex
    return $true
}

function Exit-NrCaptureMutex {
    if ($null -ne $script:NrCaptureMutex) {
        try { $script:NrCaptureMutex.ReleaseMutex() }
        finally { $script:NrCaptureMutex.Dispose(); $script:NrCaptureMutex = $null }
    }
}

function Start-NrWfpCapture {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][string]$RecoveryPath)
    $acquired = Enter-NrCaptureMutex
    if (-not $acquired) { throw 'A WFP capture is already running in this PowerShell process.' }
    try { Start-NrWfpCaptureCore -RecoveryPath $RecoveryPath }
    catch { Exit-NrCaptureMutex; throw }
}

function Start-NrWfpCaptureCore {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][string]$RecoveryPath)
    if (-not (Test-NrAdministrator)) { throw 'Run PowerShell as administrator to enable WFP connection auditing.' }
    if (Test-Path -LiteralPath $RecoveryPath) {
        throw "An audit recovery file already exists: $RecoveryPath. Complete recovery before starting a new capture."
    }
    Initialize-NrWindowsNative
    $deviceMap = Get-NrDeviceMap
    $category = [guid]'0CCE9226-69AE-11D9-BED3-505054503030'
    $original = [NrCapture.Native]::GetFlags($category)
    $cursor = Get-NrSecurityLogNewestId
    $enabled = [uint32]3
    $restore = [ordered]@{
        Format='NetwerkRapport-WfpAuditRecovery-v1'; ComputerName=$env:COMPUTERNAME
        Subcategory=$category.ToString(); OriginalFlags=[uint32]$original; EnabledFlags=$enabled
        CreatedUtc=[datetime]::UtcNow.ToString('o'); Status='Prepared'
    }
    $parent = Split-Path -Parent $RecoveryPath
    if ($parent -and -not (Test-Path -LiteralPath $parent)) { New-Item -ItemType Directory -Path $parent -Force | Out-Null }
    # Write recovery BEFORE changing the policy. This intentionally survives hard termination.
    $restore | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $RecoveryPath -Encoding UTF8 -ErrorAction Stop
    try {
        $acl = Get-Acl -LiteralPath $RecoveryPath -ErrorAction Stop
        $acl.SetAccessRuleProtection($true, $false)
        foreach ($sidText in @('S-1-5-32-544','S-1-5-18')) {
            $sid = New-Object Security.Principal.SecurityIdentifier($sidText)
            $rule = New-Object Security.AccessControl.FileSystemAccessRule($sid, 'FullControl', 'Allow')
            $acl.AddAccessRule($rule)
        }
        Set-Acl -LiteralPath $RecoveryPath -AclObject $acl -ErrorAction Stop
    } catch { Write-Verbose ('The recovery file access permissions could not be restricted: ' + $_.Exception.Message) }
    try {
        [NrCapture.Native]::SetFlags($category, $enabled)
        $actual = [NrCapture.Native]::GetFlags($category)
        if (($actual -band 3) -ne 3) { throw 'Windows did not enable auditing of permitted and blocked connection attempts.' }
        $restore.Status='Enabled'
        $restore | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $RecoveryPath -Encoding UTF8 -ErrorAction Stop
    } catch {
        $reason = $_.Exception.Message
        try { Restore-NrWfpAuditPolicy -RecoveryPath $RecoveryPath | Out-Null }
        catch { Write-Warning ('Automatic recovery after a start failure did not succeed: ' + $_.Exception.Message) }
        throw $reason
    }
    return [pscustomobject]@{
        RecoveryPath=[IO.Path]::GetFullPath($RecoveryPath); Subcategory=$category; OriginalFlags=$original
        EnabledFlags=$enabled; StartUtc=[datetime]::UtcNow; LastRecordId=$cursor
        EventsRead=0L; ParseFailures=0L; ReadsAtLimit=0L; Stopped=$false
        Warnings=(New-Object 'System.Collections.Generic.List[string]'); DeviceMap=$deviceMap
    }
}

function Restore-NrWfpAuditPolicy {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][string]$RecoveryPath)
    $acquired = Enter-NrCaptureMutex
    try { Restore-NrWfpAuditPolicyCore -RecoveryPath $RecoveryPath }
    finally { if ($acquired) { Exit-NrCaptureMutex } }
}

function Restore-NrWfpAuditPolicyCore {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)][string]$RecoveryPath)
    Initialize-NrWindowsNative
    if (-not (Test-Path -LiteralPath $RecoveryPath)) { throw "Recovery file not found: $RecoveryPath" }
    $saved = Get-Content -LiteralPath $RecoveryPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    if ($saved.Format -ne 'NetwerkRapport-WfpAuditRecovery-v1' -or
        $saved.Subcategory -ne '0cce9226-69ae-11d9-bed3-505054503030' -or
        $saved.ComputerName -ne $env:COMPUTERNAME -or [uint32]$saved.OriginalFlags -gt 7 -or
        [uint32]$saved.EnabledFlags -ne 3) { throw 'Invalid audit recovery file or a file from a different computer.' }
    $category = [guid]$saved.Subcategory
    $current = [NrCapture.Native]::GetFlags($category)
    $original = [uint32]$saved.OriginalFlags
    if (($current -band 3) -eq ($original -band 3)) {
        Remove-Item -LiteralPath $RecoveryPath -Force -ErrorAction Stop
        return 'Audit policy was already at its original setting.'
    }
    if ($current -ne [uint32]$saved.EnabledFlags) {
        throw "Audit policy was changed by Windows policy or an administrator (current value: $current). That change was not overwritten; recovery file retained: $RecoveryPath"
    }
    [NrCapture.Native]::SetFlags($category, $original)
    $after = [NrCapture.Native]::GetFlags($category)
    if (($after -band 3) -ne ($original -band 3)) { throw "Audit policy was not restored; recovery file retained: $RecoveryPath" }
    Remove-Item -LiteralPath $RecoveryPath -Force -ErrorAction Stop
    return 'Original WFP audit policy restored.'
}

function Stop-NrWfpCapture {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)]$Session)
    if ($Session.Stopped) { return }
    try {
        Restore-NrWfpAuditPolicy -RecoveryPath $Session.RecoveryPath | Out-Null
        $Session.Stopped = $true
    } finally { Exit-NrCaptureMutex }
}

function Convert-NrWfpEvent {
    param([Parameter(Mandatory=$true)]$Event, [hashtable]$ProcessTable, [hashtable]$DeviceMap = @{})
    $data = @{}
    [xml]$xml = $Event.ToXml()
    foreach ($item in $xml.Event.EventData.Data) { $data[[string]$item.Name] = [string]$item.'#text' }
    $processNumber = 0L
    if ($data['ProcessID'] -match '^0x') { $processNumber = [Convert]::ToInt64($data['ProcessID'].Substring(2), 16) }
    elseif ($data['ProcessID']) { $processNumber = [long]$data['ProcessID'] }
    $observed = $Event.TimeCreated.ToUniversalTime()
    $identity = Resolve-NrProcessIdentity -ProcessId $processNumber -ObservedUtc $observed `
        -ProcessTable $ProcessTable -AuditPath $data['Application'] -DeviceMap $DeviceMap -WfpEvent
    $protocol = switch ([string]$data['Protocol']) {
        '6' { 'TCP' }; '17' { 'UDP' }; '1' { 'ICMP' }; '58' { 'ICMPv6' }; default { 'IP-' + $data['Protocol'] }
    }
    $direction = 'Unknown'
    $local = ''; $remote = ''; $localPort = 0; $remotePort = 0
    switch ($data['Direction']) {
        '%%14592' {
            $direction='Inbound'; $local=$data['DestAddress']; $localPort=[int]$data['DestPort']
            $remote=$data['SourceAddress']; $remotePort=[int]$data['SourcePort']
        }
        '%%14593' {
            $direction='Outbound'; $local=$data['SourceAddress']; $localPort=[int]$data['SourcePort']
            $remote=$data['DestAddress']; $remotePort=[int]$data['DestPort']
        }
        default { throw "Unknown WFP direction: $($data['Direction']); source and destination were not guessed." }
    }
    $allowed = ([int]$Event.Id -eq 5156)
    $state = if ($allowed) { 'WFP: permitted at the audited layer' } else { 'WFP: blocked attempt' }
    New-NrCaptureRow -Protocol $protocol -LocalAddress $local -LocalPort $localPort `
        -RemoteAddress $remote -RemotePort $remotePort -State $state -Direction $direction `
        -ProcessId $processNumber -Identity $identity -Source ('WFP' + $Event.Id) `
        -ObservedUtc $observed -Allowed $allowed -EventRecordId $Event.RecordId
}

function Read-NrWfpCapture {
    [CmdletBinding()]
    param([Parameter(Mandatory=$true)]$Session, [hashtable]$ProcessTable = $null,
          [ValidateRange(1,100000)][int]$MaxEvents = 10000)
    if ($Session.Stopped) { return }
    try {
        # Bound the event window FIRST, then inspect current processes. Reading
        # newer events against an older process table could misattribute a reused PID.
        $newest = Get-NrSecurityLogNewestId
        if ($newest -lt $Session.LastRecordId) {
            $Session.Warnings.Add('The Windows Security log was cleared during capture; WFP coverage may be incomplete.')
            $Session.LastRecordId=0L
        }
        $logInfo = Get-NrSecurityLogInformation
        if ($Session.LastRecordId -gt 0 -and $logInfo.OldestRecordNumber -gt ($Session.LastRecordId + 1)) {
            $Session.Warnings.Add('Older Windows Security events were overwritten before they could be read; WFP coverage may be incomplete.')
        }
    } catch { throw ('Windows Security log could not be read: ' + $_.Exception.Message) }
    if ($null -eq $ProcessTable) { $ProcessTable = Get-NrProcessTable }
    $xpath = '*[System[(EventID=5156 or EventID=5157) and EventRecordID > ' + ([long]$Session.LastRecordId) + ' and EventRecordID <= ' + ([long]$newest) + ']]'
    $reader = New-NrSecurityEventReader -XPath $xpath
    $readCount=0
    try {
        while ($readCount -lt $MaxEvents) {
            $event = $reader.ReadEvent()
            if ($null -eq $event) { break }
            try {
                $Session.LastRecordId=[long]$event.RecordId
                $Session.EventsRead++; $readCount++
                try { Convert-NrWfpEvent -Event $event -ProcessTable $ProcessTable -DeviceMap $Session.DeviceMap }
                catch {
                    $Session.ParseFailures++
                    if ($Session.ParseFailures -le 5) { $Session.Warnings.Add('WFP event could not be processed: ' + $_.Exception.Message) }
                }
            } finally { $event.Dispose() }
        }
        if ($readCount -ge $MaxEvents) {
            $Session.ReadsAtLimit++
            if ($Session.ReadsAtLimit -eq 1) { $Session.Warnings.Add('WFP event limit for this sampling round reached; remaining events will be read in the next round. Check final capture coverage.') }
        }
    } finally { $reader.Dispose() }
}


function Get-NrNetworkContext {
    [CmdletBinding()]
    param()
    # Read-only environment context. Do not collect command lines, credentials,
    # Wi-Fi profiles/keys, packet contents or unrelated installed-product inventory.
    # The Windows firewall profile is not a verdict from third-party WFP providers.
    $warnings = New-Object 'System.Collections.Generic.List[string]'
    $adapters = @(); $addresses = @(); $dnsServers = @(); $routes = @(); $profiles = @()
    $collected = [datetime]::UtcNow.ToString('o')
    try {
        $adapters = @(Get-NetAdapter -IncludeHidden -ErrorAction Stop | ForEach-Object {
            [pscustomobject]@{
                InterfaceIndex=[int]$_.InterfaceIndex; InterfaceAlias=[string]$_.Name
                Description=[string]$_.InterfaceDescription; Status=[string]$_.Status
                LinkSpeed=[string]$_.LinkSpeed
            }
        })
    } catch { $warnings.Add('Network adapter context unavailable: ' + $_.Exception.Message) }
    try {
        $addresses = @(Get-NetIPAddress -ErrorAction Stop | ForEach-Object {
            [pscustomobject]@{
                InterfaceIndex=[int]$_.InterfaceIndex; InterfaceAlias=[string]$_.InterfaceAlias
                AddressFamily=[string]$_.AddressFamily; IPAddress=[string]$_.IPAddress
                PrefixLength=[int]$_.PrefixLength; AddressState=[string]$_.AddressState
                PrefixOrigin=[string]$_.PrefixOrigin; SuffixOrigin=[string]$_.SuffixOrigin
            }
        })
    } catch { $warnings.Add('Local IP address context unavailable: ' + $_.Exception.Message) }
    try {
        $dnsServers = @(Get-DnsClientServerAddress -ErrorAction Stop | ForEach-Object {
            [pscustomobject]@{
                InterfaceIndex=[int]$_.InterfaceIndex; InterfaceAlias=[string]$_.InterfaceAlias
                AddressFamily=[string]$_.AddressFamily; ServerAddresses=@($_.ServerAddresses)
            }
        })
    } catch { $warnings.Add('Configured DNS server context unavailable: ' + $_.Exception.Message) }
    try {
        $routes = @(Get-NetRoute -ErrorAction Stop | Where-Object { $_.DestinationPrefix -eq '0.0.0.0/0' -or $_.DestinationPrefix -eq '::/0' } | ForEach-Object {
            [pscustomobject]@{
                InterfaceIndex=[int]$_.InterfaceIndex; InterfaceAlias=[string]$_.InterfaceAlias
                AddressFamily=[string]$_.AddressFamily; DestinationPrefix=[string]$_.DestinationPrefix
                NextHop=[string]$_.NextHop; RouteMetric=[int]$_.RouteMetric
                Protocol=[string]$_.Protocol; State=[string]$_.State
            }
        })
    } catch { $warnings.Add('Default route context unavailable: ' + $_.Exception.Message) }
    try {
        $profiles = @(Get-NetFirewallProfile -PolicyStore ActiveStore -ErrorAction Stop | ForEach-Object {
            [pscustomobject]@{
                Name=[string]$_.Name; Enabled=[string]$_.Enabled
                DefaultInboundAction=[string]$_.DefaultInboundAction
                DefaultOutboundAction=[string]$_.DefaultOutboundAction
            }
        })
    } catch { $warnings.Add('Windows firewall profile context unavailable: ' + $_.Exception.Message) }
    return [pscustomobject]@{
        CollectedAtUtc=$collected; SystemRoot=[string]$env:SystemRoot; Adapters=@($adapters); Addresses=@($addresses)
        DnsServers=@($dnsServers); DefaultRoutes=@($routes); FirewallProfiles=@($profiles)
        Warnings=@($warnings.ToArray())
    }
}
