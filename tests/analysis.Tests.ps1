# Self-contained deterministic analysis checks. No network calls and no Pester dependency.
$ErrorActionPreference='Stop'
. (Join-Path (Split-Path $PSScriptRoot -Parent) 'Analysis.ps1')
$script:AnalysisChecks=0
function Assert-AnalysisEqual($Actual,$Expected,[string]$Label) {
    if ($Actual -cne $Expected) { throw ($Label+': expected ['+$Expected+'], got ['+$Actual+']') }
    $script:AnalysisChecks++
}
function New-AnalysisTestRow {
    param([hashtable]$Change=@{})
    $value=[ordered]@{id='c1';protocol='TCP';localAddress='10.0.0.2';localPort=50000;remoteAddress='8.8.8.8';remotePort=443;processId=100;processName='browser.exe';processPath='C:\Program Files\Browser\browser.exe';application='Browser';services=@();dnsNames=@('example.test');ptrNames=@();ipScope='Public';state='Established';states=@('Established');source='TcpSnapshot';firstSeen='2026-09-15T10:00:00Z';lastSeen='2026-09-15T10:00:15Z';direction='Unknown (snapshot)';allowed='Unknown';signatureStatus='Valid';signer='Example';observations=40;company='Example';sha256='abcd'}
    foreach($key in $Change.Keys){$value[$key]=$Change[$key]}
    return [pscustomobject]$value
}
$empty=Get-NetworkAnalysis -Connections @()
Assert-AnalysisEqual $empty.summary.records 0 'empty dataset'
Assert-AnalysisEqual @($empty.applications).Count 0 'empty applications remain array'
Assert-AnalysisEqual @($empty.findings).Count 0 'empty findings'
Assert-AnalysisEqual @($empty.timeline).Count 0 'empty timeline'

$rows=@(
    (New-AnalysisTestRow),
    (New-AnalysisTestRow @{id='c2';source='WFP5156';direction='Outbound';allowed=$true;processPath='c:/program files/browser/BROWSER.EXE';firstSeen='2026-09-15T10:00:02Z'}),
    (New-AnalysisTestRow @{id='c3';source='WFP5157';direction='Outbound';allowed=$false;protocol='UDP';remoteAddress='1.1.1.1';remotePort=443;dnsNames=@();firstSeen='2026-09-15T10:00:03Z'}),
    (New-AnalysisTestRow @{id='c4';source='UdpEndpoint';localAddress='::';localPort=60000;remoteAddress='';remotePort=0;ipScope='Unknown';protocol='UDP';state='Local UDP endpoint';states=@('Local UDP endpoint');dnsNames=@();firstSeen='2026-09-15T10:00:04Z'}),
    (New-AnalysisTestRow @{id='c5';source='TcpSnapshot';localAddress='0.0.0.0';localPort=3389;remoteAddress='0.0.0.0';remotePort=0;ipScope='Unspecified';state='Listen';states=@('Listen');dnsNames=@();firstSeen='2026-09-15T10:00:05Z'})
)
$result=Get-NetworkAnalysis -Connections $rows -Meta @{truncated=$true}
Assert-AnalysisEqual $result.summary.records 5 'counts records rather than observations'
Assert-AnalysisEqual $result.summary.applications 1 'case and path separator normalization'
Assert-AnalysisEqual $result.summary.endpointCombinations 2 'cross-source endpoint deduplication excludes wildcard'
Assert-AnalysisEqual $result.summary.publicRemoteAddresses 2 'distinct public addresses'
Assert-AnalysisEqual $result.summary.recordsWithoutRemote 2 'missing and wildcard endpoints counted'
Assert-AnalysisEqual $result.summary.listenerRecords 2 'IPv6 UDP binding and IPv4 TCP listener'
Assert-AnalysisEqual $result.summary.blockedAuditRecords 1 'only block event source'
Assert-AnalysisEqual $result.coverage.truncated $true 'truncation exposed'
Assert-AnalysisEqual @($result.findings | Where-Object code -eq 'wildcard-binding').Count 1 'wildcard finding grouped per app'
Assert-AnalysisEqual @($result.findings | Where-Object code -eq 'quic-candidate').Count 1 'UDP443 candidate'
Assert-AnalysisEqual ($result.timeline | Measure-Object -Property firstObservedRecords -Sum).Sum 5 'timeline source records not packets'
Assert-AnalysisEqual @($result.ports | Where-Object { $_.port -eq 3389 -and $_.endpoint -eq 'local-listener' }).Count 1 'listener port distinguished'
Assert-AnalysisEqual @($result.findings | Where-Object code -like 'service-port*').Count 0 'listener does not imply public exposure'
Assert-AnalysisEqual @($result.applications[0].connectionIds).Count 5 'row references preserved'
Assert-AnalysisEqual $result.destinations[0].endpointCombinations 1 'destination duplicate source dedup'

$directionRows=@(
    (New-AnalysisTestRow @{id='in-clientport';source='WFP5156';direction='Inbound';localPort=50000;remotePort=3389}),
    (New-AnalysisTestRow @{id='in-serviceport';source='WFP5156';direction='Inbound';localPort=3389;remotePort=51000}),
    (New-AnalysisTestRow @{id='out-serviceport';source='WFP5156';direction='Outbound';localPort=52000;remotePort=22}),
    (New-AnalysisTestRow @{id='snapshot';source='TcpSnapshot';direction='Unknown (snapshot)';remotePort=445})
)
$result=Get-NetworkAnalysis $directionRows
$serviceFindings=@($result.findings | Where-Object code -like 'service-port*')
Assert-AnalysisEqual $serviceFindings.Count 2 'direction selects correct destination port'
Assert-AnalysisEqual @($serviceFindings.connectionIds | Where-Object { $_ -eq 'in-clientport' -or $_ -eq 'snapshot' }).Count 0 'do not treat peer source port as destination'

$identityRows=@(
    (New-AnalysisTestRow @{id='unsigned';processPath='C:\Users\Pat\Downloads\tool.exe';signatureStatus='NotSigned'}),
    (New-AnalysisTestRow @{id='uncheckable';processPath='C:\Other\gone.exe';signatureStatus='FileNotFound'}),
    (New-AnalysisTestRow @{id='unchecked';processPath='C:\Other\unchecked.exe';signatureStatus='Not checked'}),
    (New-AnalysisTestRow @{id='unknown1';processPath='';processId=501}),
    (New-AnalysisTestRow @{id='unknown2';processPath='';processId=502})
)
$result=Get-NetworkAnalysis $identityRows
Assert-AnalysisEqual $result.summary.applications 5 'unknown path PIDs do not merge'
Assert-AnalysisEqual @($result.findings | Where-Object code -eq 'signature-review').Count 1 'unsigned review only'
Assert-AnalysisEqual @($result.findings | Where-Object code -eq 'signature-unavailable').Count 1 'uncheckable separate'
Assert-AnalysisEqual @($result.findings | Where-Object code -eq 'profile-path').Count 1 'profile path review'
Assert-AnalysisEqual $result.coverage.signatureUncheckedRecords 1 'unchecked signature coverage'
Assert-AnalysisEqual $result.coverage.recordsWithoutProcessPath 2 'attribution coverage'

$uncheckableStates=@('Timeout','LargeFileSkipped','NonLocalPathSkipped','NonLocalDriveSkipped','ReparsePointSkipped','ChangedDuringInspection','FileUnavailable')
$uncheckableRows=@(foreach($status in $uncheckableStates){New-AnalysisTestRow @{id=$status;processPath=('C:\Program Files\'+$status+'\app.exe');signatureStatus=$status}})
$result=Get-NetworkAnalysis $uncheckableRows
Assert-AnalysisEqual @($result.findings | Where-Object code -eq 'signature-unavailable').Count 7 'metadata collection limits are uncheckable signatures'
Assert-AnalysisEqual @($result.findings | Where-Object code -eq 'signature-review').Count 0 'metadata collection limits are not unsigned or untrusted'

$many=@(for($i=1;$i -le 30;$i++){New-AnalysisTestRow @{id=('m'+$i);remoteAddress=('8.8.4.'+$i);dnsNames=@();observations=1000}})
$result=Get-NetworkAnalysis $many
$manyFinding=@($result.findings | Where-Object code -eq 'many-destinations')[0]
Assert-AnalysisEqual $manyFinding.level 'info' 'many addresses is informational'
Assert-AnalysisEqual $result.summary.records 30 'high observation count not traffic count'
Assert-AnalysisEqual $result.summary.publicRemoteAddresses 30 'many public addresses count'
Assert-AnalysisEqual @($result.findings | Where-Object { $_.PSObject.Properties['score'] }).Count 0 'no threat score'

$ipv6Rows=@(
    (New-AnalysisTestRow @{id='v6a';remoteAddress='2606:4700:4700:0:0:0:0:1111'}),
    (New-AnalysisTestRow @{id='v6b';remoteAddress='2606:4700:4700::1111';source='WFP5156'})
)
$result=Get-NetworkAnalysis $ipv6Rows
Assert-AnalysisEqual $result.summary.remoteAddresses 1 'equivalent IPv6 addresses normalized'
Assert-AnalysisEqual $result.summary.endpointCombinations 1 'IPv6 endpoint dedup'
$badTime=Get-NetworkAnalysis @((New-AnalysisTestRow @{firstSeen='invalid';allowed=$false;source='TcpSnapshot'}))
Assert-AnalysisEqual $badTime.coverage.recordsWithoutValidTime 1 'invalid time excluded explicitly'
Assert-AnalysisEqual $badTime.summary.blockedAuditRecords 0 'non-WFP false status not audit block'
Assert-AnalysisEqual @($badTime.timeline).Count 0 'invalid time no guessed timeline'
$json=$result | ConvertTo-Json -Depth 20 | ConvertFrom-Json
Assert-AnalysisEqual @($json.applications).Count 1 'JSON serializes correctly'
Write-Host ('Analysis: '+$script:AnalysisChecks+' checks passed.')
