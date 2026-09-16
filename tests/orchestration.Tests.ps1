$ErrorActionPreference='Stop'
$root=Split-Path $PSScriptRoot -Parent
$stage=Join-Path ([IO.Path]::GetTempPath()) ('network-orchestration-'+[guid]::NewGuid().ToString('N'))
$null=New-Item -ItemType Directory -Path $stage
try {
 foreach($name in @('Start-Network-Analyzer.ps1','Analysis.ps1','ConnectionExplanations.ps1','ReportBuilder.ps1','Enrichment.ps1','report-template.html','report-filters.js')) { Copy-Item (Join-Path $root $name) $stage }
 $path=Join-Path $stage 'Start-Network-Analyzer.ps1'
 $text=[IO.File]::ReadAllText($path).Replace("`$nrIsWindows = `$env:OS -eq 'Windows_NT'",'$nrIsWindows = $true')
 [IO.File]::WriteAllText($path,$text)
 @'
function Test-NrAdministrator { return $true }
function Get-NrNetworkContext { return [pscustomobject]@{Adapters=@();Warnings=@();DnsServers=@()} }
function Start-NrWfpCapture { param($RecoveryPath);Set-Content $RecoveryPath 'test recovery';return [pscustomobject]@{RecoveryPath=$RecoveryPath;Warnings=@();EventsRead=0;ParseFailures=0} }
function Stop-NrWfpCapture {param($Session);Remove-Item $Session.RecoveryPath;Set-Content (Join-Path (Split-Path $Session.RecoveryPath) 'restored.txt') 'yes'}
function Read-NrWfpCapture {param($Session);$Session.EventsRead++;[pscustomobject]@{Protocol='UDP';LocalAddress='10.10.10.10';LocalPort=12345;RemoteAddress='1.1.1.1';RemotePort=443;ProcessId=100;ProcessName='media.exe';ProcessPath='';Source='WFP5156';State='Permitted';Direction='Outbound';Allowed=$true}}
function Get-NrConnectionSnapshot { [CmdletBinding()]param();[pscustomobject]@{Protocol='UDP';LocalAddress='0.0.0.0';LocalPort=12345;RemoteAddress='';RemotePort=0;ProcessId=100;ProcessName='media.exe';ProcessPath='';Source='UdpEndpoint';State='Bound';Direction='Unknown (local endpoint)';Allowed=$null} }
function Get-DnsClientCache { @() }
'@ | Set-Content (Join-Path $stage 'WindowsCapture.ps1')
 @'
function Get-NrFileMetadata {param($Paths,[switch]$SkipSignatures,[switch]$SkipHashes,$TimeoutSeconds);return @{} }
'@ | Set-Content (Join-Path $stage 'FileMetadata.ps1')
 $out=Join-Path $stage 'result'
 & $path -DurationSeconds 10 -IntervalSeconds 1 -SkipRdap -SkipPtr -SkipSignatures -SkipHashes -NoOpen -OutputDirectory $out
 if(-not(Test-Path (Join-Path $out 'restored.txt'))){throw 'Audit cleanup missing'}
 if(Test-Path (Join-Path $out 'audit-recovery.json')){throw 'Recovery file was not removed'}
 $data=Get-Content -Raw (Join-Path $out 'report-data.json') | ConvertFrom-Json
 if($data.meta.phase -ne 'Complete' -or $data.meta.requestedDurationSeconds -ne 10){throw 'Final metadata incorrect'}
 if(@($data.connections).Count -ne 2){throw 'Unexpected row count'}
 if(@($data.connections|Where-Object source -eq 'UdpEndpoint')[0].remoteAddress -ne ''){throw 'Invented UDP remote destination'}
 if(@($data.connections|Where-Object source -eq 'WFP5156')[0].remoteAddress -ne '1.1.1.1'){throw 'WFP UDP endpoint missing'}
 if($null -eq $data.analysis.coverage){throw 'Analysis coverage missing'}
 if(@($data.connections | Where-Object { -not $_.explanation.summary }).Count -gt 0){throw 'Per-connection explanation missing'}
 # The writer uses UTF-8 without a BOM. Preserve non-ASCII application names and
 # paths when rebuilding, including on Windows PowerShell 5.1 (ANSI by default).
 $capturePath=Join-Path $out 'capture.json'
 $saved=Get-Content -LiteralPath $capturePath -Raw -Encoding UTF8 | ConvertFrom-Json
 $unicodeApplication='M'+[char]0x00FC+'nchen '+[char]0x6771+[char]0x4EAC
 $unicodePath='C:\Users\Andr'+[char]0x00E9+'\'+$unicodeApplication+'.exe'
 $saved.connections[0].application=$unicodeApplication
 $saved.connections[0].processName=$unicodeApplication+'.exe'
 $saved.connections[0].processPath=$unicodePath
 # Simulate a 2.0 capture: newer structured identity and explanation fields absent.
 $saved.meta.version='2.0.0'
 foreach($r in $saved.connections) {
   foreach($field in @('serviceDetails','serviceEvidence','attributionStatus','processEvidence','explanation')) { $r.PSObject.Properties.Remove($field) }
 }
 [IO.File]::WriteAllText($capturePath,($saved | ConvertTo-Json -Depth 60),(New-Object Text.UTF8Encoding($false)))
 $out2=Join-Path $stage 'rebuilt'
 # Rebuild with the real unmodified entry point on Linux: no capture/native API allowed.
 & (Join-Path $root 'Start-Network-Analyzer.ps1') -ReportFrom (Join-Path $out 'capture.json') -OutputDirectory $out2 -SkipRdap -SkipPtr -SkipSignatures -SkipHashes -NoOpen
 if(-not(Test-Path (Join-Path $out2 'report.html'))){throw 'Rebuild did not produce HTML'}
 $again=Get-Content -Raw -Encoding UTF8 (Join-Path $out2 'report-data.json') | ConvertFrom-Json
 if(@($again.connections).Count -ne 2){throw 'Rebuild changed captured row count'}
 if($again.connections[0].application -cne $unicodeApplication -or $again.connections[0].processPath -cne $unicodePath){throw 'UTF-8 application name or executable path was corrupted during rebuild'}
 if($again.meta.version -ne '3.0.1'){throw 'Rebuilt report generator version is stale'}
 if(@($again.connections | Where-Object { -not $_.explanation.summary }).Count -gt 0){throw 'Legacy capture explanations not generated'}
 Write-Host 'PASS orchestration: selectable duration, native-only sources, audit cleanup, UDP endpoint preservation, offline analysis, UTF-8 saved-capture rebuild.'
} finally { Remove-Item -LiteralPath $stage -Recurse -Force -ErrorAction SilentlyContinue }
