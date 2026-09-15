$ErrorActionPreference='Stop'
$root=Split-Path $PSScriptRoot -Parent
. (Join-Path $root 'ReportBuilder.ps1')
. (Join-Path $root 'Enrichment.ps1')
. (Join-Path $root 'Analysis.ps1')
. (Join-Path $root 'ConnectionExplanations.ps1')
$MaxConnections=100
Initialize-NrReportState
$checks=0
function Assert($condition,$message) { if(-not $condition){throw $message};$script:checks++ }
foreach($pair in @(@('5',300),@('0.5',30),@('0,5',30),@('1440',86400),@('1',60))) {
 Assert ((ConvertTo-NrDurationSeconds $pair[0]) -eq $pair[1]) ('Duration '+$pair[0])
}
foreach($bad in @('NaN','Infinity','-1','0','abc','1441')) {
 $caught=$false;try{ConvertTo-NrDurationSeconds $bad | Out-Null}catch{$caught=$true};Assert $caught ('Reject duration '+$bad)
}
$script:promptAnswers = New-Object 'System.Collections.Generic.Queue[string]'
function Read-Host { param([string]$Prompt); $script:seenPrompt=$Prompt; return $script:promptAnswers.Dequeue() }
$script:promptAnswers.Enqueue('')
Assert ((Read-NrDurationSeconds -DefaultMinutes 3) -eq 180) 'Enter selects the original three-minute default'
Assert ($script:seenPrompt -match 'minutes.*Enter = 3') 'Duration prompt communicates minutes and default'
$script:promptAnswers.Enqueue('bad');$script:promptAnswers.Enqueue('0,5')
Assert ((Read-NrDurationSeconds) -eq 30) 'Invalid input is retried and decimal comma is accepted'
Assert ($script:promptAnswers.Count -eq 0) 'Prompt consumed only the expected answers'
$script:promptAnswers.Enqueue('10')
Assert ((Read-NrDurationSeconds) -eq 600) 'Entered minutes converted to recording seconds'
Remove-Item function:Read-Host
Assert ((ConvertTo-NrWindowsArgument 'C:\') -eq '"C:\\"') 'Trailing slash quoting'
Assert ((ConvertTo-NrWindowsArgument 'a"b') -eq '"a\"b"') 'Embedded quote quoting'
$time='2026-09-15T10:00:00Z'
$raw=[pscustomobject]@{Protocol='TCP';LocalAddress='10.10.10.10';LocalPort=55555;RemoteAddress='8.8.8.8';RemotePort=443;ProcessId=10;ProcessName='browser.exe';ProcessPath='C:\Apps\browser.exe';ProcessStartTimeUtc='2026-09-15T09:00:00Z';State='Established';Source='TcpSnapshot';Direction='Unknown (snapshot)';Allowed=$null;FirstSeenUtc=$time;LastSeenUtc=$time}
Add-NrRows @($raw);$raw.LastSeenUtc='2026-09-15T10:00:05Z';Add-NrRows @($raw)
$raw.LastSeenUtc='2026-09-15T10:00:01Z';Add-NrRows @($raw)
$row=@($script:NrRows.Values)[0]
Assert ($row.observations -eq 3) 'Repeated observations'
Assert ($row.lastSeen -eq '2026-09-15T10:00:05.0000000Z') 'Late event cannot move time backwards'
Assert ($row.allowed -eq 'Unknown') 'Unknown decision stays unknown'
Assert ($row.id -eq 'c000001') 'Stable record identifier'
$raw | Add-Member ServiceDetails @([pscustomobject]@{Name='Dnscache';DisplayName='DNS Client';Description='Resolves and caches DNS names';State='Running';StartMode='Auto'})
$raw | Add-Member Services @('Dnscache')
$raw | Add-Member ServiceEvidence 'Service observed in the owning process; exact connection initiator unknown.'
Add-NrRows @($raw)
Assert ($row.serviceDetails.Count -eq 1 -and $row.serviceDetails[0].name -eq 'Dnscache') 'Later service snapshot enriches existing process identity'
Assert ($row.serviceDetails[0].displayName -eq 'DNS Client') 'Service display name preserved'
Assert ($row.serviceEvidence -match 'initiator unknown') 'Service attribution limitation preserved'
Assert ($row.attributionStatus -eq 'Unavailable') 'Missing structured attribution stays unavailable'
Update-NrAddressScopes @($row)
Assert ($row.ipScope -eq 'Public' -and $row.localIpScope -eq 'Private') 'Local/remote scope'
$row.application='</script><script>alert(1)</script>'
$dir=Join-Path ([IO.Path]::GetTempPath()) ('network-builder-test-'+[guid]::NewGuid().ToString('N'))
$null=New-Item -ItemType Directory -Path $dir
try {
 $meta=[ordered]@{computer='TEST';warnings=@();sources=@();started=$time;finished='2026-09-15T10:00:05Z';durationSeconds=5}
 Write-NrCaptureCheckpoint $dir $meta @($row) @()
 Write-NrHtmlReport $dir (Join-Path $root 'report-template.html') $meta @($row)
 $capture=Get-Content -Raw (Join-Path $dir 'capture.json') | ConvertFrom-Json
 Assert ($capture.format -eq 'WindowsNetworkAnalyzerCapture-v2') 'Capture format'
 $html=Get-Content -Raw (Join-Path $dir 'report.html')
 Assert (-not $html.Contains('__NETWORK_REPORT_DATA__')) 'Template replaced'
 Assert (-not $html.Contains('__NETWORK_REPORT_FILTER_ENGINE__')) 'Filter engine is embedded into the standalone HTML'
 Assert ($html.Contains('NetworkReportFilters')) 'Advanced filtering code is present in the generated report'
 Assert (-not $html.Contains('<script>alert(1)</script>')) 'No inline script injection'
 Assert ($html.Contains('\u003c/script\u003e')) 'JSON escaped for HTML'
 $data=Get-Content -Raw (Join-Path $dir 'report-data.json') | ConvertFrom-Json
 Assert ($null -ne $data.analysis -and @($data.connections).Count -eq 1) 'Analysis embedded'
 Assert ($data.connections[0].explanation.summary.Length -gt 0) 'Every connection has an explanation'
 Assert ($data.connections[0].explanation.necessity.Length -gt 0) 'Purpose does not imply necessity'
 Assert ($data.analysis.applications[0].serviceDetails[0].name -eq 'Dnscache') 'Application view retains detailed service association'
 Initialize-NrReportState
 $raw | Add-Member AttributionStatus 'MatchedLiveProcess'
 $raw | Add-Member ProcessEvidence 'Windows socket PID and start time checked.'
 Add-NrRows @($raw)
 $firstServiceRow=@($script:NrRows.Values)[0]
 Assert ($firstServiceRow.serviceDetails[0].name -eq 'Dnscache') 'Initial service details retained'
 Assert ($firstServiceRow.attributionStatus -eq 'MatchedLiveProcess') 'Structured attribution retained'
 Assert ($firstServiceRow.processEvidence -match 'start time checked') 'Process identity evidence retained'
} finally { Remove-Item -LiteralPath $dir -Recurse -Force }
Write-Host "Report builder: $checks checks passed."
