#requires -Version 5.1
<## Windows Network Analyzer 3.0.0. Run the .cmd launcher for the duration prompt. ##>
[CmdletBinding()]
param(
    [double]$DurationMinutes = 3,
    [ValidateRange(10,86400)][int]$DurationSeconds,
    [ValidateRange(1,60)][int]$IntervalSeconds = 2,
    [string]$OutputDirectory,
    [switch]$Interactive,
    [switch]$SkipWfp,
    [switch]$SkipRdap,
    [switch]$SkipPtr,
    [switch]$SkipSignatures,
    [switch]$CheckSignatures,
    [switch]$SkipHashes,
    [switch]$NoOpen,
    [string]$ReportFrom,
    [string]$RestoreAuditPolicy,
    [ValidateRange(100,500000)][int]$MaxConnections = 50000,
    [ValidateRange(1,30)][int]$LookupTimeoutSeconds = 8,
    [ValidateRange(3,120)][int]$FileTimeoutSeconds = 15,
    [ValidateRange(0,100000)][int]$MaxIpLookups = 0,
    [ValidateRange(0,100000)][int]$MaxDomainLookups = 0
)
$ErrorActionPreference = 'Stop'
foreach ($module in @('WindowsCapture.ps1','Enrichment.ps1','Analysis.ps1','ConnectionExplanations.ps1','FileMetadata.ps1','ReportBuilder.ps1')) {
    $path = Join-Path $PSScriptRoot $module
    if (-not (Test-Path -LiteralPath $path)) { throw "Missing $module. Extract the entire ZIP before running this script." }
    . $path
}
Initialize-NrReportState
if ($CheckSignatures -and $SkipSignatures) { throw 'Use either -CheckSignatures or -SkipSignatures, not both.' }
if ($PSBoundParameters.ContainsKey('DurationSeconds') -and $PSBoundParameters.ContainsKey('DurationMinutes')) {
    throw 'Use either -DurationSeconds or -DurationMinutes, not both.'
}
$nrIsWindows = $env:OS -eq 'Windows_NT'
$isAdmin = if ($nrIsWindows) { Test-NrAdministrator } else { $false }
if (-not $ReportFrom -and -not $nrIsWindows) { throw 'Live capture requires Windows 11 and 64-bit Windows PowerShell 5.1 or newer.' }
if ($nrIsWindows -and -not [Environment]::Is64BitProcess) { throw 'Use 64-bit PowerShell, not PowerShell (x86).' }
if ($nrIsWindows -and -not $isAdmin -and $Interactive -and -not $ReportFrom) {
    $parts = New-Object 'System.Collections.Generic.List[string]'
    foreach ($item in @('-NoProfile','-ExecutionPolicy','Bypass','-File',(ConvertTo-NrWindowsArgument $PSCommandPath))) { $parts.Add($item) }
    foreach ($entry in $PSBoundParameters.GetEnumerator()) {
        if ($entry.Key -eq 'Interactive') { continue }
        if ($entry.Value -is [switch]) { if ($entry.Value) { $parts.Add('-'+$entry.Key) } }
        else {
            $value = if ($entry.Value -is [IFormattable]) { $entry.Value.ToString($null,[Globalization.CultureInfo]::InvariantCulture) } else { [string]$entry.Value }
            if ($entry.Key -in @('OutputDirectory','RestoreAuditPolicy')) { $value=[IO.Path]::GetFullPath($value) }
            $parts.Add('-'+$entry.Key); $parts.Add((ConvertTo-NrWindowsArgument $value))
        }
    }
    $parts.Add('-Interactive')
    Write-Host 'Windows will request administrator access for the local connection audit.'
    $exe = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
    try {
        $child=Start-Process -FilePath $exe -ArgumentList ($parts -join ' ') -WorkingDirectory (Get-Location).ProviderPath -Verb RunAs -Wait -PassThru
        exit $child.ExitCode
    } catch { throw 'Administrator startup was cancelled or failed. Right-click Start-Network-Analyzer.cmd and select Run as administrator.' }
}
if ($RestoreAuditPolicy) {
    if (-not $nrIsWindows -or -not $isAdmin) { throw 'Restoring the audit setting requires PowerShell running as administrator on the original Windows PC.' }
    Restore-NrWfpAuditPolicy -RecoveryPath $RestoreAuditPolicy
    exit 0
}
if (-not $ReportFrom -and -not $SkipWfp -and -not $isAdmin) { throw 'Run PowerShell as administrator, or use -SkipWfp for a limited socket-only capture.' }

if ($Interactive -and -not $ReportFrom -and -not $PSBoundParameters.ContainsKey('DurationSeconds') -and -not $PSBoundParameters.ContainsKey('DurationMinutes')) {
    Write-Host ''
    Write-Host 'WINDOWS NETWORK ANALYZER 3.0' -ForegroundColor Cyan
    Write-Host 'Choose any duration from 10 seconds to 24 hours. Decimal minutes are accepted.'
    $recordSeconds = Read-NrDurationSeconds -DefaultMinutes 3
} elseif ($PSBoundParameters.ContainsKey('DurationSeconds')) { $recordSeconds=$DurationSeconds }
else { $recordSeconds=ConvertTo-NrDurationSeconds $DurationMinutes.ToString([Globalization.CultureInfo]::InvariantCulture) }

if (-not $OutputDirectory) {
    $OutputDirectory=Join-Path $PSScriptRoot ('Report-'+(Get-Date -Format 'yyyyMMdd-HHmmss')+'-'+[guid]::NewGuid().ToString('N').Substring(0,6))
}
$OutputDirectory=[IO.Path]::GetFullPath($OutputDirectory)
if (Test-Path -LiteralPath (Join-Path $OutputDirectory 'capture.json')) { throw 'The output folder already contains a capture. Choose a new output folder.' }
$null=New-Item -ItemType Directory -Path $OutputDirectory -Force
$templatePath=Join-Path $PSScriptRoot 'report-template.html'
$meta=[ordered]@{
    version='3.0.0';computer=$env:COMPUTERNAME;started='';finished='';durationSeconds=0
    requestedDurationSeconds=$recordSeconds;generated='';phase='Recording';warnings=@();sources=@()
    networkContext=$null;enrichmentStats=$null;signatureChecks=(-not $SkipSignatures);hashChecks=(-not $SkipHashes)
    rdapEnabled=(-not $SkipRdap);ptrEnabled=(-not $SkipPtr);snapshotRounds=0;wfpEvents=0;wfpParseFailures=0
    stopReason='Duration reached';recordLimit=$MaxConnections;truncated=$false
}

if ($ReportFrom) {
    $saved=Get-Content -LiteralPath $ReportFrom -Raw -Encoding UTF8 -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop
    if ($saved.format -ne 'WindowsNetworkAnalyzerCapture-v2' -or $null -eq $saved.meta -or $null -eq $saved.connections) {
        throw 'ReportFrom requires a version-2-format capture.json created by Windows Network Analyzer 2.x or 3.x.'
    }
    foreach ($property in $saved.meta.PSObject.Properties) { $meta[$property.Name]=$property.Value }
    $meta.version='3.0.0'
    foreach ($note in $saved.meta.warnings) { Add-NrWarning ([string]$note) }
    foreach ($source in $saved.meta.sources) { $null=$script:NrSourceNames.Add([string]$source) }
    $rows=@($saved.connections)
    Add-NrDnsRecords @($saved.dnsRecords)
    $meta.signatureChecks=(-not $SkipSignatures);$meta.hashChecks=(-not $SkipHashes)
    $meta.rdapEnabled=(-not $SkipRdap);$meta.ptrEnabled=(-not $SkipPtr)
    $meta.phase='Rebuilding report'
    Write-Host "Rebuilding $($rows.Count) saved records. No new network capture is started."
} else {
    if (-not $isAdmin) { Add-NrWarning 'Not running as administrator: process paths and other protected metadata can be unavailable.' }
    try {
        $meta.networkContext=Get-NrNetworkContext
        foreach ($note in $meta.networkContext.Warnings) { Add-NrWarning ([string]$note) }
    } catch { Add-NrWarning ('Network context unavailable: '+$_.Exception.Message) }
    $started=[datetime]::UtcNow; $deadline=$started.AddSeconds($recordSeconds)
    $meta.started=$started.ToString('o')
    $session=$null; $dnsNext=[datetime]::MinValue; $checkpointNext=$started.AddSeconds(30)
    $recoveryPath=Join-Path $OutputDirectory 'audit-recovery.json'
    $script:NrJournal=New-Object IO.StreamWriter((Join-Path $OutputDirectory 'observations.jsonl'),$false,$script:NrUtf8)
    $script:NrJournal.AutoFlush=$true
    Write-Host ''
    Write-Host ('Recording for {0:n1} minutes ({1} seconds).' -f ($recordSeconds/60),$recordSeconds) -ForegroundColor Cyan
    Write-Host 'Use the apps and websites you want to investigate. Press S to stop recording early and build the report.'
    Write-Host "Output: $OutputDirectory"
    try {
        if (-not $SkipWfp) {
            try {
                Write-Host 'Temporarily enabling Windows connection auditing; its original setting is saved for restoration.'
                $session=Start-NrWfpCapture -RecoveryPath $recoveryPath
            } catch { Add-NrWarning ('Windows connection audit unavailable: '+$_.Exception.Message) }
        } else { Add-NrWarning 'Windows connection auditing was skipped. UDP remote endpoints cannot be obtained from the UDP socket list alone.' }
        do {
            try {
                $captureNotes=@()
                Add-NrRows @(Get-NrConnectionSnapshot -WarningVariable captureNotes)
                foreach ($note in $captureNotes) { Add-NrWarning ([string]$note) }
                $meta.snapshotRounds++
            } catch { Add-NrWarning ('Socket snapshot failed: '+$_.Exception.Message) }
            if ($null -ne $session) {
                try { Add-NrRows @(Read-NrWfpCapture -Session $session) }
                catch { Add-NrWarning ('Reading Windows audit failed: '+$_.Exception.Message) }
            }
            if ([datetime]::UtcNow -ge $dnsNext) {
                try { Add-NrDnsRecords @(Get-NetworkDnsCacheSnapshot) }
                catch { Add-NrWarning ('Reading the DNS cache failed: '+$_.Exception.Message) }
                $dnsNext=[datetime]::UtcNow.AddSeconds(10)
            }
            if ([datetime]::UtcNow -ge $checkpointNext) {
                $meta.finished=[datetime]::UtcNow.ToString('o');$meta.durationSeconds=[int]([datetime]::UtcNow-$started).TotalSeconds
                Write-NrCaptureCheckpoint $OutputDirectory $meta @($script:NrRows.Values) @($script:NrDns.Values)
                $checkpointNext=[datetime]::UtcNow.AddSeconds(30)
            }
            $remaining=[math]::Max(0,[int]($deadline-[datetime]::UtcNow).TotalSeconds)
            Write-Progress -Activity 'Recording network metadata' -Status "$remaining seconds remaining; $($script:NrRows.Count) records" -PercentComplete ([math]::Min(100,100*(([datetime]::UtcNow-$started).TotalSeconds/$recordSeconds)))
            try {
                if (-not [Console]::IsInputRedirected -and [Console]::KeyAvailable) {
                    $key=[Console]::ReadKey($true)
                    if ($key.Key -eq [ConsoleKey]::S) { $meta.stopReason='Stopped with S'; break }
                }
            } catch { } # Hosts without an interactive console still honor the chosen duration.
            if ([datetime]::UtcNow -lt $deadline) { Start-Sleep -Milliseconds ([int]([math]::Max(0,[math]::Min($IntervalSeconds,($deadline-[datetime]::UtcNow).TotalSeconds))*1000)) }
        } while ([datetime]::UtcNow -lt $deadline)
        if ($null -ne $session) {
            Start-Sleep -Seconds 1
            for ($flush=0;$flush -lt 5;$flush++) {
                $before=$session.EventsRead
                Add-NrRows @(Read-NrWfpCapture -Session $session)
                if (($session.EventsRead-$before) -lt 10000) { break }
            }
            if ($flush -ge 5) { Add-NrWarning 'The final Windows event drain reached its limit. Some audit events may be missing.' }
        }
    } catch {
        $meta.stopReason='Capture error'; Add-NrWarning ('Capture stopped early: '+$_.Exception.Message)
    } finally {
        if ($null -ne $session) {
            try { Stop-NrWfpCapture -Session $session; Write-Host 'The Windows connection-audit setting was restored.' }
            catch { Add-NrWarning ("Audit restoration failed: "+$_.Exception.Message+". Run -RestoreAuditPolicy with: $recoveryPath") }
            foreach ($note in $session.Warnings) { Add-NrWarning ([string]$note) }
            $meta.wfpEvents=$session.EventsRead;$meta.wfpParseFailures=$session.ParseFailures
        }
        if ($null -ne $script:NrJournal) { $script:NrJournal.Dispose();$script:NrJournal=$null }
        Write-Progress -Activity 'Recording network metadata' -Completed
        $meta.finished=[datetime]::UtcNow.ToString('o');$meta.durationSeconds=[int]([datetime]::UtcNow-$started).TotalSeconds
        $meta.truncated=$script:NrLimitWarned;$meta.phase='Capture complete; enrichment pending'
        $rows=@($script:NrRows.Values | Sort-Object processName,remoteAddress,remotePort,source)
        Update-NrAddressScopes $rows
        # Save raw data and a usable offline report before any slower file/online lookups.
        Write-NrCaptureCheckpoint $OutputDirectory $meta $rows @($script:NrDns.Values)
        Write-NrHtmlReport $OutputDirectory $templatePath $meta $rows
    }
}

Update-NrAddressScopes $rows
$meta.phase='Enrichment in progress'
Write-NrCaptureCheckpoint $OutputDirectory $meta $rows @($script:NrDns.Values)
if ($ReportFrom) { Write-NrHtmlReport $OutputDirectory $templatePath $meta $rows }
Write-Host "Capture saved: $($rows.Count) records. Inspecting executable files..."
try {
    $paths=@($rows | ForEach-Object { $_.processPath } | Where-Object { $_ } | Sort-Object -Unique)
    if ($nrIsWindows) {
        $files=Get-NrFileMetadata -Paths $paths -SkipSignatures:$SkipSignatures -SkipHashes:$SkipHashes -TimeoutSeconds $FileTimeoutSeconds
        Merge-NrFileMetadata $rows $files
        Write-NrJson (Join-Path $OutputDirectory 'file-metadata.json') $files
    } elseif ($paths.Count -gt 0) { Add-NrWarning 'Executable inspection requires the original Windows PC; existing saved metadata is retained.' }
} catch { Add-NrWarning ('Executable inspection incomplete: '+$_.Exception.Message) }
Write-NrCaptureCheckpoint $OutputDirectory $meta $rows @($script:NrDns.Values)
Write-Host 'Looking up DNS and public IP/domain registration records...'
try {
    $addresses=@($rows | ForEach-Object { $_.remoteAddress; $_.localAddress } | Where-Object { $_ } | Sort-Object -Unique)
    $enrichment=Invoke-NetworkEnrichment -Addresses $addresses -DnsRecords @($script:NrDns.Values) -OutputDirectory $OutputDirectory -TimeoutSeconds $LookupTimeoutSeconds -MaxIpLookups $MaxIpLookups -MaxDomainLookups $MaxDomainLookups -SkipPtr:$SkipPtr -SkipRdap:$SkipRdap -CheckpointPath (Join-Path $OutputDirectory 'enrichment-partial.json')
    foreach ($note in $enrichment.warnings) { Add-NrWarning ([string]$note) }
    Merge-NrEnrichment $rows $enrichment
    $meta.enrichmentStats=$enrichment.stats
    Write-NrJson (Join-Path $OutputDirectory 'enrichment.json') $enrichment
} catch { Add-NrWarning ('DNS/registration lookup incomplete: '+$_.Exception.Message) }
$meta.phase='Complete';$meta.generated=[datetime]::UtcNow.ToString('o')
Write-NrHtmlReport $OutputDirectory $templatePath $meta $rows
Write-NrCaptureCheckpoint $OutputDirectory $meta $rows @($script:NrDns.Values)
$htmlPath=Join-Path $OutputDirectory 'report.html'
Write-Host ''
Write-Host 'Report ready:' -ForegroundColor Green
Write-Host $htmlPath
Write-Host 'The HTML file works offline. Share the report folder for raw registration links; it contains network and process metadata.'
if (-not $NoOpen) { try { Start-Process -FilePath $htmlPath } catch { Write-Warning 'Open report.html in your browser manually.' } }
if ($Interactive) { $null=Read-Host 'Press Enter to close this window' }
