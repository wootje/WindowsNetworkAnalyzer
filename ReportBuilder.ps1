# Shared report normalization and serialization. Windows PowerShell 5.1.
function Add-NrWarning([string]$Message) {
    if (-not $script:NrWarnings.Contains($Message)) {
        $script:NrWarnings.Add($Message)
        Write-Warning $Message
    }
}
function Get-NrValue($Object, [string[]]$Names, $Default = '') {
    foreach ($name in $Names) {
        if ($null -eq $Object) { continue }
        $v = $null
        if ($Object -is [System.Collections.IDictionary]) {
            if ($Object.Contains($name)) { $v = $Object[$name] }
        } elseif ($null -ne $Object.PSObject.Properties[$name]) { $v = $Object.$name }
        if ($null -ne $v -and -not ($v -is [string] -and $v.Length -eq 0)) {
            # PSCustomObject arrays can stringify to an empty string. Keep the
            # structured value so service metadata is not discarded.
            return $v
        }
    }
    return $Default
}
function ConvertTo-NrTime($Value) {
    if ($null -eq $Value -or [string]$Value -eq '') { return [DateTime]::UtcNow.ToString('o') }
    try { return ([datetime]$Value).ToUniversalTime().ToString('o') } catch { return [string]$Value }
}
function Add-NrDnsRecords($Records) {
    foreach ($record in $Records) {
        $name = [string](Get-NrValue $record @('name','Entry','RecordName'))
        $data = [string](Get-NrValue $record @('data','Data'))
        if ($name -and $data) { $script:NrDns[$name.ToLowerInvariant() + '|' + $data] = $record }
    }
}
function ConvertTo-NrServiceDetails($Details) {
    foreach ($detail in @($Details)) {
        if ($null -eq $detail) { continue }
        $name = [string](Get-NrValue $detail @('Name'))
        if (-not $name) { continue }
        [pscustomobject][ordered]@{
            name=$name
            displayName=[string](Get-NrValue $detail @('DisplayName'))
            description=[string](Get-NrValue $detail @('Description'))
            state=[string](Get-NrValue $detail @('State'))
            startMode=[string](Get-NrValue $detail @('StartMode'))
        }
    }
}
function Add-NrRows($Rows) {
    foreach ($raw in $Rows) {
        if ($null -eq $raw) { continue }
        $source = [string](Get-NrValue $raw @('Source') 'Unknown')
        $null = $script:NrSourceNames.Add($source)
        $procPath = [string](Get-NrValue $raw @('ProcessPath'))
        $procId = [long](Get-NrValue $raw @('ProcessId') 0)
        $procStart = [string](Get-NrValue $raw @('ProcessStartTimeUtc'))
        $remote = [string](Get-NrValue $raw @('RemoteAddress'))
        $protocol = [string](Get-NrValue $raw @('Protocol') 'Unknown')
        $allowed = Get-NrValue $raw @('Allowed') 'Unknown'
        $state = [string](Get-NrValue $raw @('State') 'Unknown')
        $direction = [string](Get-NrValue $raw @('Direction') 'Unknown')
        $localAddress = [string](Get-NrValue $raw @('LocalAddress'))
        $localPort = Get-NrValue $raw @('LocalPort') 0
        $remotePort = Get-NrValue $raw @('RemotePort') 0
        # Keep Windows audit decisions separate from socket observations.
        $key = @($source,$protocol,$procId,$procStart,$procPath,$localAddress,$localPort,$remote,$remotePort,$direction,[string]$allowed) -join '|'
        if ($script:NrRows.ContainsKey($key)) {
            $row = $script:NrRows[$key]
            $observedLast = ConvertTo-NrTime (Get-NrValue $raw @('LastSeenUtc','LastSeen'))
            if ($observedLast -gt $row.lastSeen) { $row.lastSeen = $observedLast }
            $row.observations++
            $row.state = $state
            if ($state -notin $row.states) { $row.states = @($row.states) + $state }
            # Retain the first available service snapshot for the same process
            # identity. Do not combine services into an invented exact initiator.
            if (@($row.serviceDetails).Count -eq 0) {
                $details = @(ConvertTo-NrServiceDetails (Get-NrValue $raw @('ServiceDetails') @()))
                if ($details.Count -gt 0) {
                    $row.serviceDetails = $details
                    $row.services = @(Get-NrValue $raw @('Services') @())
                    $row.serviceEvidence = [string](Get-NrValue $raw @('ServiceEvidence'))
                }
            }
            continue
        }
        if ($script:NrRows.Count -ge $MaxConnections) {
            if (-not $script:NrLimitWarned) {
                Add-NrWarning "The $MaxConnections record limit was reached. New endpoint combinations are omitted; existing records still update."
                $script:NrLimitWarned = $true
            }
            continue
        }
        $row = [pscustomobject][ordered]@{
            id = ('c{0:D6}' -f ($script:NrRows.Count + 1)); protocol = $protocol; localAddress = $localAddress; localPort = $localPort
            remoteAddress = $remote; remotePort = $remotePort; processId = $procId
            processName = [string](Get-NrValue $raw @('ProcessName') 'Unknown or exited')
            processPath = $procPath; processStartTimeUtc = $procStart
            socketCreatedUtc = [string](Get-NrValue $raw @('SocketCreatedUtc'))
            application = [string](Get-NrValue $raw @('Application','ProcessName') 'Unknown')
            services = @(Get-NrValue $raw @('Services') @())
            serviceDetails = @(ConvertTo-NrServiceDetails (Get-NrValue $raw @('ServiceDetails') @()))
            serviceEvidence = [string](Get-NrValue $raw @('ServiceEvidence'))
            dnsNames = @(); dnsEvidence = ''; ptrNames = @(); ptrStatus = 'Not checked'; ptrError = ''
            state = $state; states = @($state); source = $source
            firstSeen = ConvertTo-NrTime (Get-NrValue $raw @('FirstSeenUtc','FirstSeen'))
            lastSeen = ConvertTo-NrTime (Get-NrValue $raw @('LastSeenUtc','LastSeen'))
            direction = $direction; allowed = $allowed; observations = 1
            attribution = [string](Get-NrValue $raw @('Attribution') 'See data source')
            attributionStatus = [string](Get-NrValue $raw @('AttributionStatus') 'Unavailable')
            processEvidence = [string](Get-NrValue $raw @('ProcessEvidence','Attribution') 'Process attribution evidence was not supplied by this source.')
            signatureStatus = 'Not checked'; signer = ''; company = ''; fileVersion = ''
            sha256 = ''; hashStatus = 'Not checked'; metadataCollectedUtc = ''; metadataError = ''
            metadataStatus = 'Not checked'; fileSize = ''; lastWriteUtc = ''
            ipScope = ''; ipRegistration = $null; localIpScope = ''; localIpRegistration = $null; domainRegistrations = @()
        }
        $script:NrRows[$key] = $row
        if ($null -ne $script:NrJournal) {
            $script:NrJournal.WriteLine(($row | ConvertTo-Json -Depth 12 -Compress))
        }
    }
}
function Write-NrJson([string]$Path, $Value) {
    $json = ConvertTo-Json -InputObject $Value -Depth 40
    $tempPath = $Path + '.' + [guid]::NewGuid().ToString('N') + '.tmp'
    try { [IO.File]::WriteAllText($tempPath, $json, $script:NrUtf8); Move-Item -LiteralPath $tempPath -Destination $Path -Force }
    finally { if (Test-Path -LiteralPath $tempPath) { Remove-Item -LiteralPath $tempPath -Force } }
}

function Initialize-NrReportState {
    $script:NrWarnings = New-Object 'System.Collections.Generic.List[string]'
    $script:NrRows = @{}
    $script:NrDns = @{}
    $script:NrLimitWarned = $false
    $script:NrJournal = $null
    $script:NrSourceNames = New-Object 'System.Collections.Generic.HashSet[string]'
    $script:NrUtf8 = New-Object System.Text.UTF8Encoding($false)
}

function ConvertTo-NrDurationSeconds {
    param([string]$Minutes)
    $value = 0.0
    $normal = $Minutes.Trim().Replace(',','.')
    if (-not [double]::TryParse($normal, [Globalization.NumberStyles]::Float,
        [Globalization.CultureInfo]::InvariantCulture, [ref]$value) -or
        [double]::IsNaN($value) -or [double]::IsInfinity($value)) { throw 'Enter a number of minutes, for example 5 or 0.5.' }
    $seconds = [math]::Round($value * 60)
    if ($seconds -lt 10 -or $seconds -gt 86400) { throw 'Choose a duration between 10 seconds and 24 hours.' }
    return [int]$seconds
}

function ConvertTo-NrWindowsArgument {
    param([AllowEmptyString()][string]$Value)
    # CommandLineToArgvW quoting, including a trailing backslash before a closing quote.
    $encoded = [regex]::Replace($Value, '(\\*)"', '$1$1\"')
    $encoded = [regex]::Replace($encoded, '(\\+)$', '$1$1')
    return '"' + $encoded + '"'
}

function Read-NrDurationSeconds {
    param([int]$DefaultMinutes = 3)
    do {
        $choice = Read-Host "Recording duration in minutes (e.g. 1, 5, 10, 30, 60; Enter = $DefaultMinutes)"
        if ([string]::IsNullOrWhiteSpace($choice)) { $choice = [string]$DefaultMinutes }
        try { return (ConvertTo-NrDurationSeconds $choice) }
        catch { Write-Host $_.Exception.Message -ForegroundColor Yellow }
    } while ($true)
}

function Update-NrAddressScopes($Rows) {
    foreach ($row in $Rows) {
        $row.ipScope = if ($row.remoteAddress) { (Get-NetworkAddressScope -Address $row.remoteAddress).scope } else { 'No remote endpoint' }
        $row.localIpScope = if ($row.localAddress) { (Get-NetworkAddressScope -Address $row.localAddress).scope } else { 'Unknown' }
    }
}

function Write-NrCaptureCheckpoint([string]$Directory, $Meta, $Rows, $DnsRecords) {
    $Meta.warnings = @($script:NrWarnings.ToArray())
    $Meta.sources = @($script:NrSourceNames)
    Write-NrJson (Join-Path $Directory 'capture.json') ([ordered]@{format='WindowsNetworkAnalyzerCapture-v2';meta=$Meta;connections=@($Rows);dnsRecords=@($DnsRecords)})
}

function Write-NrHtmlReport([string]$Directory, [string]$TemplatePath, $Meta, $Rows) {
    $Meta.warnings = @($script:NrWarnings.ToArray())
    $Meta.sources = @($script:NrSourceNames)
    Update-NrConnectionExplanations -Connections @($Rows) -Meta ([pscustomobject]$Meta)
    $analysis = Get-NetworkAnalysis -Connections @($Rows) -Meta ([pscustomobject]$Meta)
    $document = [ordered]@{meta=$Meta;connections=@($Rows);analysis=$analysis}
    Write-NrJson (Join-Path $Directory 'report-data.json') $document
    $json = ConvertTo-Json -InputObject $document -Depth 60 -Compress
    $json = $json.Replace('&','\u0026').Replace('<','\u003c').Replace('>','\u003e').Replace([string][char]0x2028,'\u2028').Replace([string][char]0x2029,'\u2029')
    $template = [IO.File]::ReadAllText($TemplatePath)
    if (-not $template.Contains('__NETWORK_REPORT_DATA__')) { throw 'The HTML template is missing its data placeholder.' }
    if ($template.Contains('__NETWORK_REPORT_FILTER_ENGINE__')) {
        $filterPath = Join-Path (Split-Path -Parent $TemplatePath) 'report-filters.js'
        if (-not (Test-Path -LiteralPath $filterPath -PathType Leaf)) { throw 'report-filters.js is missing. Extract the complete release archive.' }
        $filterScript = [IO.File]::ReadAllText($filterPath)
        $filterScript = [regex]::Replace($filterScript, '(?i)</script', '<\/script')
        $template = $template.Replace('__NETWORK_REPORT_FILTER_ENGINE__', $filterScript)
    }
    $path = Join-Path $Directory 'report.html'
    $temp = $path + '.tmp'
    [IO.File]::WriteAllText($temp, $template.Replace('__NETWORK_REPORT_DATA__',$json), $script:NrUtf8)
    Move-Item -LiteralPath $temp -Destination $path -Force
}

function Merge-NrEnrichment($Rows, $Enrichment) {
    $ipMap = @{}
    foreach ($entry in $Enrichment.addresses) { $ipMap[[string]$entry.address] = $entry }
    foreach ($row in $Rows) {
        if ($ipMap.ContainsKey($row.localAddress)) {
            $row.localIpScope = [string]$ipMap[$row.localAddress].scope
            $row.localIpRegistration = $ipMap[$row.localAddress].whois
        }
        if ($ipMap.ContainsKey($row.remoteAddress)) {
            $entry = $ipMap[$row.remoteAddress]
            $row.ipScope = [string]$entry.scope
            $row.ptrNames = @($entry.ptrNames)
            $row.ptrStatus = [string]$entry.ptrStatus
            $row.ptrError = [string]$entry.ptrError
            $row.ipRegistration = $entry.whois
            $row.domainRegistrations = @($entry.domainWhois)
            $row.dnsNames = @($entry.dnsCandidates)
            if ($row.dnsNames.Count) { $row.dnsEvidence = 'Candidates from the shared Windows DNS cache. This does not establish which process requested a name; several domains may share one IP.' }
        }
    }
}

function Merge-NrFileMetadata($Rows, [hashtable]$Metadata) {
    foreach ($row in $Rows) {
        if (-not $row.processPath -or -not $Metadata.ContainsKey($row.processPath)) { continue }
        $entry = $Metadata[$row.processPath]
        if ($entry.application) { $row.application = [string]$entry.application }
        foreach ($field in @('company','fileVersion','signatureStatus','signer','sha256','hashStatus','metadataCollectedUtc','metadataStatus','fileSize','lastWriteUtc')) {
            $row.$field = [string]$entry.$field
        }
        $row.metadataError = [string]$entry.error
    }
}
