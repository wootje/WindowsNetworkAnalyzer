# Development regression checks for the offline report-layout patcher.
# Run in a fresh PowerShell process; this does not collect network data.
$ErrorActionPreference = 'Stop'
$root = Split-Path $PSScriptRoot -Parent
$patcher = Join-Path $root 'Apply-Responsive-Layout.ps1'
$checks = 0
function Assert($Condition, [string]$Message) {
    if (-not $Condition) { throw $Message }
    $script:checks++
}
$tokens = $null
$parseErrors = $null
$null = [System.Management.Automation.Language.Parser]::ParseFile($patcher, [ref]$tokens, [ref]$parseErrors)
Assert ($parseErrors.Count -eq 0) 'Patcher parses without errors'
$temp = Join-Path ([IO.Path]::GetTempPath()) ('wna-css-test-'+[guid]::NewGuid().ToString('N'))
$null = New-Item -ItemType Directory -Path $temp
try {
    $source = Join-Path $temp 'Example [report].html'
    $template = [IO.File]::ReadAllText((Join-Path $root 'report-template.html'))
    $template = [regex]::Replace($template, '(?is)<style id="wna-responsive-layout">.*?</style>', '')
    $payload = '{"meta":{"version":"3.0.0"},"connections":[{"id":"test","processName":"example.exe","dnsNames":["example.test"]}]}'
    $engine = [IO.File]::ReadAllText((Join-Path $root 'report-filters.js'))
    $html = $template.Replace('__NETWORK_REPORT_FILTER_ENGINE__',$engine).Replace('__NETWORK_REPORT_DATA__',$payload)
    [IO.File]::WriteAllText($source,$html,(New-Object Text.UTF8Encoding $false))
    $before = (Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash
    $output = & $patcher -InputHtml $source -NoOpen
    Assert (Test-Path -LiteralPath $output -PathType Leaf) 'Responsive copy created'
    Assert ($output -ne $source) 'Source path is never reused'
    Assert ((Split-Path $output -Parent) -eq $temp) 'Copy remains alongside original evidence'
    Assert ((Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash -eq $before) 'Source bytes unchanged'
    $updated = [IO.File]::ReadAllText($output)
    Assert ([regex]::Matches($updated,'id="wna-responsive-layout"').Count -eq 1) 'Exactly one stylesheet'
    $scriptsBefore = [regex]::Matches($html,'(?is)<script(?:\s[^>]*)?>.*?</script>')
    $scriptsAfter = [regex]::Matches($updated,'(?is)<script(?:\s[^>]*)?>.*?</script>')
    Assert ($scriptsBefore.Count -eq $scriptsAfter.Count) 'No added script blocks'
    for ($i=0;$i -lt $scriptsBefore.Count;$i++) {
        Assert ($scriptsBefore[$i].Value -ceq $scriptsAfter[$i].Value) 'Script/JSON bytes preserved as text'
    }
    Assert ($updated.Contains($payload)) 'Captured data retained'
    Assert ($updated.Contains('"version":"3.0.0"')) 'Capture version not rewritten'
    $second = & $patcher -InputHtml $source -NoOpen
    Assert ($second -ne $output) 'Existing output is not overwritten'
    $repatched = & $patcher -InputHtml $output -NoOpen
    $again = [IO.File]::ReadAllText($repatched)
    Assert ([regex]::Matches($again,'id="wna-responsive-layout"').Count -eq 1) 'Repeated patch replaces its own stylesheet'
    Assert ($again.Contains($payload)) 'Repeated patch preserves record data'
} finally { Remove-Item -LiteralPath $temp -Recurse -Force }
Write-Host "Responsive patcher: $checks checks passed."
