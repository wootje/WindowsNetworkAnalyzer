# Windows Network Analyzer 3.0.1 - update an existing report's CSS only.
# Windows PowerShell 5.1 compatible. No elevation or network access required.
[CmdletBinding()]
param(
    [Parameter(Position=0)]
    [string]$InputHtml,
    [switch]$NoOpen
)
Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'
try {
    if ([string]::IsNullOrWhiteSpace($InputHtml)) {
        # The .cmd launcher uses -STA for this native Windows file picker.
        Add-Type -AssemblyName System.Windows.Forms
        $picker = New-Object System.Windows.Forms.OpenFileDialog
        try {
            $picker.Title = 'Select an existing Windows Network Analyzer report'
            $picker.Filter = 'HTML reports (*.html;*.htm)|*.html;*.htm'
            $picker.CheckFileExists = $true
            $picker.Multiselect = $false
            if ($picker.ShowDialog() -ne [System.Windows.Forms.DialogResult]::OK) {
                Write-Host 'No file selected. Nothing was changed.'
                return
            }
            $InputHtml = $picker.FileName
        } finally { $picker.Dispose() }
    }

    $item = Get-Item -LiteralPath $InputHtml -ErrorAction Stop
    if ($item.PSIsContainer -or $item.Extension -notmatch '^\.html?$') {
        throw 'Select a .html or .htm report file, not a folder or ZIP archive.'
    }
    $sourcePath = $item.FullName
    $cssPath = Join-Path $PSScriptRoot 'report-responsive.css'
    if (-not (Test-Path -LiteralPath $cssPath -PathType Leaf)) {
        throw 'report-responsive.css is missing. Extract the complete update ZIP first.'
    }
    $html = [IO.File]::ReadAllText($sourcePath, [Text.Encoding]::UTF8)
    $css = [IO.File]::ReadAllText($cssPath, [Text.Encoding]::UTF8)
    if ($html -notmatch 'id=["'']report-data["'']' -or
        $html -notmatch 'id=["'']rows["'']' -or
        $html -notmatch 'data-key=["'']lastSeen["'']' -or
        $html -notmatch '(?i)</head\s*>') {
        throw 'This does not look like a supported single-table Windows Network Analyzer HTML report.'
    }
    if ($css -notmatch 'Windows Network Analyzer 3\.0\.1' -or $css -match '(?i)</style') {
        throw 'The responsive stylesheet is missing its expected header or is invalid.'
    }

    # Replace only our own style block on subsequent runs. The report's
    # original styles, scripts, embedded JSON and relative links stay intact.
    $style = "`r`n<style id=`"wna-responsive-layout`">`r`n" + $css + "`r`n</style>`r`n"
    $styleRegex = New-Object Text.RegularExpressions.Regex '(?is)<style\b[^>]*\bid\s*=\s*["'']wna-responsive-layout["''][^>]*>.*?</style\s*>'
    $match = $styleRegex.Match($html)
    if ($match.Success) {
        if ($styleRegex.Matches($html).Count -ne 1) {
            throw 'Multiple responsive style blocks were found. Use the original report as input.'
        }
        $html = $html.Substring(0,$match.Index) + $style + $html.Substring($match.Index+$match.Length)
    } else {
        $head = [regex]::Match($html, '(?i)</head\s*>')
        $html = $html.Insert($head.Index, $style)
    }
    $html = $html.Replace(
        'Sortable connection table; scroll horizontally for all columns',
        'Sortable connection records; all fields fit the available width')

    $baseName = [IO.Path]::GetFileNameWithoutExtension($sourcePath)
    $outputPath = Join-Path $item.DirectoryName ($baseName + '-responsive' + $item.Extension)
    if (Test-Path -LiteralPath $outputPath) {
        $suffix = (Get-Date -Format 'yyyyMMdd-HHmmss') + '-' + [guid]::NewGuid().ToString('N').Substring(0,6)
        $outputPath = Join-Path $item.DirectoryName ($baseName + '-responsive-' + $suffix + $item.Extension)
    }
    $encoding = New-Object Text.UTF8Encoding $false
    $bytes = $encoding.GetBytes($html)
    # CreateNew prevents accidental replacement, even if another process
    # creates the chosen filename between the existence check and the write.
    $stream = [IO.File]::Open($outputPath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try { $stream.Write($bytes, 0, $bytes.Length) } finally { $stream.Dispose() }
    Write-Host 'Responsive report created. The original report is unchanged.' -ForegroundColor Green
    Write-Host ('Saved next to the original: ' + $outputPath)
    Write-Host 'No new capture, DNS lookup or registration lookup was performed.'
    Write-Output $outputPath
    if (-not $NoOpen) {
        try { Invoke-Item -LiteralPath $outputPath }
        catch { Write-Warning ('The report was saved, but could not be opened automatically: ' + $_.Exception.Message) }
    }
} catch {
    Write-Host ('ERROR: ' + $_.Exception.Message) -ForegroundColor Red
    exit 1
}
