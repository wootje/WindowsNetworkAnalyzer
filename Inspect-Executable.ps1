# Internal worker. Never launches or loads the inspected executable as code.
param([Parameter(Mandatory=$true)][string]$RequestPath)
$ErrorActionPreference = 'Stop'
$resultPath = $null
try {
    . (Join-Path $PSScriptRoot 'FileMetadata.ps1')
    $request = [IO.File]::ReadAllText($RequestPath) | ConvertFrom-Json
    # The parent creates both files inside one access-restricted temporary directory.
    $requestDirectory = [IO.Path]::GetDirectoryName([IO.Path]::GetFullPath($RequestPath))
    $candidateResult = [IO.Path]::GetFullPath([string]$request.resultPath)
    if ([IO.Path]::GetDirectoryName($candidateResult) -ne $requestDirectory) { throw 'Invalid worker output directory.' }
    $resultPath = $candidateResult
    $result = Invoke-NrInspectLocalFile -Path ([string]$request.path) -SkipSignatures:([bool]$request.skipSignatures) -SkipHashes:([bool]$request.skipHashes)
    [IO.File]::WriteAllText($resultPath, ($result | ConvertTo-Json -Depth 5 -Compress), (New-Object Text.UTF8Encoding($false)))
    exit 0
} catch {
    if ($resultPath) {
        try {
            $failure = New-NrMetadataResult -Status 'WorkerError' -ErrorText $_.Exception.Message
            [IO.File]::WriteAllText($resultPath, ($failure | ConvertTo-Json -Compress), (New-Object Text.UTF8Encoding($false)))
        } catch { }
    }
    exit 1
}
