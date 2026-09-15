# Portable, offline checks. Windows path validation and Authenticode are mocked
# where necessary; these tests do NOT assert an actual Windows trust verdict.
$ErrorActionPreference = 'Stop'
$modulePath = Join-Path (Split-Path $PSScriptRoot -Parent) 'FileMetadata.ps1'
. $modulePath
$script:testCount = 0
function Assert-Equal($Actual, $Expected, [string]$Label) {
    if ($Actual -cne $Expected) { throw "$Label`: expected [$Expected], got [$Actual]" }
    $script:testCount++
}
foreach ($invalid in @('','relative.exe','\\server\share\a.exe','Microsoft.PowerShell.Core\FileSystem::C:\a.exe','C:a.exe','C:\a.exe:stream',"C:\a`n.exe",'https://example.com/a.exe')) {
    Assert-Equal (Test-NrMetadataLocalPath $invalid).ok $false ('reject unsafe path ' + $invalid)
}
$none = Get-NrFileMetadata -Paths @()
Assert-Equal ($none -is [hashtable]) $true 'empty result is a hashtable'
Assert-Equal $none.Count 0 'empty path set'
$invalidSet = Get-NrFileMetadata -Paths @('\\server\share\a.exe','\\SERVER\SHARE\A.EXE')
Assert-Equal $invalidSet.Count 1 'deduplicate Windows paths without case'
Assert-Equal $invalidSet['\\server\share\a.exe'].metadataStatus 'NonLocalPathSkipped' 'explicit skipped path result'

$temporary = Join-Path ([IO.Path]::GetTempPath()) ('nr-metadata-test-' + [Guid]::NewGuid().ToString('N'))
[void][IO.Directory]::CreateDirectory($temporary)
$originalValidator = (Get-Item function:Test-NrMetadataLocalPath).ScriptBlock
$originalShellPath = (Get-Item function:Get-NrMetadataPowerShellPath).ScriptBlock
$originalDirectorySecurity = (Get-Item function:New-NrMetadataDirectorySecurity).ScriptBlock
$originalWorker = (Get-Item function:Invoke-NrMetadataWorker).ScriptBlock
$file = Join-Path $temporary 'sample.exe'
try {
    # The production validator is never bypassed through a command-line option.
    function Test-NrMetadataLocalPath {
        param([string]$Path)
        return [pscustomobject]@{ok=$true;path=$Path;status='OK';error=''}
    }
    [IO.File]::WriteAllText($file, 'abc', (New-Object Text.UTF8Encoding($false)))
    $result = Invoke-NrInspectLocalFile -Path $file -SkipSignatures
    Assert-Equal $result.hashStatus 'OK' 'SHA-256 computed'
    Assert-Equal $result.sha256 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad' 'known SHA-256'
    Assert-Equal $result.signatureStatus 'Disabled' 'signature opt out explicit'
    Assert-Equal $result.fileSize 3 'file size recorded'
    Assert-Equal ([string]::IsNullOrEmpty($result.metadataCollectedUtc)) $false 'inspection time recorded'
    $disabled = Invoke-NrInspectLocalFile -Path $file -SkipSignatures -SkipHashes
    Assert-Equal $disabled.hashStatus 'Disabled' 'hash opt out explicit'
    Assert-Equal $disabled.sha256 '' 'disabled hashing has no digest'

    # A mocked signature provider changes the file between hash and final stat.
    function Get-AuthenticodeSignature {
        param([string]$LiteralPath)
        [IO.File]::AppendAllText($LiteralPath, 'changed')
        return [pscustomobject]@{Status='Valid';SignerCertificate=[pscustomobject]@{Subject='CN=Test only'}}
    }
    $changed = Invoke-NrInspectLocalFile -Path $file
    Assert-Equal $changed.metadataStatus 'ChangedDuringInspection' 'changed file detected'
    Assert-Equal $changed.hashStatus 'ChangedDuringInspection' 'changed hash status'
    Assert-Equal $changed.sha256 '' 'changed hash discarded'
    Assert-Equal $changed.signatureStatus 'ChangedDuringInspection' 'changed signature discarded'
    Assert-Equal $changed.signer '' 'changed signer discarded'
    function Get-AuthenticodeSignature {
        param([string]$LiteralPath)
        return [pscustomobject]@{Status='NotSigned';SignerCertificate=$null}
    }
    $unsigned = Invoke-NrInspectLocalFile -Path $file -SkipHashes
    Assert-Equal $unsigned.signatureStatus 'NotSigned' 'unsigned verdict preserved'
    function Get-AuthenticodeSignature {
        param([string]$LiteralPath)
        throw 'Synthetic trust provider failure'
    }
    $partial = Invoke-NrInspectLocalFile -Path $file
    Assert-Equal $partial.signatureStatus 'Error' 'signature failure explicit'
    Assert-Equal $partial.hashStatus 'OK' 'hash preserved despite signature failure'
    Assert-Equal $partial.metadataStatus 'Partial' 'partial metadata explicit'

    $largeFile = Join-Path $temporary 'large.exe'
    $stream = [IO.File]::Create($largeFile)
    try { $stream.SetLength(256MB + 1) } finally { $stream.Dispose() }
    $large = Invoke-NrInspectLocalFile -Path $largeFile -SkipSignatures
    Assert-Equal $large.hashStatus 'LargeFileSkipped' 'large executable hash bounded'
    Assert-Equal $large.sha256 '' 'large file has no digest'

    # Exercise real isolated child startup, safe argument transport and timeout.
    $worker = Join-Path $temporary "worker ' quote & dollar `$ ( ) ;.ps1"
    $request = Join-Path $temporary "request ' & dollar `$ ( ) ;.json"
    $output = Join-Path $temporary 'worker-result.txt'
    [IO.File]::WriteAllText($worker, @'
param([string]$RequestPath)
$ErrorActionPreference='Stop'
$request=[IO.File]::ReadAllText($RequestPath) | ConvertFrom-Json
if ($request.sleep) { Start-Sleep -Seconds 20 }
[IO.File]::WriteAllText([string]$request.output,[string]$request.marker)
'@)
    $requestBody = @{output=$output;marker='literal $() & ; value';sleep=$false} | ConvertTo-Json
    [IO.File]::WriteAllText($request, $requestBody)
    $shell = (Get-Process -Id $PID).Path
    $workerResult = Invoke-NrMetadataWorker -PowerShellPath $shell -WorkerPath $worker -RequestPath $request -TimeoutSeconds 10
    Assert-Equal $workerResult.status 'Exited' 'isolated worker exits'
    Assert-Equal $workerResult.exitCode 0 'isolated worker success'
    Assert-Equal ([IO.File]::ReadAllText($output)) 'literal $() & ; value' 'quoted paths and metacharacters passed as data'
    [IO.File]::Delete($output)
    [IO.File]::WriteAllText($request, (@{output=$output;marker='must not appear';sleep=$true} | ConvertTo-Json))
    $watch = [Diagnostics.Stopwatch]::StartNew()
    $timeout = Invoke-NrMetadataWorker -PowerShellPath $shell -WorkerPath $worker -RequestPath $request -TimeoutSeconds 1
    $watch.Stop()
    Assert-Equal $timeout.status 'Timeout' 'hung worker is stopped'
    Assert-Equal ($watch.Elapsed.TotalSeconds -lt 8) $true 'timeout is bounded'
    Assert-Equal ([IO.File]::Exists($output)) $false 'timed out worker did not finish inspection'

    # Exercise Get-NrFileMetadata's eligible-path path, including its actual
    # Set-Acl invocation. Platform primitives are mocked; orchestration is real.
    $script:aclCalls = 0
    $script:metadataWorkerCalls = 0
    $script:metadataTemporaryPath = ''
    function Get-NrMetadataPowerShellPath { return 'mock-powershell.exe' }
    function New-NrMetadataDirectorySecurity { return [pscustomobject]@{testAcl=$true} }
    function Set-Acl {
        param([string]$LiteralPath, $AclObject, $ErrorAction)
        if (-not [IO.Directory]::Exists($LiteralPath)) { throw 'ACL target does not exist.' }
        if (-not $AclObject.testAcl) { throw 'ACL object was not supplied.' }
        $script:aclCalls++
        $script:metadataTemporaryPath = $LiteralPath
    }
    function Invoke-NrMetadataWorker {
        param([string]$PowerShellPath, [string]$WorkerPath, [string]$RequestPath, [int]$TimeoutSeconds)
        if ($script:aclCalls -ne 1) { throw 'Worker started before ACL protection.' }
        $script:metadataWorkerCalls++
        $request = [IO.File]::ReadAllText($RequestPath) | ConvertFrom-Json
        $result = New-NrMetadataResult -Status 'OK'
        $result.application = 'Mock application'
        [IO.File]::WriteAllText([string]$request.resultPath, ($result | ConvertTo-Json))
        return [pscustomobject]@{status='Exited';exitCode=0}
    }
    $collected = Get-NrFileMetadata -Paths @($file, $file) -SkipHashes -SkipSignatures
    Assert-Equal $script:aclCalls 1 'eligible collector calls Set-Acl'
    Assert-Equal $script:metadataWorkerCalls 1 'eligible collector deduplicates paths'
    Assert-Equal $collected[$file].application 'Mock application' 'eligible collector parses worker result'
    Assert-Equal $collected[$file].metadataStatus 'OK' 'eligible collector returns metadata status'
    Assert-Equal ([IO.Directory]::Exists($script:metadataTemporaryPath)) $false 'eligible collector removes temporary directory'

    # Failing ACL setup must abort inspection rather than use unprotected files.
    function Set-Acl {
        param([string]$LiteralPath, $AclObject, $ErrorAction)
        throw 'Synthetic ACL setup failure'
    }
    $aclFailed = Get-NrFileMetadata -Paths @($file)
    Assert-Equal $aclFailed[$file].metadataStatus 'WorkerError' 'ACL failure is explicit'
    Assert-Equal $script:metadataWorkerCalls 1 'ACL failure prevents worker startup'
} finally {
    Set-Item function:Test-NrMetadataLocalPath $originalValidator
    Set-Item function:Get-NrMetadataPowerShellPath $originalShellPath
    Set-Item function:New-NrMetadataDirectorySecurity $originalDirectorySecurity
    Set-Item function:Invoke-NrMetadataWorker $originalWorker
    Remove-Item function:Set-Acl -ErrorAction SilentlyContinue
    Remove-Item function:Get-AuthenticodeSignature -ErrorAction SilentlyContinue
    if (Test-Path -LiteralPath $temporary) { Remove-Item -LiteralPath $temporary -Recurse -Force }
}
Write-Host ("File metadata: {0} checks passed (portable/mocked trust tests)." -f $script:testCount)
