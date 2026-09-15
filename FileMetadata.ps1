# Windows PowerShell 5.1. File inspection runs AFTER the network capture.
# No inspected program is started. Signatures describe a file, not its behavior.
$script:NrMetadataModulePath = $PSCommandPath

function New-NrMetadataResult {
    param([string]$Status = 'NotChecked', [string]$ErrorText = '')
    return [pscustomobject][ordered]@{
        application = ''; company = ''; fileVersion = ''
        signatureStatus = $Status; signer = ''; sha256 = ''; hashStatus = $Status
        metadataStatus = $Status; metadataCollectedUtc = [datetime]::UtcNow.ToString('o')
        fileSize = $null; lastWriteUtc = ''; error = $ErrorText
    }
}

function Test-NrMetadataLocalPath {
    param([AllowEmptyString()][string]$Path)
    # Reject UNC, device/provider paths, relative paths, alternate streams and controls.
    if ([string]::IsNullOrWhiteSpace($Path) -or $Path -notmatch '^[A-Za-z]:\\' -or
        $Path.Substring(2).Contains(':') -or $Path -match '[\x00-\x1f]') {
        return [pscustomobject]@{ok=$false;path='';status='NonLocalPathSkipped';error='Only an absolute path on a fixed local Windows drive can be inspected.'}
    }
    if ([Environment]::OSVersion.Platform -ne [PlatformID]::Win32NT) {
        return [pscustomobject]@{ok=$false;path='';status='UnsupportedPlatform';error='File inspection requires Windows.'}
    }
    try {
        if (-not ('NrMetadata.Native' -as [type])) {
            Add-Type -TypeDefinition @'
using System.Runtime.InteropServices;
namespace NrMetadata {
    public static class Native {
        [DllImport("kernel32.dll", CharSet=CharSet.Unicode)]
        public static extern uint GetDriveType(string rootPathName);
    }
}
'@ -ErrorAction Stop
        }
        $fullPath = [IO.Path]::GetFullPath($Path)
        $root = [IO.Path]::GetPathRoot($fullPath)
        if ([NrMetadata.Native]::GetDriveType($root) -ne 3) {
            return [pscustomobject]@{ok=$false;path='';status='NonLocalDriveSkipped';error='Network, removable and non-fixed drives are not inspected.'}
        }
        # A local drive may contain a junction or symlink into a network share.
        # Walk from its root and stop BEFORE following any reparse component.
        $current = $root
        foreach ($component in @($fullPath.Substring($root.Length).Split('\'))) {
            if (-not $component) { continue }
            $current = [IO.Path]::Combine($current, $component)
            $attributes = [IO.File]::GetAttributes($current)
            if (($attributes -band [IO.FileAttributes]::ReparsePoint) -ne 0) {
                return [pscustomobject]@{ok=$false;path='';status='ReparsePointSkipped';error='A symbolic link, junction or other reparse point was not followed.'}
            }
        }
        if (-not [IO.File]::Exists($fullPath)) {
            return [pscustomobject]@{ok=$false;path='';status='FileUnavailable';error='The executable file is missing or inaccessible.'}
        }
        return [pscustomobject]@{ok=$true;path=$fullPath;status='OK';error=''}
    } catch {
        return [pscustomobject]@{ok=$false;path='';status='FileUnavailable';error=$_.Exception.Message}
    }
}

function Invoke-NrInspectLocalFile {
    param([string]$Path, [switch]$SkipSignatures, [switch]$SkipHashes)
    $check = Test-NrMetadataLocalPath -Path $Path
    if (-not $check.ok) { return (New-NrMetadataResult -Status $check.status -ErrorText $check.error) }
    $result = New-NrMetadataResult
    $errors = New-Object 'System.Collections.Generic.List[string]'
    try {
        $before = New-Object IO.FileInfo($check.path)
        $beforeLength = $before.Length
        $beforeWrite = $before.LastWriteTimeUtc.Ticks
        $result.fileSize = $beforeLength
        $result.lastWriteUtc = $before.LastWriteTimeUtc.ToString('o')
        try {
            $version = [Diagnostics.FileVersionInfo]::GetVersionInfo($check.path)
            $result.application = [string]$version.ProductName
            if (-not $result.application) { $result.application = [string]$version.FileDescription }
            $result.company = [string]$version.CompanyName
            $result.fileVersion = [string]$version.FileVersion
        } catch { $errors.Add('Version information: ' + $_.Exception.Message) }
        if ($SkipHashes) { $result.hashStatus = 'Disabled' }
        elseif ($beforeLength -gt 256MB) {
            $result.hashStatus = 'LargeFileSkipped'
        } else {
            $stream = $null; $hasher = $null
            try {
                # Sharing Read denies concurrent writes/deletes while the hash is computed.
                $stream = [IO.File]::Open($check.path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read)
                $hasher = [Security.Cryptography.SHA256]::Create()
                $result.sha256 = [BitConverter]::ToString($hasher.ComputeHash($stream)).Replace('-', '').ToLowerInvariant()
                $result.hashStatus = 'OK'
            } catch {
                $result.hashStatus = 'Error'; $errors.Add('SHA-256: ' + $_.Exception.Message)
            } finally {
                if ($stream) { $stream.Dispose() }
                if ($hasher) { $hasher.Dispose() }
            }
        }
        if ($SkipSignatures) { $result.signatureStatus = 'Disabled' }
        else {
            try {
                $signature = Get-AuthenticodeSignature -LiteralPath $check.path -ErrorAction Stop
                $result.signatureStatus = [string]$signature.Status
                if ($signature.SignerCertificate) { $result.signer = [string]$signature.SignerCertificate.Subject }
            } catch {
                $result.signatureStatus = 'Error'; $errors.Add('Authenticode: ' + $_.Exception.Message)
            }
        }
        $after = New-Object IO.FileInfo($check.path)
        if (-not $after.Exists -or $after.Length -ne $beforeLength -or $after.LastWriteTimeUtc.Ticks -ne $beforeWrite) {
            # Do not present values taken from different file revisions as verified together.
            $result.metadataStatus = 'ChangedDuringInspection'
            $result.sha256 = ''; $result.hashStatus = 'ChangedDuringInspection'
            $result.signer = ''; $result.signatureStatus = 'ChangedDuringInspection'
            $errors.Add('The executable changed during inspection; signature and hash results were discarded.')
        } elseif ($errors.Count -gt 0) { $result.metadataStatus = 'Partial' }
        else { $result.metadataStatus = 'OK' }
    } catch {
        $result.metadataStatus = 'FileUnavailable'; $errors.Add($_.Exception.Message)
    }
    $result.metadataCollectedUtc = [datetime]::UtcNow.ToString('o')
    $result.error = $errors -join ' | '
    return $result
}

function ConvertTo-NrMetadataEncodedCommand {
    param([string]$WorkerPath, [string]$RequestPath)
    # Both paths are data, encoded before use; neither is interpreted as shell code.
    $worker64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($WorkerPath))
    $request64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($RequestPath))
    $command = '$ErrorActionPreference="Stop";$w=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String("' + $worker64 + '"));$r=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String("' + $request64 + '"));& $w -RequestPath $r'
    return [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command))
}

function Invoke-NrMetadataWorker {
    param([string]$PowerShellPath, [string]$WorkerPath, [string]$RequestPath, [int]$TimeoutSeconds)
    $start = New-Object Diagnostics.ProcessStartInfo
    $start.FileName = $PowerShellPath
    $start.Arguments = '-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand ' + (ConvertTo-NrMetadataEncodedCommand $WorkerPath $RequestPath)
    $start.UseShellExecute = $false
    $start.CreateNoWindow = $true
    # No redirected pipes to fill/deadlock. The worker writes its result to a file.
    $process = New-Object Diagnostics.Process
    $process.StartInfo = $start
    try {
        if (-not $process.Start()) { throw 'Could not start the file inspection worker.' }
        if (-not $process.WaitForExit($TimeoutSeconds * 1000)) {
            try { $process.Kill(); [void]$process.WaitForExit(3000) } catch { }
            return [pscustomobject]@{status='Timeout';exitCode=$null}
        }
        return [pscustomobject]@{status='Exited';exitCode=$process.ExitCode}
    } finally {
        # Also stop this exact worker if the surrounding operation is interrupted.
        try { if (-not $process.HasExited) { $process.Kill() } } catch { }
        $process.Dispose()
    }
}

function Get-NrMetadataPowerShellPath {
    return (Join-Path ([Environment]::SystemDirectory) 'WindowsPowerShell\v1.0\powershell.exe')
}

function New-NrMetadataDirectorySecurity {
    $acl = New-Object Security.AccessControl.DirectorySecurity
    $acl.SetAccessRuleProtection($true, $false)
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent().User
    foreach ($sid in @($identity, (New-Object Security.Principal.SecurityIdentifier('S-1-5-18')))) {
        $rule = New-Object Security.AccessControl.FileSystemAccessRule($sid, 'FullControl', 'ContainerInherit, ObjectInherit', 'None', 'Allow')
        [void]$acl.AddAccessRule($rule)
    }
    return $acl
}

function Get-NrFileMetadata {
    [CmdletBinding()]
    param(
        [AllowEmptyCollection()][string[]]$Paths = @(),
        [switch]$SkipSignatures,
        [switch]$SkipHashes,
        [ValidateRange(1,120)][int]$TimeoutSeconds = 15
    )
    $results = @{}
    $eligible = @{}
    foreach ($path in $Paths) {
        if ([string]::IsNullOrWhiteSpace($path) -or $results.ContainsKey($path)) { continue }
        $check = Test-NrMetadataLocalPath -Path $path
        if (-not $check.ok) { $results[$path] = New-NrMetadataResult -Status $check.status -ErrorText $check.error }
        else { $results[$path] = $null; $eligible[$path] = $check.path }
    }
    if ($eligible.Count -eq 0) { return $results }
    $workerPath = Join-Path (Split-Path $script:NrMetadataModulePath -Parent) 'Inspect-Executable.ps1'
    $powerShellPath = Get-NrMetadataPowerShellPath
    $temporary = Join-Path ([IO.Path]::GetTempPath()) ('NetworkAnalyzer-FileMetadata-' + [Guid]::NewGuid().ToString('N'))
    try {
        [void][IO.Directory]::CreateDirectory($temporary)
        # Protect JSON requests/results from other users while running elevated.
        $acl = New-NrMetadataDirectorySecurity
        Set-Acl -LiteralPath $temporary -AclObject $acl -ErrorAction Stop
        $index = 0
        foreach ($path in @($eligible.Keys | Sort-Object)) {
            $index++
            Write-Progress -Id 31 -Activity 'Inspecting executable files' -Status ("{0} of {1}: {2}" -f $index, $eligible.Count, [IO.Path]::GetFileName($path)) -PercentComplete ([int](100 * $index / $eligible.Count))
            $requestPath = Join-Path $temporary ('request-' + $index + '.json')
            $resultPath = Join-Path $temporary ('result-' + $index + '.json')
            $request = @{path=$eligible[$path];skipSignatures=[bool]$SkipSignatures;skipHashes=[bool]$SkipHashes;resultPath=$resultPath}
            [IO.File]::WriteAllText($requestPath, ($request | ConvertTo-Json -Compress), (New-Object Text.UTF8Encoding($false)))
            try {
                $worker = Invoke-NrMetadataWorker -PowerShellPath $powerShellPath -WorkerPath $workerPath -RequestPath $requestPath -TimeoutSeconds $TimeoutSeconds
                if ($worker.status -eq 'Timeout') {
                    $results[$path] = New-NrMetadataResult -Status 'Timeout' -ErrorText ("Inspection exceeded {0} seconds; only its own worker was stopped." -f $TimeoutSeconds)
                } elseif ([IO.File]::Exists($resultPath)) {
                    $resultInfo = New-Object IO.FileInfo($resultPath)
                    if ($resultInfo.Length -gt 1048576) { throw 'Unexpectedly large file inspection result.' }
                    $result = [IO.File]::ReadAllText($resultPath) | ConvertFrom-Json
                    foreach ($required in @('application','company','fileVersion','signatureStatus','signer','sha256','hashStatus','metadataStatus','metadataCollectedUtc','error')) {
                        if (-not $result.PSObject.Properties[$required]) { throw ('File inspection result is missing ' + $required) }
                    }
                    $results[$path] = $result
                } else { throw ('The file inspection worker returned no result (exit code ' + $worker.exitCode + ').') }
            } catch { $results[$path] = New-NrMetadataResult -Status 'WorkerError' -ErrorText $_.Exception.Message }
        }
    } catch {
        foreach ($path in $eligible.Keys) {
            if ($null -eq $results[$path]) { $results[$path] = New-NrMetadataResult -Status 'WorkerError' -ErrorText $_.Exception.Message }
        }
    } finally {
        Write-Progress -Id 31 -Activity 'Inspecting executable files' -Completed
        if ([IO.Directory]::Exists($temporary)) { Remove-Item -LiteralPath $temporary -Recurse -Force -ErrorAction SilentlyContinue }
    }
    return $results
}
