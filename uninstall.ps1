# Chaperone Windows uninstaller — removes binaries + logon task.
# NEVER touches data: %USERPROFILE%\.config\chaperone is preserved.

$ErrorActionPreference = "Continue"
$taskName = "ChaperoneGateway"
schtasks /Delete /TN $taskName /F 2>$null | Out-Null

$binDir = Join-Path $env:LOCALAPPDATA "Programs\chaperone"
if (Test-Path $binDir) {
    Remove-Item -Recurse -Force $binDir
    Write-Host "removed $binDir"
}

$userPath = [Environment]::GetEnvironmentVariable("Path", "User")
if ($userPath -like "*$binDir*") {
    $newPath = ($userPath -split ';' | Where-Object { $_ -ne $binDir }) -join ';'
    [Environment]::SetEnvironmentVariable("Path", $newPath, "User")
}

Write-Host "KEPT: $env:USERPROFILE\.config\chaperone (vault, audit journal, enrollment, keys)"
Write-Host "delete manually ONLY if you are certain:"
Write-Host "  Remove-Item -Recurse -Force $env:USERPROFILE\.config\chaperone"
