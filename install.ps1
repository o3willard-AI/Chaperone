# Chaperone Windows installer — PLAN Phase 13 (decision DA: script-first;
# 13c labeled PREVIEW: no service account story without codesigning, so the
# daemon runs as a logon Scheduled Task).
#
# Run from an extracted release archive:
#   powershell -ExecutionPolicy Bypass -File install.ps1
#
# Idempotent. Per-user only. Data files are NEVER touched.

$ErrorActionPreference = "Stop"

Write-Host "== Chaperone installer (Windows) - PREVIEW quality"

$scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$binDir    = Join-Path $env:LOCALAPPDATA "Programs\chaperone"
$configDir = Join-Path $env:USERPROFILE ".config\chaperone"

if (-not (Test-Path (Join-Path $scriptDir "chaperone.exe"))) {
    Write-Error "chaperone.exe not found beside installer"
}

New-Item -ItemType Directory -Force -Path $binDir    | Out-Null
New-Item -ItemType Directory -Force -Path $configDir | Out-Null

Copy-Item (Join-Path $scriptDir "chaperone.exe")        $binDir -Force
Copy-Item (Join-Path $scriptDir "chaperone-helper.exe") $binDir -Force

# User PATH (idempotent)
$userPath = [Environment]::GetEnvironmentVariable("Path", "User")
if ($userPath -notlike "*$binDir*") {
    [Environment]::SetEnvironmentVariable("Path", "$userPath;$binDir", "User")
    Write-Host "added to user PATH: $binDir (new terminals only)"
}

# Logon Scheduled Task instead of a service.
# Passphrase comes from a 0600-equivalent file (see checklist below).
$taskName = "ChaperoneGateway"
$exe = Join-Path $binDir "chaperone.exe"
$args = @(
    "serve",
    "--enrollment",     "$configDir\enrollment.json",
    "--policy",         "$configDir\policy.toml",
    "--store",          "$configDir\vault.bin",
    "--audit-journal",  "$configDir\audit.jsonl",
    "--audit-key",      "$configDir\audit.key",
    "--passphrase-file","$configDir\vault.pass"
)
$action    = New-ScheduledTaskAction -Execute $exe -Argument ($args -join " ")
$trigger   = New-ScheduledTaskTrigger -AtLogOn
$principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive
Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger `
    -Principal $principal -Force | Out-Null
Write-Host "installed logon task: $taskName"

Write-Host @"

== Installed. Next steps:
1. Put your vault passphrase where the service can read it:
     Set-Content -Path "$configDir\vault.pass" -Value "YOUR-PASSPHRASE"
2. Create enrollment/policy/vault (docs/LOCAL-VAULT-GUIDE.md).
3. Start: Start-ScheduledTask -TaskName $taskName
4. Verify: chaperone version

Uninstall: schtasks /Delete /TN $taskName /F; remove $binDir
Data kept: $configDir
"@
