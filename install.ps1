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
# agents.json (not enrollment.json) matches GETTING-STARTED.md and the CLI's
# own --help; a prior version of this script pointed at the wrong filename,
# so a Scheduled Task registered by that version would never find the
# enrollment store the wizard/CLI walkthrough actually creates.
$taskName = "ChaperoneGateway"
$exe = Join-Path $binDir "chaperone.exe"
$args = @(
    "serve",
    "--enrollment",     "$configDir\agents.json",
    "--policy",         "$configDir\policy.toml",
    "--store",          "$configDir\vault.bin",
    "--audit-journal",  "$configDir\audit.jsonl",
    "--audit-key",      "$configDir\audit.key",
    "--passphrase-file","$configDir\vault.pass"
)
$action    = New-ScheduledTaskAction -Execute $exe -Argument ($args -join " ")
$trigger   = New-ScheduledTaskTrigger -AtLogOn
$principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive

# Task Scheduler write operations require an elevated token even for a task
# that only affects the calling user's own logon session -- a non-elevated
# process (including one run by an account that IS a local Administrator,
# per Windows' UAC token filtering) gets Access Denied here. Caught
# separately so binaries/PATH still install successfully and the operator
# gets an actionable next step instead of a bare HRESULT crash.
$taskRegistered = $false
try {
    Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger `
        -Principal $principal -Force -ErrorAction Stop | Out-Null
    Write-Host "installed logon task: $taskName"
    $taskRegistered = $true
} catch {
    Write-Warning "could not register the '$taskName' Scheduled Task: $($_.Exception.Message)"
    Write-Warning "this usually means the current PowerShell session is not elevated (Task Scheduler write operations require it, even for a per-user task). Re-run this installer from an elevated PowerShell to install the logon task, or start the gateway directly with 'chaperone serve ...' instead."
}

$nextSteps = @"

== Installed. Next steps:
1. Put your vault passphrase where the service can read it:
     Set-Content -Path "$configDir\vault.pass" -Value "YOUR-PASSPHRASE"
2. Create enrollment/policy/vault (docs/GETTING-STARTED.md).
3. Create the config UI access token (required before 'serve' will start it, D41):
     chaperone ui-token rotate --token "$configDir\ui.token"
"@
if ($taskRegistered) {
    $nextSteps += @"

4. Start: Start-ScheduledTask -TaskName $taskName
5. Verify: chaperone version

Uninstall: schtasks /Delete /TN $taskName /F; remove $binDir
"@
} else {
    $nextSteps += @"

4. No logon task was registered (see warning above). Start the gateway
   directly instead: chaperone serve --enrollment "$configDir\agents.json" ``
     --policy "$configDir\policy.toml" --store "$configDir\vault.bin" ``
     --audit-journal "$configDir\audit.jsonl" --audit-key "$configDir\audit.key" ``
     --passphrase-file "$configDir\vault.pass"
5. Verify: chaperone version

Uninstall: remove $binDir (no task to delete)
"@
}
$nextSteps += @"

Data kept: $configDir
"@
Write-Host $nextSteps
