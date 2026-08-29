# Chaperone Windows installer — PLAN Phase 13 (decision DA: script-first;
# 13c labeled PREVIEW: no service account story without codesigning, so the
# daemon runs as a logon Scheduled Task where possible).
#
# Run from an extracted release archive:
#   powershell -ExecutionPolicy Bypass -File install.ps1
#
# Idempotent. Per-user only — no system-wide changes, no other accounts
# touched, nothing installed to Program Files. Data files are NEVER touched.
#
# Registering the Scheduled Task needs ONE brief, scoped elevation prompt:
# Windows' Task Scheduler API denies write operations to a non-elevated
# token even for a task that only ever runs as YOUR OWN account (a UAC
# token-filtering quirk, not a request for broader access — this installer,
# the daemon, and the browser wizard below all run as your normal user
# throughout; only the single Register-ScheduledTask call is elevated, in a
# separate hidden helper process, and only if the non-elevated attempt
# fails first). Decline the prompt and installation continues without it: a
# Startup-folder shortcut (shell:startup) is registered instead, which needs
# no elevation at all and starts the gateway at your next logon.

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

# --------------------------------------------------------------------------
# Persistence (issue #38): Scheduled Task preferred (survives more restart
# scenarios), Startup-folder shortcut as the no-elevation fallback.
# agents.json (not enrollment.json) matches GETTING-STARTED.md and the CLI's
# own --help; a prior version of this script pointed at the wrong filename,
# so a Scheduled Task registered by that version would never find the
# enrollment store the wizard/CLI walkthrough actually creates.
# --------------------------------------------------------------------------
$taskName = "ChaperoneGateway"
$exe = Join-Path $binDir "chaperone.exe"

# Both Start-Process -ArgumentList (array form) and New-ScheduledTaskAction
# -Argument join their pieces with a bare space and do NOT quote elements
# containing one -- confirmed on hardware: a Windows account whose display
# name contains a space (the common "Full Name" default, e.g.
# "C:\Users\Stephen Blankenship\...") silently breaks --enrollment's value
# into two malformed arguments, and the daemon fails with
# `error: unexpected argument "...`. Every path-shaped value below is
# pre-quoted so this holds regardless of what a real account looks like.
function Quote-Arg {
    param([string]$s)
    if ($s -match '[\s"]') { return '"' + ($s -replace '"', '\"') + '"' }
    return $s
}

$serveArgList = @(
    "serve",
    "--enrollment",     (Quote-Arg "$configDir\agents.json"),
    "--policy",         (Quote-Arg "$configDir\policy.toml"),
    "--store",          (Quote-Arg "$configDir\vault.bin"),
    "--audit-journal",  (Quote-Arg "$configDir\audit.jsonl"),
    "--audit-key",      (Quote-Arg "$configDir\audit.key"),
    "--passphrase-file",(Quote-Arg "$configDir\vault.pass")
)
$serveArgString = ($serveArgList -join " ")

function Try-RegisterScheduledTaskDirect {
    # Attempt without elevation first: a genuinely non-admin standard-user
    # account can sometimes register its own logon task without hitting the
    # UAC token-filtering wall that Administrators-group accounts do.
    try {
        $action    = New-ScheduledTaskAction -Execute $exe -Argument $serveArgString
        $trigger   = New-ScheduledTaskTrigger -AtLogOn
        $principal = New-ScheduledTaskPrincipal -UserId $env:USERNAME -LogonType Interactive
        Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger `
            -Principal $principal -Force -ErrorAction Stop | Out-Null
        return $true
    } catch {
        return $false
    }
}

function Register-ScheduledTaskElevated {
    # Scoped elevation: a short-lived, hidden helper PowerShell process that
    # does NOTHING but call Register-ScheduledTask, so nothing else in this
    # installer (or the wizard/daemon launched later) ever runs elevated.
    $esc = { param($s) $s -replace "'", "''" }
    $tempScript = [System.IO.Path]::GetTempFileName() -replace '\.tmp$', '.ps1'
    $resultFile = [System.IO.Path]::GetTempFileName()
    $body = @"
`$ErrorActionPreference = 'Stop'
try {
    `$action    = New-ScheduledTaskAction -Execute '$(& $esc $exe)' -Argument '$(& $esc $serveArgString)'
    `$trigger   = New-ScheduledTaskTrigger -AtLogOn
    `$principal = New-ScheduledTaskPrincipal -UserId '$(& $esc $env:USERNAME)' -LogonType Interactive
    Register-ScheduledTask -TaskName '$(& $esc $taskName)' -Action `$action -Trigger `$trigger -Principal `$principal -Force | Out-Null
    Set-Content -Path '$(& $esc $resultFile)' -Value 'OK'
} catch {
    Set-Content -Path '$(& $esc $resultFile)' -Value "FAIL: `$(`$_.Exception.Message)"
}
"@
    Set-Content -Path $tempScript -Value $body

    $declined = $false
    $failReason = ""
    try {
        $elevArgs = @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", (Quote-Arg $tempScript)) -join " "
        Start-Process -FilePath "powershell.exe" -ArgumentList $elevArgs `
            -Verb RunAs -Wait -WindowStyle Hidden | Out-Null
    } catch {
        $declined = $true
        $failReason = $_.Exception.Message
    }

    # Get-Content -Raw on a zero-byte file returns $null, not "" -- happens
    # whenever the elevated helper's own script body never actually ran
    # (e.g. Windows silently cancels the elevation request rather than
    # showing/waiting on the UAC consent dialog, observed on this box: the
    # spawned process exits in ~1-2s having done nothing, no exception
    # thrown by Start-Process itself). Must not crash the whole installer.
    $resultRaw = if (Test-Path $resultFile) { Get-Content $resultFile -Raw } else { $null }
    $result = if ($resultRaw) { $resultRaw.Trim() } else { "" }
    Remove-Item $tempScript, $resultFile -ErrorAction SilentlyContinue

    if ($declined) {
        return @{ Success = $false; Reason = "elevation prompt declined or unavailable: $failReason" }
    } elseif ($result -eq "OK") {
        return @{ Success = $true }
    } else {
        return @{ Success = $false; Reason = $(if ($result) { $result } else { "elevated helper produced no result (unexpected)" }) }
    }
}

function Register-StartupShortcut {
    $startupDir = [Environment]::GetFolderPath("Startup")
    $shortcutPath = Join-Path $startupDir "$taskName.lnk"
    try {
        $wsh = New-Object -ComObject WScript.Shell
        $shortcut = $wsh.CreateShortcut($shortcutPath)
        $shortcut.TargetPath = $exe
        $shortcut.Arguments = $serveArgString
        $shortcut.WorkingDirectory = $binDir
        $shortcut.Description = "Chaperone gateway daemon (starts at logon; no elevation required)"
        $shortcut.Save()
        return $true
    } catch {
        Write-Warning "could not create Startup-folder shortcut: $($_.Exception.Message)"
        return $false
    }
}

$persistence = ""
if (Try-RegisterScheduledTaskDirect) {
    $persistence = "task"
    Write-Host "installed logon task: $taskName"
} else {
    Write-Host @"

This installer wants to register a Scheduled Task so the gateway starts
automatically at logon. Doing that needs administrator rights for this one
step only (a Windows quirk: Task Scheduler denies non-elevated writes even
for a task that only runs as you). Nothing else -- not the daemon, not the
wizard below -- runs elevated.

A Windows User Account Control (UAC) prompt is about to appear. Accept it
to register the Scheduled Task, or decline it to use a Startup-folder
shortcut instead (starts the gateway at logon too, just without the extra
restart-policy options a Scheduled Task can offer later).
"@
    $elevated = Register-ScheduledTaskElevated
    if ($elevated.Success) {
        $persistence = "task"
        Write-Host "installed logon task: $taskName (via elevated helper)"
    } else {
        Write-Warning "Scheduled Task not registered: $($elevated.Reason)"
        Write-Host "Falling back to a Startup-folder shortcut (shell:startup) -- no elevation needed."
        if (Register-StartupShortcut) {
            $persistence = "startup"
            Write-Host "installed Startup-folder shortcut: $taskName.lnk"
        } else {
            $persistence = "none"
        }
    }
}

# --------------------------------------------------------------------------
# One-shot setup wizard (issue #40, Windows half — mirrors install.sh).
# If the broker artifacts don't exist yet, drive the first-run flow: generate
# the D41 UI token, start `serve` in setup-only mode (no artifacts = wizard
# only), and open the wizard in the default browser. Skipped with
# CHAPERONE_NO_WIZARD=1 or when a browser can't be launched (headless); the
# manual CLI path in docs/GETTING-STARTED.md remains the documented
# alternative either way.
# --------------------------------------------------------------------------
$wizardSkippedReason = ""
if ($env:CHAPERONE_NO_WIZARD -eq "1") {
    $wizardSkippedReason = "CHAPERONE_NO_WIZARD=1"
} elseif (-not (Test-Path "$configDir\policy.toml") -and -not (Test-Path "$configDir\vault.bin")) {
    Write-Host "`n== Starting the setup wizard (first-run) =="
    & $exe ui-token rotate --token "$configDir\ui.token" | Out-Null
    $tokenLine = & $exe ui-token show --token "$configDir\ui.token" | Select-String "^UI token:\s*(.+)$"
    $uiToken = $tokenLine.Matches[0].Groups[1].Value.Trim()
    $uiPort = if ($env:CHAPERONE_UI_PORT) { $env:CHAPERONE_UI_PORT } else { "8720" }
    $wizardUrl = "http://127.0.0.1:$uiPort/?token=$uiToken"

    Write-Host "`nLaunching setup wizard in your browser (Ctrl-C the daemon window when done):"
    Write-Host "  $wizardUrl`n"

    # serve with no broker artifacts runs SETUP MODE ONLY: wizard on
    # loopback, no passphrase prompt, no gateway pipe. Runs in THIS console
    # (not elevated, not the Scheduled Task/Startup path) so Ctrl-C here
    # stops it cleanly.
    $wizardArgs = @(
        "serve",
        "--enrollment",    (Quote-Arg "$configDir\agents.json"),
        "--policy",        (Quote-Arg "$configDir\policy.toml"),
        "--store",         (Quote-Arg "$configDir\vault.bin"),
        "--audit-journal", (Quote-Arg "$configDir\audit.jsonl"),
        "--audit-key",     (Quote-Arg "$configDir\audit.key"),
        "--ui-port",       $uiPort
    ) -join " "
    $serveProc = Start-Process -FilePath $exe -ArgumentList $wizardArgs -NoNewWindow -PassThru

    Start-Sleep -Seconds 1
    try {
        Start-Process $wizardUrl -ErrorAction Stop | Out-Null
    } catch {
        Write-Warning "could not open a browser automatically; use the URL above."
    }
    Wait-Process -Id $serveProc.Id
} else {
    $wizardSkippedReason = "broker artifacts already exist"
}

if ($wizardSkippedReason) {
    Write-Host "(setup wizard not launched: $wizardSkippedReason)"
}

# --------------------------------------------------------------------------
# Next steps
# --------------------------------------------------------------------------
$nextSteps = "`n== Installed. Next steps:`n"
if ($wizardSkippedReason) {
    $nextSteps += @"
1. Create the per-instance UI access token (D41 requires it; the config UI
   refuses to start without one):
     chaperone ui-token rotate --token "$configDir\ui.token"
2. Put your vault passphrase where the service can read it:
     Set-Content -Path "$configDir\vault.pass" -Value "YOUR-PASSPHRASE"
3. Create enrollment/policy/vault (docs/GETTING-STARTED.md), or run
   `chaperone serve ...` once for the setup wizard.
"@
} else {
    $nextSteps += @"
1. Put your vault passphrase where the service can read it:
     Set-Content -Path "$configDir\vault.pass" -Value "YOUR-PASSPHRASE"
"@
}

switch ($persistence) {
    "task" {
        $nextSteps += @"

4. Start: Start-ScheduledTask -TaskName $taskName
5. Verify: chaperone version

Uninstall: schtasks /Delete /TN $taskName /F; remove $binDir
"@
    }
    "startup" {
        $nextSteps += @"

4. The gateway starts automatically at your next logon (Startup-folder
   shortcut). To start it right now instead of waiting:
     chaperone serve --enrollment "$configDir\agents.json" ``
       --policy "$configDir\policy.toml" --store "$configDir\vault.bin" ``
       --audit-journal "$configDir\audit.jsonl" --audit-key "$configDir\audit.key" ``
       --passphrase-file "$configDir\vault.pass"
5. Verify: chaperone version

Uninstall: remove "$([Environment]::GetFolderPath('Startup'))\$taskName.lnk" and $binDir
"@
    }
    default {
        $nextSteps += @"

4. No automatic persistence was registered. Start the gateway directly:
     chaperone serve --enrollment "$configDir\agents.json" ``
       --policy "$configDir\policy.toml" --store "$configDir\vault.bin" ``
       --audit-journal "$configDir\audit.jsonl" --audit-key "$configDir\audit.key" ``
       --passphrase-file "$configDir\vault.pass"
5. Verify: chaperone version

Uninstall: remove $binDir
"@
    }
}
$nextSteps += "`n`nData kept: $configDir`n"
Write-Host $nextSteps
