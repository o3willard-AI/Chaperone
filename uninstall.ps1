# Chaperone Windows uninstaller — removes binaries + whichever persistence
# mechanism install.ps1 registered (Scheduled Task, or the Startup-folder
# shortcut fallback used when Task Scheduler elevation wasn't available).
# NEVER touches data: %USERPROFILE%\.config\chaperone is preserved.

$ErrorActionPreference = "Continue"
$taskName = "ChaperoneGateway"

# Deleting a Scheduled Task hits the same UAC token-filtering wall
# registering one does (install.ps1, issue #38) -- a non-elevated `schtasks
# /Delete` silently fails (the old `2>$null` here masked that: it looked
# like it worked, but Get-ScheduledTask afterward still showed the task).
# Try unelevated first (works for genuinely non-admin accounts), then a
# scoped elevated helper -- nothing else in this script runs elevated.
if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
    schtasks /Delete /TN $taskName /F 2>$null | Out-Null
    if (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue) {
        $tempScript = [System.IO.Path]::GetTempFileName() -replace '\.tmp$', '.ps1'
        $esc = { param($s) $s -replace "'", "''" }
        @"
schtasks /Delete /TN '$(& $esc $taskName)' /F 2>`$null | Out-Null
"@ | Set-Content -Path $tempScript
        try {
            # -File's value must be quoted: $tempScript lives under %TEMP%,
            # which (like any path derived from a Windows account's display
            # name) may contain a space -- Start-Process joins ArgumentList
            # array elements with a bare, unquoted space (install.ps1,
            # issue #38's Quote-Arg comment has the full story).
            $quotedTempScript = if ($tempScript -match '[\s"]') { '"' + ($tempScript -replace '"', '\"') + '"' } else { $tempScript }
            $delArgs = @("-NoProfile", "-ExecutionPolicy", "Bypass", "-File", $quotedTempScript) -join " "
            Start-Process -FilePath "powershell.exe" -ArgumentList $delArgs -Verb RunAs -Wait -WindowStyle Hidden | Out-Null
        } catch {
            Write-Warning "could not remove Scheduled Task '$taskName' (elevation declined or unavailable): $($_.Exception.Message)"
        }
        Remove-Item $tempScript -ErrorAction SilentlyContinue
    }
    if (-not (Get-ScheduledTask -TaskName $taskName -ErrorAction SilentlyContinue)) {
        Write-Host "removed Scheduled Task: $taskName"
    } else {
        Write-Warning "Scheduled Task '$taskName' still exists; remove manually: schtasks /Delete /TN $taskName /F (from an elevated prompt)"
    }
}

$shortcutPath = Join-Path ([Environment]::GetFolderPath("Startup")) "$taskName.lnk"
if (Test-Path $shortcutPath) {
    Remove-Item -Force $shortcutPath
    Write-Host "removed Startup-folder shortcut: $shortcutPath"
}

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
