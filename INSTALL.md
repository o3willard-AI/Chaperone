# Installing Chaperone

Per-user install from release archives. **No root/admin required for the
base install**. Binaries are unsigned by design — verify by rebuilding from
source or checking the hash manifest ([RELEASE.md](RELEASE.md)). Download the
latest release archive from the
[GitHub releases page](https://github.com/o3willard-AI/Chaperone/releases).

Artifacts: `chaperone` (CLI + gateway daemon), `chaperone-helper` (isolated
privileged-command helper), install scripts, service templates.

## Linux

```sh
tar xzf chaperone-vX.Y.Z-x86_64-unknown-linux-gnu.tar.gz
cd chaperone-vX.Y.Z-x86_64-unknown-linux-gnu
./install.sh
```

What it does: binaries → `~/.local/bin` · systemd **user** unit installed
(`chaperoned.service`) · config skeleton at `~/.config/chaperone` · prints a
post-install checklist including the optional sudoers line.

Manage the service:

```sh
chaperone ui-token rotate --token ~/.config/chaperone/ui.token   # D41: config UI needs this
systemctl --user enable --now chaperoned   # start + enable at login
systemctl --user status chaperoned
journalctl --user -u chaperoned -f
systemctl --user disable --now chaperoned  # stop
```

### Optional: privileged local commands (sudoers)

The daemon runs unprivileged. To let agents run pinned commands as root:

```sh
sudo cp packaging/sudoers.chaperone-helper.example /etc/sudoers.d/chaperone-helper
sudo mkdir -p /etc/chaperone && sudo install -m 0444 -o root \
  packaging/helper-allow.toml.example /etc/chaperone/helper-allow.toml
sudo visudo -c   # validate!
```

Edit BOTH files to your reality first. The allowlist must stay ROOT-OWNED:
the helper refuses user-owned allowlists when elevated, because editing your
own list would otherwise become arbitrary-root-exec. Then point the daemon's
`helper_argv` (serve config) at `sudo -n /usr/local/bin/chaperone-helper`.

## macOS

```sh
tar xzf chaperone-vX.Y.Z-aarch64-apple-darwin.tar.gz
cd chaperone-vX.Y.Z-aarch64-apple-darwin
./install.sh
chaperone ui-token rotate --token ~/.config/chaperone/ui.token   # D41: config UI needs this
launchctl load ~/Library/LaunchAgents/ai.chaperone.gw.plist   # start
launchctl list | grep chaperone                               # verify
launchctl unload ~/Library/LaunchAgents/ai.chaperone.gw.plist # stop
```

Privileged commands: same sudoers approach as Linux above.

### Gatekeeper (unsigned binaries)

`chaperone` and `chaperone-helper` ship with **no Apple Developer ID
signature or notarization** (deliberate — see [RELEASE.md](RELEASE.md)).
If the archive you downloaded carries the `com.apple.quarantine` flag
(normal after downloading via a browser), macOS's Gatekeeper reacts
differently depending on *how* you run the binary — confirmed by testing
each path directly (2026-08-28/29 QA pass):

| How you run it | What happens |
|---|---|
| Double-click in Finder, or `open ./chaperone` | **Blocked.** Finder/LaunchServices refuses to launch it and shows "chaperone" cannot be opened because Apple cannot check it for malicious software" (or, on older macOS, "...from an unidentified developer"). |
| `spctl -a -vv --type execute chaperone` | Reports `rejected` — this is Gatekeeper's own policy check, and it's telling the truth: an unsigned binary fails it by design. |
| **Running it from Terminal** (`./chaperone --version`, or anything install.sh/the launchd plist does) | **Not blocked.** Gatekeeper's quarantine enforcement is specific to Finder/LaunchServices-mediated launches; a shell directly exec'ing a quarantined command-line binary is not intercepted the same way. |

In practice this means **normal `chaperone` usage — running `./install.sh`,
invoking `chaperone` from Terminal, or letting `launchctl load` start the
background service — is not blocked at all.** You will only see a
Gatekeeper prompt if you double-click the binary in Finder out of
curiosity. If you do hit it, either of these resolves it permanently for
that file:

**Option A — System Settings (no Terminal needed):**
1. Try to open it once (you'll see the blocked dialog above; click OK/Done).
2. **System Settings → Privacy & Security**, scroll to the Security section.
   You'll see a line naming `chaperone` was blocked, with an
   **"Open Anyway"** button — click it, then confirm once more in the
   dialog that follows (may ask for your password/Touch ID).

**Option B — Terminal, before you ever try to open it:**
```sh
xattr -dr com.apple.quarantine chaperone chaperone-helper
```
Removes the quarantine flag from both binaries recursively (`-r` matters
if you point it at the extracted archive directory instead of individual
files). Safe to run unconditionally as part of your own install process —
it does not touch, weaken, or bypass any signature verification, because
there is no signature to bypass; it only clears the "this came from the
internet" flag that triggers the Finder-path prompt above.

This is **not** the same as trusting the binary — it only lets it run.
Actual trust, per this project's model, comes from verifying it against
the hash manifest or rebuilding it yourself; see
[RELEASE.md](RELEASE.md#the-verification-model-no-signing-prove-it-yourself).

## Windows (preview quality)

```powershell
Expand-Archive chaperone-vX.Y.Z-x86_64-pc-windows-msvc.zip
cd chaperone-vX.Y.Z-x86_64-pc-windows-msvc
powershell -ExecutionPolicy Bypass -File install.ps1
chaperone ui-token rotate --token "~/.config/chaperone/ui.token"   # D41: config UI needs this
Start-ScheduledTask -TaskName ChaperoneGateway     # start
Get-ScheduledTask ChaperoneGateway                 # verify
schtasks /End /TN ChaperoneGateway                 # stop
```

SmartScreen may prompt (binaries are unsigned by design); verify the hash manifest or rebuild from source. The daemon runs as a logon
Scheduled Task (no service account without codesigning — preview tradeoff).
Privilege elevation on Windows is not yet packaged.

## Vault passphrase for services

The daemon unlocks your vault at startup. Headless services read it from a
file you protect:

```sh
umask 077
printf 'your-passphrase\n' > ~/.config/chaperone/vault.pass
```

(Windows: `Set-Content $HOME\.config\chaperone\vault.pass "your-passphrase"`.)
Tradeoff documented: file-on-disk beats command-line/history leakage, but is
still plaintext at rest — protect it like the vault itself.

## Upgrades

1. Stop the service.
2. Extract the new archive; re-run `./install.sh` (binaries and units are
   replaced; **data in `~/.config/chaperone` is never touched**).
3. Start the service; `chaperone version` to confirm.

Data formats are versioned; format migrations are explicit releases notes
items, never silent.

## Uninstall

```sh
./uninstall.sh        # or uninstall.ps1 on Windows
```

Stops/removes services and binaries. Your data directory
(`~/.config/chaperone`) is preserved — delete it manually only when certain;
it contains your vault (unrecoverable passphrase protection applies) and the
audit chain (your evidence).
