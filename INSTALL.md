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

### Before you run anything: what the warnings mean

If you downloaded the release archive rather than building from source,
Windows will warn you twice before you can run it. Both warnings are
**expected** — they're not a sign anything is wrong, and clicking through
them without checking anything isn't the recommended path either. Here's
what each one says and the one command that actually verifies the file,
no Rust toolchain required.

**1. Your browser, right after the download finishes.** Edge shows:

> **chaperone-vX.Y.Z-x86_64-pc-windows-msvc.zip isn't commonly downloaded.**
> Make sure you trust [site] before you open it.
> `Keep` · `Delete` · `...`

Chrome's wording is similar ("This file isn't commonly downloaded and
could be dangerous"). This is Microsoft SmartScreen / Google Safe Browsing
judging the file by download *popularity*, not by inspecting it — a
brand-new open-source project's first releases will always trigger this,
signed or not.

**2. Windows Defender SmartScreen, the first time `chaperone.exe` or
`chaperone-helper.exe` actually runs** (via `install.ps1`, the Scheduled
Task, or you running one directly):

> **Windows protected your PC**
> Microsoft Defender SmartScreen prevented an unrecognized app from
> starting. Running this app might put your PC at risk.
>
> App: chaperone.exe
> Publisher: Unknown publisher
>
> `Don't run` (default) · `More info` → reveals `Run anyway`

This is the *exact* prompt Chaperone triggers, because it's the exact
prompt every unsigned Windows binary triggers — see [§3 below](#why-unsigned-permanently)
for why that's permanent, not a bug to fix.

### Verify before you click through — no Rust toolchain needed

Every release publishes `SHA256SUMS.txt` next to the archives. This
confirms your specific download matches what the project's CI actually
built, using only PowerShell's built-in `Get-FileHash` — copy-paste this
after downloading both the archive and `SHA256SUMS.txt` into the same
folder:

```powershell
$file = "chaperone-vX.Y.Z-x86_64-pc-windows-msvc.zip"   # match your actual filename
$expected = (Select-String -Path SHA256SUMS.txt -Pattern ([regex]::Escape($file))).Line -replace '\s.*$',''
$actual = (Get-FileHash $file -Algorithm SHA256).Hash
if ($actual -ieq $expected) { "MATCH -- verified, safe to proceed" } else { "MISMATCH -- do not run this file" }
```

If it says `MATCH`, the bytes you have are exactly the bytes CI produced
from this repository's source — the SmartScreen prompts above are about
*popularity*, not integrity, and you've just checked integrity yourself.
If it says `MISMATCH`, stop: re-download, and if it mismatches again,
report it (`SECURITY.md`) rather than running it anyway.

Want the strongest possible check instead of trusting CI? Rebuild from
source and compare — see [RELEASE.md](docs/RELEASE.md). That needs a Rust
toolchain; the hash check above doesn't, which is why it's the path
documented here first.

<a name="why-unsigned-permanently"></a>
### Why unsigned, permanently

Code-signing a Windows binary means buying and holding a Microsoft
Authenticode certificate, which means an entity — a company, a legal
person — owns it. Chaperone is open source maintained by no company; there
is nobody to hold that certificate, and there won't be for this
repository (a downstream corporate fork could add one, but that's a
different trust story than this one). "Unsigned" here means "verifiable
by reconstruction instead of by a signature you have to trust" — see
[RELEASE.md](docs/RELEASE.md) for the full reasoning.

### Install

```powershell
Expand-Archive chaperone-vX.Y.Z-x86_64-pc-windows-msvc.zip
cd chaperone-vX.Y.Z-x86_64-pc-windows-msvc
powershell -ExecutionPolicy Bypass -File install.ps1
```

On a fresh install this generates the D41 config UI token itself, starts
the daemon in setup-only mode, and opens the setup wizard in your browser
— no manual steps needed to reach it. It also registers the gateway to
start at logon: a Scheduled Task if it can (needs one brief, scoped
elevation prompt — nothing else runs elevated, and declining it is fine),
otherwise a Startup-folder shortcut that needs no elevation at all. The
installer's own final output tells you exactly which one it used and how
to start/stop/uninstall it.

Skip the automatic wizard with `$env:CHAPERONE_NO_WIZARD = "1"` before
running the installer if you'd rather walk through
[GETTING-STARTED.md](docs/GETTING-STARTED.md)'s manual CLI path.

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
