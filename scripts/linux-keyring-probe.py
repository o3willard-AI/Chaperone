#!/usr/bin/env python3
"""
linux-keyring-probe.py — characterize the Linux kernel keyring for Chaperone's
headless vault-sealing problem.

QUESTION it answers: when Chaperone seals the vault DEK through the `keyring`
crate's `linux-native` backend (kernel keyring), does that key survive a
daemon restart under systemd (no PAM login session)?

WHY it matters: the session keyring is ephemeral — it lives as long as the
login session that created it. A systemd user service (`chaperoned.service`)
has no PAM login session, so a DEK stored in the session keyring can vanish on
restart, bricking the vault. The persistent (user) keyring survives restarts.

APPROACH: talk to the kernel keyring with the raw add_key()/keyctl() SYSCALLS
via ctypes — no `keyctl` CLI, no libkeyutils, no third-party package (mirrors
Chaperone's no-external-dep posture). glibc does not export these symbols, so
we go straight through syscall(2).

MODES:
  persistent            print (or create) the persistent keyring serial
  write                 add a "user" key to a ring (--ring session|persistent|user|process)
  read                  read a key by description from a ring (exit 0 = found)
  probe                 write to session + persistent, then ask a FRESH
                        `systemd-run --user` service which one it can see
                        (the real "restart" question)
"""
import ctypes
import os
import subprocess
import sys
import argparse

# --- kernel keyring constants (x86_64) ---
SYS_add_key = 248
SYS_keyctl = 250

KEY_SPEC_PROCESS_KEYRING = -2
KEY_SPEC_SESSION_KEYRING = -3
KEY_SPEC_USER_KEYRING = -4

KEYCTL_SEARCH = 10
KEYCTL_READ = 11
KEYCTL_GET_PERSISTENT = 22

_libc = ctypes.CDLL("libc.so.6", use_errno=True)
_libc.syscall.restype = ctypes.c_long


def _sys(nr: int, *args) -> int:
    r = _libc.syscall(nr, *args)
    if r < 0:
        err = ctypes.get_errno()
        return -(err if err else r)  # normalize to a negative errno
    return r


def add_key(desc: str, payload: bytes, ring: int) -> int:
    """Add a 'user' key, return its serial (>=0). Negative = -errno."""
    buf = ctypes.create_string_buffer(payload)
    return _sys(SYS_add_key, b"user", desc.encode(), buf, len(payload), ring)


def keyctl_search(ring: int, desc: str) -> int:
    return _sys(SYS_keyctl, KEYCTL_SEARCH, ring, b"user", desc.encode(), 0)


def keyctl_read(serial: int) -> bytes | None:
    buf = ctypes.create_string_buffer(4096)
    n = _sys(SYS_keyctl, KEYCTL_READ, serial, buf, 4096)
    if n < 0:
        return None
    return buf.raw[:n]


def read_by_desc(ring: int, desc: str) -> bytes | None:
    serial = keyctl_search(ring, desc)
    if serial < 0:
        return None
    return keyctl_read(serial)


def get_persistent() -> int:
    """Return (creating if needed) the persistent keyring serial; negative = -errno."""
    return _sys(SYS_keyctl, KEYCTL_GET_PERSISTENT, os.getuid(), KEY_SPEC_SESSION_KEYRING)


def run_fresh_service(ring_flag: str, desc: str) -> tuple[int, str]:
    """Run `read` in a fresh systemd-run --user service; return (rc, stdout)."""
    probe = subprocess.run(
        ["systemctl", "--user", "is-system-running"], capture_output=True, text=True
    )
    if probe.returncode != 0:
        return -1, "(systemd --user unavailable)"
    cmd = [
        "systemd-run", "--user", "--wait", "--pipe", "--quiet",
        sys.executable, os.path.abspath(__file__),
        "read", "--ring", ring_flag, "--desc", desc,
    ]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=90)
        return p.returncode, p.stdout.strip()
    except (subprocess.TimeoutExpired, OSError) as e:
        return -1, f"({e})"


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("mode", choices=["persistent", "write", "read", "probe"])
    ap.add_argument("--ring", default="session", choices=["session", "persistent", "user", "process"])
    ap.add_argument("--desc", default="chaperone-probe")
    ap.add_argument("--payload", default="chaperone-marker")
    a = ap.parse_args()

    if a.mode == "persistent":
        s = get_persistent()
        if s < 0:
            print(f"persistent keyring UNAVAILABLE: errno {-s}")
            sys.exit(1)
        print(f"persistent keyring serial: {s}")
        return

    ring = {
        "session": KEY_SPEC_SESSION_KEYRING,
        "user": KEY_SPEC_USER_KEYRING,
        "process": KEY_SPEC_PROCESS_KEYRING,
    }.get(a.ring, KEY_SPEC_SESSION_KEYRING)
    if a.ring == "persistent":
        ring = get_persistent()
        if ring < 0:
            print(f"persistent keyring UNAVAILABLE: errno {-ring}")
            sys.exit(1)

    if a.mode == "write":
        s = add_key(a.desc, a.payload.encode(), ring)
        if s < 0:
            print(f"write FAILED: errno {-s}")
            sys.exit(1)
        print(f"wrote '{a.desc}' -> serial {s} (ring={a.ring}/{ring})")
        return

    if a.mode == "read":
        v = read_by_desc(ring, a.desc)
        print(f"ring={a.ring} desc='{a.desc}' -> {v!r}")
        sys.exit(0 if v is not None else 1)

    # --- probe ---
    persist = get_persistent()
    if persist < 0:
        print(f"persistent keyring UNAVAILABLE: errno {-persist}")
    else:
        print(f"persistent keyring: serial {persist}")
    try:
        with open("/proc/sys/kernel/keys/persistent_keyring_expiry") as f:
            exp = f.read().strip()
            print(f"persistent_keyring_expiry: {exp}s (default 259200 = 3 days)")
    except OSError:
        print("persistent_keyring_expiry: (not readable)")

    add_key("probe-session", b"session-marker", KEY_SPEC_SESSION_KEYRING)
    if persist >= 0:
        add_key("probe-persistent", b"persistent-marker", persist)

    same_session = read_by_desc(KEY_SPEC_SESSION_KEYRING, "probe-session") is not None
    same_persist = (read_by_desc(persist, "probe-persistent") is not None) if persist >= 0 else None

    rc_sess, out_sess = run_fresh_service("session", "probe-session")
    rc_pers, out_pers = (run_fresh_service("persistent", "probe-persistent") if persist >= 0
                         else (-1, "(no persistent ring)"))

    print("\n=== probe results ===")
    print(f"session keyring    : in-process read ok={same_session}")
    print(f"persistent keyring : in-process read ok={same_persist}")
    print(f"fresh service / session keyring    : rc={rc_sess} out={out_sess!r}")
    print(f"fresh service / persistent keyring : rc={rc_pers} out={out_pers!r}")

    print("\n=== conclusion ===")
    fresh_session = rc_sess == 0
    fresh_persist = rc_pers == 0
    if (not fresh_session) and fresh_persist:
        print("SESSION keyring does NOT survive a fresh service; PERSISTENT does.")
        print("=> the linux-native backend must target the persistent (user) keyring")
        print("   for vault sealing to survive a daemon restart on headless Linux.")
    elif fresh_session:
        print("The session keyring IS visible to a fresh service here — check")
        print("KeyringMode= / pam_keyinit config on the systemd user manager.")
    else:
        print("Inconclusive (systemd-run unavailable, or both rings invisible to a fresh service).")

    print("\nNOTE: regardless of session-vs-persistent visibility, a REBOOT clears ALL")
    print("kernel keyrings (session AND persistent). The persistent keyring also")
    print("expires (see persistent_keyring_expiry above) unless Entry::new() is")
    print("called periodically to reset the timer. A passphrase fallback is required.")


if __name__ == "__main__":
    main()
