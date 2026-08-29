#!/usr/bin/env python3
"""Rewrite a macOS Mach-O executable's LC_UUID to a deterministic value
derived from its own content, then re-sign it ad-hoc.

WHY THIS EXISTS

ld64 embeds a Mach-O LC_UUID load command at link time that is NOT a
function of the linked content -- confirmed empirically (macOS QA pass,
2026-08-28) by cmp'ing two builds of the identical source from two
different checkout paths, with scripts/repro-env.sh's --remap-path-prefix
fix already applied: every byte matched except the 16-byte LC_UUID and
the 32 bytes of ad-hoc code-signature hash that cascade from it (the
signature covers the UUID load command). That's 48 bytes total out of a
~6.6MB binary -- nothing else differs. This is a distinct bug from the
CARGO_HOME/checkout path-embedding issue that --remap-path-prefix fixes,
and a distinct mechanism from Windows' MSVC TimeDateStamp problem that
-Brepro fixes (see .cargo/config.toml) -- this is macOS/ld64-specific.

A tempting "fix" is `-C link-arg=-Wl,-no_uuid`, which suppresses the load
command entirely and does make two-path builds hash-identical. DO NOT USE
IT: dyld hard-requires LC_UUID to launch a Mach-O executable at all --
`dyld: missing LC_UUID load command` -- so a binary built that way cannot
run. (Confirmed the hard way: it briefly broke a real installed
`chaperone` binary during install.sh testing before this fix existed.)

THE FIX

Make the UUID a pure function of the binary's own content instead of
removing it -- mirroring what -Brepro does for MSVC's TimeDateStamp on
Windows: two builds with byte-identical code now embed the identical
UUID, because the UUID is *derived from* that code (with the UUID field
itself zeroed before hashing, so the computation doesn't depend on
whatever value happened to be there before).

ORDER OF OPERATIONS (load-bearing -- see rewrite() below)

  1. cargo build produces a linked, ad-hoc-signed binary with a
     non-deterministic LC_UUID.
  2. This script strips that signature first (`codesign --remove-signature`).
     This step is NOT optional: an ad-hoc signature's CMS blob and code
     directory hashes are themselves computed over content that includes
     the old random UUID, and unlike the UUID field they are not fixed
     size / fixed offset, so simply zeroing the 16 UUID bytes and hashing
     leaves signature-derived bytes elsewhere in the file still carrying
     traces of the old random value -- confirmed empirically: without
     this step, two builds from different checkout paths still produced
     two DIFFERENT "deterministic" UUIDs, because each one's hash input
     silently included its own build's stale signature bytes. Stripping
     the signature first was verified (cmp -l) to leave the two builds
     identical in every byte except the UUID field itself, before any
     new UUID is even computed.
  3. This script locates LC_UUID in the now-unsigned file, hashes the
     file with that field zeroed, and overwrites the field with the
     first 16 bytes of that hash.
  4. This script then re-signs (`codesign --force -s -`) AFTER the byte
     rewrite, not before: signing covers the UUID bytes, so it must be
     the last step, over the final content, or the signature will not
     match what's actually in the file (fails `codesign -v`) -- the OS
     may refuse to execute it.

Only 64-bit thin (single-architecture) Mach-O executables are supported;
fat/universal binaries are not something this project produces.
"""
import hashlib
import struct
import subprocess
import sys

MH_MAGIC_64 = 0xFEEDFACF
LC_UUID = 0x1B


def find_uuid_offset(data: bytes) -> int:
    if len(data) < 32:
        raise ValueError("file too small to be a Mach-O binary")
    magic, = struct.unpack_from("<I", data, 0)
    if magic != MH_MAGIC_64:
        raise ValueError(
            f"not a 64-bit thin Mach-O (magic={magic:#x}); "
            "fat/universal binaries are not supported"
        )
    ncmds, sizeofcmds = struct.unpack_from("<II", data, 16)
    off = 32  # sizeof(mach_header_64)
    end = off + sizeofcmds
    if end > len(data):
        raise ValueError("load command table extends past end of file")
    for _ in range(ncmds):
        if off + 8 > end:
            raise ValueError("load command table overrun")
        cmd, cmdsize = struct.unpack_from("<II", data, off)
        if cmd == LC_UUID:
            if cmdsize != 24:
                raise ValueError(f"unexpected LC_UUID cmdsize {cmdsize} (expected 24)")
            return off + 8  # the 16-byte uuid follows the 8-byte cmd/cmdsize header
        off += cmdsize
    raise ValueError("no LC_UUID load command found")


def rewrite(path: str) -> None:
    # Strip any existing signature FIRST (see ORDER OF OPERATIONS above) --
    # its bytes otherwise leak the old random UUID into the hash below.
    # Exit code 1 with "not signed" on stderr is fine (nothing to strip);
    # anything else is a real failure.
    strip = subprocess.run(
        ["codesign", "--remove-signature", path],
        capture_output=True, text=True,
    )
    if strip.returncode != 0 and "not signed" not in strip.stderr:
        raise RuntimeError(f"codesign --remove-signature failed: {strip.stderr.strip()}")

    with open(path, "rb") as f:
        data = bytearray(f.read())

    uuid_off = find_uuid_offset(bytes(data))

    # Hash with the UUID field zeroed: the new UUID must be a function of
    # everything EXCEPT the previous (non-deterministic) UUID value, or
    # this would just launder the same nondeterminism through a hash.
    zeroed = bytearray(data)
    zeroed[uuid_off:uuid_off + 16] = b"\x00" * 16
    digest = hashlib.sha256(bytes(zeroed)).digest()
    data[uuid_off:uuid_off + 16] = digest[:16]

    with open(path, "wb") as f:
        f.write(bytes(data))

    # Re-sign LAST: must happen after the byte rewrite above, never
    # before (see ORDER OF OPERATIONS in the module docstring).
    subprocess.run(["codesign", "--force", "-s", "-", path], check=True)


def main(argv: list[str]) -> int:
    if len(argv) < 2:
        print(f"usage: {argv[0]} <macho-binary> [<macho-binary> ...]", file=sys.stderr)
        return 2
    for path in argv[1:]:
        rewrite(path)
        print(f"[macho-deterministic-uuid] rewrote {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
