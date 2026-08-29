#!/usr/bin/env python3
"""Chaperone sanctioned test agent (docs/skill/test-agent.py).

Zero-dependency proof that your install enrolls and authenticates an agent
end-to-end. You need only the release archive (the `chaperone` binary on
PATH) and python3 — no Rust toolchain, no pip packages.

What it wraps (the exact CLI commands, in order):
  1. chaperone enroll --store <ENROLL-STORE> --agent-id <ID> --public-key <B64URL>
     (enrolls the throwaway keypair this script generates in-memory; the
     private key never touches disk — like a real agent's key store)
  2. ONE signed intent over the local channel to a RUNNING `chaperone serve`
     (start it per docs/GETTING-STARTED.md; a Unix socket by default, or
     pass --port for a --tcp-port gateway)

It prints PASS if the gateway's decision matches --expect (default: allow),
FAIL otherwise, with the gateway's exact response. A signature the gateway
verifies is the real test: a wrong implementation returns E_BAD_SIGNATURE.

Example (against the Getting Started install):
  chaperone serve ... --socket ~/.config/chaperone/agent.sock &
  python3 docs/skill/test-agent.py \
      --enroll-store ~/.config/chaperone/agents.json \
      --socket ~/.config/chaperone/agent.sock
If policy is still default-deny the gateway answers E_DENIED; add the rule
the script prints and re-run to see decision:allow.
"""
import argparse
import base64
import hashlib
import json
import os
import secrets
import socket
import subprocess
import sys
import time

# ---------- pure-python ed25519 (RFC 8032); stdlib-only, one-shot speed ----------
_p = 2**255 - 19
_l = 2**252 + 27742317777372353535851937790883648493
_d = -121665 * pow(121666, _p - 2, _p) % _p
_I = pow(2, (_p - 1) // 4, _p)


def _inv(x):
    return pow(x, _p - 2, _p)


def _xrecover(y):
    xx = (y * y - 1) * _inv(_d * y * y + 1)
    x = pow(xx, (_p + 3) // 8, _p)
    if (x * x - xx) % _p != 0:
        x = x * _I % _p
    if (x * x - xx) % _p != 0:
        raise ValueError("point decompression failed")
    if x % 2 != 0:
        x = _p - x
    return x


_By = 4 * _inv(5) % _p
_B = (_xrecover(_By) % _p, _By, 1, _xrecover(_By) * _By % _p)
_IDENT = (0, 1, 1, 0)


def _add(P, Q):
    x1, y1, z1, t1 = P
    x2, y2, z2, t2 = Q
    a = (y1 - x1) * (y2 - x2) % _p
    b = (y1 + x1) * (y2 + x2) % _p
    c = 2 * _d * t1 * t2 % _p
    dd = 2 * z1 * z2 % _p
    e, f, g, h = b - a, dd - c, dd + c, b + a
    return (e * f % _p, g * h % _p, f * g % _p, e * h % _p)


def _mult(P, e):
    Q = _IDENT
    while e > 0:
        if e & 1:
            Q = _add(Q, P)
        P = _add(P, P)
        e >>= 1
    return Q


def _encode(P):
    x, y, z, _ = P
    zi = _inv(z)
    x, y = x * zi % _p, y * zi % _p
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def _expand(seed):
    h = hashlib.sha512(seed).digest()
    a = int.from_bytes(h[:32], "little")
    a = (a & ((1 << 254) - 8)) | (1 << 254)
    return a, h[32:]


def ed25519_pubkey(seed):
    a, _ = _expand(seed)
    return _encode(_mult(_B, a))


def ed25519_sign(seed, msg):
    a, prefix = _expand(seed)
    r = int.from_bytes(hashlib.sha512(prefix + msg).digest(), "little") % _l
    R = _encode(_mult(_B, r))
    pub = ed25519_pubkey(seed)
    h = int.from_bytes(hashlib.sha512(R + pub + msg).digest(), "little") % _l
    return R + ((r + h * a) % _l).to_bytes(32, "little")


# ---------- Content-Length framing over the local channel ----------
def send_msg(sock, obj):
    data = json.dumps(obj, separators=(",", ":"), ensure_ascii=False).encode()
    sock.sendall(b"Content-Length: %d\r\n\r\n" % len(data) + data)


def recv_msg(sock):
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            raise RuntimeError("gateway closed the connection before replying")
        buf += chunk
    head, _, rest = buf.partition(b"\r\n\r\n")
    clen = next(
        int(line.split(":", 1)[1])
        for line in head.decode().split("\r\n")
        if line.lower().startswith("content-length")
    )
    while len(rest) < clen:
        chunk = sock.recv(4096)
        if not chunk:
            raise RuntimeError("connection closed mid-response")
        rest += chunk
    return json.loads(rest[:clen])


def b64url(raw):
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def main():
    ap = argparse.ArgumentParser(description="Chaperone sanctioned test agent")
    ap.add_argument("--socket", help="gateway Unix socket path (default: %(default)s)",
                    default=os.environ.get("CHAPERONE_SOCKET",
                                           "~/.config/chaperone/agent.sock"))
    ap.add_argument("--port", type=int, help="use loopback TCP instead of a Unix socket")
    ap.add_argument("--agent-id", default="agent:test-%s" % secrets.token_hex(3))
    ap.add_argument("--enroll-store",
                    default=os.path.expanduser("~/.config/chaperone/agents.json"),
                    help="agents.json path")
    ap.add_argument("--cred-ref", default="local://smoke/test")
    ap.add_argument("--target-uri", default="https://smoke.example.invalid/ping")
    ap.add_argument("--mechanism", default="http-bearer")
    ap.add_argument("--chaperone", default="chaperone", help="chaperone binary")
    ap.add_argument("--seed-file", help="hex file holding this agent's seed. "
                    "Created (and enrolled) on first run; reused (enroll skipped) on re-runs. "
                    "The seed IS the private key: keep it 0600 and delete it after testing.")
    ap.add_argument("--print-key", action="store_true",
                    help="write/generate --seed-file, print the public key, and exit "
                    "(no enroll, no send) — for enrolling BEFORE `serve` starts")
    ap.add_argument("--expect", choices=("allow", "denied"), default="allow")
    args = ap.parse_args()

    # 1. Throwaway keypair (fresh or persisted via --seed-file); enroll its
    #    PUBLIC key via the CLI — only when the keypair is fresh.
    had_seed = bool(args.seed_file) and os.path.exists(args.seed_file)
    if had_seed:
        seed = bytes.fromhex(open(args.seed_file).read().strip())
        print(f"using existing seed {args.seed_file} (skipping enroll; agent should already be enrolled)")
    else:
        seed = secrets.token_bytes(32)
        if args.seed_file:
            fd = os.open(args.seed_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w") as f:
                f.write(seed.hex())
    pub = b64url(ed25519_pubkey(seed))

    if args.print_key:
        print(pub)
        return 0

    if not had_seed:
        try:
            subprocess.run(
                [args.chaperone, "enroll", "--store", args.enroll_store,
                 "--agent-id", args.agent_id, "--public-key", pub],
                check=True, stdout=subprocess.DEVNULL,
            )
        except subprocess.CalledProcessError as e:
            print(f"FAIL: enroll failed (exit {e.returncode}); "
                  f"if the agent is already enrolled, pass --seed-file with the original seed")
            return 1
        print(f"enrolled {args.agent_id} (public key {pub[:12]}…) via:"
              f" chaperone enroll --store {args.enroll_store} --agent-id {args.agent_id}")

    # 2. ONE signed intent (signature covers the whole envelope minus sig).
    envelope = {
        "chaperone": "0.1",
        "msg_id": secrets.token_hex(6),
        "type": "intent",
        "agent_id": args.agent_id,
        "issued_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "nonce": secrets.token_hex(8),
        "target": {"uri": args.target_uri, "label": "test-agent"},
        "mechanism": args.mechanism,
        "cred_ref": args.cred_ref,
        "operation": {"method": "GET", "headers": {}},
    }
    canonical = json.dumps(envelope, sort_keys=True, separators=(",", ":"),
                           ensure_ascii=False).encode()
    envelope["sig"] = b64url(ed25519_sign(seed, canonical))

    if args.port:
        sock = socket.create_connection(("127.0.0.1", args.port), timeout=15)
    else:
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.settimeout(15)
        sock.connect(os.path.expanduser(args.socket))
    send_msg(sock, envelope)
    response = recv_msg(sock)
    sock.close()

    print("gateway response:", json.dumps(response, sort_keys=True))
    decision = response.get("decision") or (
        "denied" if response.get("code") == "E_DENIED" else None)
    if decision == args.expect:
        print(f"PASS: decision={decision} (expected {args.expect})")
        return 0
    if response.get("code") == "E_DENIED" and args.expect == "allow":
        print(
            "FAIL: policy denied this agent. Add a matching rule to policy.toml, e.g.:\n"
            f'  [[rule]]\n  name = "smoke test"\n  effect = "allow"\n'
            f'  agent_id = "{args.agent_id}"\n  cred_ref = "{args.cred_ref}"\n'
            f'  target_uri = "{args.target_uri}"\n  mechanism = "{args.mechanism}"\n'
            "then restart serve and re-run."
        )
    else:
        print(f"FAIL: expected decision={args.expect}, got: {response}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
