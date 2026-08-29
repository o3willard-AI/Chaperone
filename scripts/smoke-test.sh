#!/usr/bin/env bash
# Chaperone install->serve->signed-intent smoke test (issue #41).
#
# Productionizes the QA probe: on a scratch config dir it runs the real
# onboarding flow with the locally-built binaries, sends ONE signed intent
# from the sanctioned test agent through the live gateway, and asserts
# decision:allow. Exits non-zero on ANY failure; leaves the scratch dir
# behind on failure for post-mortem, cleans up on success.
#
# Usage:
#   scripts/smoke-test.sh [path-to-chaperone-binary]
#     (default: target/release/chaperone — build first:
#      cargo build --release --locked -p chaperone-cli -p chaperone-privileged-helper)
#
# CI wiring (per platform, in .github/workflows/release.yml, after the build
# step and before packaging — see PR notes):
#   - name: Smoke test (Linux/macOS)
#     if: runner.os != 'Windows'
#     shell: bash
#     run: scripts/smoke-test.sh target/release/chaperone
#   - name: Smoke test (Windows)
#     if: runner.os == 'Windows'
#     shell: bash
#     run: scripts/smoke-test.sh target/release/chaperone.exe
# (Same script works: every chaperone invocation goes through CHAP var.)
# Windows needs Python on the runner (setup-python) and Git Bash's python3
# aliasing; the Unix legs run on stock runners.

set -euo pipefail

CHAP="${1:-target/release/chaperone}"
[ -x "$CHAP" ] || { echo "smoke: binary not found/executable: $CHAP" >&2
                    echo "smoke: build with: cargo build --release --locked -p chaperone-cli -p chaperone-privileged-helper" >&2
                    exit 2; }
CHAP="$(cd "$(dirname "$CHAP")" && pwd)/$(basename "$CHAP")"
SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)/docs/skill/test-agent.py"
[ -f "$SCRIPT_DIR" ] || { echo "smoke: missing docs/skill/test-agent.py" >&2; exit 2; }

WORK="$(mktemp -d /tmp/chaperone-smoke.XXXXXX)"
cleanup() { [ "${SMOKE_KEEP:-0}" = "1" ] || rm -rf "$WORK"; kill "${SRV_PID:-0}" "${TGT_PID:-0}" 2>/dev/null || true; }
trap cleanup EXIT

# The http-bearer injector performs the REAL outbound call, so the smoke
# test runs a throwaway loopback HTTP target (a 404 from it is fine: the
# asserted `decision` reflects policy, not the target's status code).
TARGET_PORT=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1",0)); print(s.getsockname()[1]); s.close()')

step() { printf '\n== %s ==\n' "$*"; }
die()  { printf '\nsmoke: FAILED: %s\n' "$*" >&2; exit 1; }

D="$WORK/cfg"; mkdir -p "$D"
SOCK="$D/agent.sock"

step "1/6 vault + audit key + policy + UI token (the onboarding artifacts)"
printf 'smoke-pass-1\n' > "$D/vault.pass"
"$CHAP" vault-init --store "$D/vault.bin" --passphrase-stdin < "$D/vault.pass" \
    >/dev/null || die "vault-init failed"
"$CHAP" audit-keygen --out "$D/audit.key" >/dev/null || die "audit-keygen failed"
: > "$D/policy.toml"; chmod 600 "$D/policy.toml"
"$CHAP" ui-token rotate --token "$D/ui.token" >/dev/null || die "ui-token rotate failed"

step "2/6 store a credential + allow-rule, and enroll the test agent (before serve: a running gateway does not re-read agents.json)"
printf 'smoke-pass-1\nsmoke-secret-value\n' \
    | "$CHAP" vault-set --store "$D/vault.bin" --path smoke/test --passphrase-stdin \
    >/dev/null || die "vault-set failed"
AGENT_ID="agent:smoke-$(date +%s)"
cat >> "$D/policy.toml" <<EOF
[[rule]]
name = "smoke test"
effect = "allow"
agent_id = "$AGENT_ID"
cred_ref = "local://smoke/test"
target_uri = "http://127.0.0.1:$TARGET_PORT/*"
mechanism = "http-bearer"
EOF
# Phase 1 of the test agent: materialize its keypair, print the public key.
PUB="$(python3 "$SCRIPT_DIR" --print-key --seed-file "$D/agent.seed")" \
    || die "test agent key generation failed"
"$CHAP" enroll --store "$D/agents.json" --agent-id "$AGENT_ID" --public-key "$PUB" \
    >/dev/null || die "enroll failed"

step "3/6 doctor (must be green before serve)"
"$CHAP" doctor --policy "$D/policy.toml" --enrollment "$D/agents.json" \
    --store "$D/vault.bin" --audit-key "$D/audit.key" --audit-journal "$D/audit.jsonl" \
    --passphrase-file "$D/vault.pass" >/dev/null \
    || { "$CHAP" doctor --policy "$D/policy.toml" --enrollment "$D/agents.json" \
             --store "$D/vault.bin" --audit-key "$D/audit.key" \
             --audit-journal "$D/audit.jsonl" --passphrase-file "$D/vault.pass" || true;
         die "doctor reported an unhealthy install"; }

step "4/6 serve (broker mode) + wait for the socket"
python3 -m http.server "$TARGET_PORT" --bind 127.0.0.1 > /dev/null 2>&1 &
TGT_PID=$!
"$CHAP" serve --socket "$SOCK" --enrollment "$D/agents.json" --policy "$D/policy.toml" \
    --store "$D/vault.bin" --audit-journal "$D/audit.jsonl" --audit-key "$D/audit.key" \
    --passphrase-file "$D/vault.pass" --no-ui > "$WORK/serve.log" 2>&1 &
SRV_PID=$!
for i in $(seq 1 50); do
    [ -S "$SOCK" ] && break
    kill -0 "$SRV_PID" 2>/dev/null || { cat "$WORK/serve.log" >&2; die "serve exited early"; }
    sleep 0.2
done
[ -S "$SOCK" ] || { cat "$WORK/serve.log" >&2; die "socket never appeared"; }
grep -q "chaperone gateway listening" "$WORK/serve.log" || { cat "$WORK/serve.log" >&2; die "serve did not report listening"; }

step "5/6 doctor against the live gateway (now including the transport check)"
"$CHAP" doctor --policy "$D/policy.toml" --enrollment "$D/agents.json" \
    --store "$D/vault.bin" --audit-key "$D/audit.key" --audit-journal "$D/audit.jsonl" \
    --passphrase-file "$D/vault.pass" --socket "$SOCK" >/dev/null \
    || die "doctor failed against the live gateway"

step "6/6 one signed intent through the live gateway (test-agent.py)"
python3 "$SCRIPT_DIR" --chaperone "$CHAP" \
    --enroll-store "$D/agents.json" --socket "$SOCK" \
    --seed-file "$D/agent.seed" \
    --agent-id "$AGENT_ID" --cred-ref "local://smoke/test" \
    --target-uri "http://127.0.0.1:$TARGET_PORT/ping" --expect allow \
    || die "test agent did not get decision:allow"

step "audit chain verifies after the live decision"
# audit-verify demands the verifying key; derive it from the seed file
# (base64url, unpadded) the way serve does, via the test agent's ed25519.
AUDIT_PUB="$(python3 -c '
import sys, base64, importlib.util
b64 = open(sys.argv[1]).read().strip()
seed = base64.urlsafe_b64decode(b64 + "=" * (-len(b64) % 4))
spec = importlib.util.spec_from_file_location("ta", sys.argv[2])
ta = importlib.util.module_from_spec(spec); spec.loader.exec_module(ta)
print(ta.b64url(ta.ed25519_pubkey(seed)))
' "$D/audit.key" "$SCRIPT_DIR")" || die "could not derive audit public key"
"$CHAP" audit-verify --journal "$D/audit.jsonl" --public-key "$AUDIT_PUB" \
    >/dev/null || die "audit chain failed to verify after the smoke decision"

echo
echo "smoke: PASS (install -> serve -> signed intent -> decision:allow; audit chain verified)"
