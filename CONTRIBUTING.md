# Contributing to Chaperone

Thank you for helping build credential infrastructure for agents. This is
security software, built in the open: every commit is visible on purpose. Write
every commit, comment, and document as if a security researcher you respect is
reading it — because one will.

## Ground rules (non-negotiable)

These come from the [implementation brief](docs/IMPLEMENTATION_AGENT_BRIEF.md)
§3 and the specifications it cites. They are properties, not style preferences:

- **No secret in agent space, ever.** No code path returns, logs, echoes, or
  serializes raw credential material — including errors, debug output, and
  audit records.
- **Default-deny.** Absence of an explicit allow is a denial. There is no
  permissive mode; tests work *with* default-deny.
- **Attribution before action.** Verify signature and freshness before parsing
  mechanism bodies, before policy, before the vault. The verification order in
  [PROTO-SPEC §4](docs/01-protocol-spec.md) is load-bearing; implement it
  exactly and stop at the first failure.
- **Secure fragility over durability.** Fetch late, hold minimally,
  scrub always, re-fetch fresh on retry. Never cache a secret to smooth a
  retry — not even "just for tests."
- **Never weaken a security property to make a test pass or a demo work.**
  Fix the test, not the property.

## Getting started

```sh
git clone https://github.com/o3willard-AI/Chaperone
cd Chaperone
cargo build --locked   # rustup provisions the pinned toolchain automatically
cargo test --locked
```

Before pushing:

```sh
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
cargo audit
```

## Working discipline

- **Test against the spec, not against your implementation.** Where possible,
  write the acceptance test from PROTO-SPEC's stated behavior first, then make
  it pass. The specs are the oracle.
- **Every security rule gets an explicit test** that would fail if violated:
  no secret in logs, default-deny holds, retries re-fetch rather than cache.
  Gaps here are release blockers.
- **Small, legible commits with honest messages.** If a commit makes a
  security-relevant tradeoff, say so in the message.
- **When the spec is silent, decide explicitly and write it down** in
  [DESIGN-DECISIONS.md](docs/DESIGN-DECISIONS.md).
- **When the spec is wrong or unclear, say so** — add it to
  [SPEC-ISSUES.md](docs/SPEC-ISSUES.md) or open an issue describing the problem
  and a proposed resolution, rather than quietly diverging.

## Reporting issues

Bugs and spec questions: public GitHub issues are welcome. Anything you believe
is exploitable: report privately per [SECURITY.md](SECURITY.md).

## License

By contributing you agree your contributions are licensed under Apache-2.0
(see [LICENSE](LICENSE)).
