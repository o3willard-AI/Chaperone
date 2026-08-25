# Chaperone

**A local-first authentication broker for AI agents.**

Chaperone lets an AI agent perform authenticated operations against other
systems — APIs, databases, SSH hosts, privileged local commands — **without any
credential ever entering the agent's context, transport, or logs**. The agent
sends a *signed intent* naming a credential *reference*; the gateway verifies
who is asking, decides whether policy allows it, fetches the real secret at the
last possible moment, injects it on the outbound side, and returns the result.

The agent holds a reference, never a secret.

Chaperone is not "a thing that injects credentials." It is a **policy
enforcement point with attribution and audit**: it decides which agent may use
which credential against which target for which operation, proves who asked,
and records tamper-evident evidence.

> The north star: an agent can do real authenticated work, and at no point does
> a human ever see a secret scroll by, or find one in a log, or have to paste
> one in — while the operator keeps provable, revocable control over every
> action.

## Status

**Individual preview (`v0.1.0-alpha.1`).** All four v1 mechanisms are
implemented - http, ssh sessions, db-scram against PostgreSQL, and
local-privilege through the isolated helper - plus identity, default-deny
policy, tamper-evident audit, the vault abstraction (local sealed +
HashiCorp Vault), the confirmation gate, conformance tests, fuzzing, and a
reproducible-build release pipeline. Corporate OS code signing (Authenticode /
Apple notarization) is deliberately deferred until there is an entity to own
it; artifacts carry ed25519 signatures and are reproducibly buildable -
see [docs/RELEASE.md](docs/RELEASE.md) for verification. Expect breaking
changes while the specs themselves remain v0.1 drafts open for review.

## Documentation

| Document | Defines |
|---|---|
| [Protocol Specification](docs/01-protocol-spec.md) | The wire contract between agent and gateway — the canonical schema. Governs all others. |
| [Architecture Specification](docs/02-architecture-spec.md) | Internal structure: layers, vault abstraction, injectors, privileged helper, audit chain, ephemerality rules. |
| [Threat Model](docs/03-threat-model.md) | Adversaries, confused-deputy analysis, secure-fragility tenet, hardening. |
| [Agent Skill](docs/04-agent-skill.md) | The agent-facing projection of the schema ([sources](docs/skill/)). |

Implementation working documents:

- [PLAN.md](docs/PLAN.md) — phased plan: goals, spec sections, acceptance tests, security rules.
- [BUILDER-NOTES-MACOS.md](docs/BUILDER-NOTES-MACOS.md) — brief for building and validating on Apple hardware.
- [CONNECTIVITY-MATRIX.md](docs/CONNECTIVITY-MATRIX.md) — every application/service type agents can reach today, how, and what is missing. File a connectivity request to shape the roadmap.
- [LOCAL-VAULT-GUIDE.md](docs/LOCAL-VAULT-GUIDE.md) — user guide for the built-in encrypted vault: create, store, rotate, back up — no third-party service required.
- [DESIGN-DECISIONS.md](docs/DESIGN-DECISIONS.md) — explicit decisions where the specs are silent.
- [SPEC-ISSUES.md](docs/SPEC-ISSUES.md) — discrepancies found while reading, tracked rather than papered over.

## Repository layout

```
crates/
  protocol/           wire-contract types (version, error taxonomy, envelope)
  gateway-core/       orchestration spine: verify -> policy -> confirm -> resolve -> inject -> audit
  transport/          local channel + Content-Length framing (UDS / named pipe / loopback)
  identity/           Ed25519 attestation, JCS canonicalization, replay cache, enrollment
  policy/             default-deny decision engine
  vault/              provider abstraction + built-in sealed local vault
  injectors/          mechanism modules: http, db-scram, ssh, local-privilege
  audit/              append-only hash-chained signed evidence records
  privileged-helper/  separate elevated process for local-privilege
  cli/                operator CLI (enrollment, policy, vault CRUD, audit verify)
docs/                 specifications, threat model, agent skill, plans
```

Crate boundaries mirror the architecture's five layers and their inward-only
dependency rule (ARCH-SPEC §1.1).

## Development

Requires Rust (toolchain pinned in `rust-toolchain.toml`; rustup provisions it
automatically):

```sh
cargo build --locked
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
cargo fmt --all -- --check
```

CI enforces all of the above on Linux, macOS, and Windows, plus `cargo audit`
for dependency CVEs. See [CONTRIBUTING.md](CONTRIBUTING.md) for the project's
working discipline.

## Security

Please report vulnerabilities privately — see
[SECURITY.md](SECURITY.md). Do not open public issues for anything you believe
is exploitable.

## License

Apache-2.0. See [LICENSE](LICENSE).
