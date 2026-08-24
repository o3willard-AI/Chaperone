# Chaperone Documentation

Chaperone is a local-first **authentication broker**: it lets an AI agent perform authenticated operations against other systems — APIs, databases, SSH hosts, privileged local commands — **without any credential ever entering the agent's context, transport, or logs.** The agent sends a *signed intent* naming a credential *reference*; the gateway verifies who is asking, decides whether policy allows it, injects the real secret on the outbound side, and returns the result. The agent holds a reference, never a secret.

These four documents define the system. They all derive from one canonical intent schema; **the Protocol Specification governs** wherever they differ.

| # | Document | What it defines |
|---|---|---|
| 1 | [Protocol Specification](01-protocol-spec.md) | The wire contract between agent and gateway — the canonical schema. |
| 2 | [Architecture Specification](02-architecture-spec.md) | The gateway's internal structure: layers, vault abstraction, injectors, privileged helper, audit chain, ephemerality rules. |
| 3 | [Threat Model](03-threat-model.md) | Adversaries, the confused-deputy analysis, the secure-fragility tenet, and hardening. |
| 4 | [Agent Skill](04-agent-skill.md) | The agent-facing projection of the schema. Source under [`../skill/`](../skill/). |

**For implementers:** start with the [Implementation Agent Brief](IMPLEMENTATION_AGENT_BRIEF.md) — it explains how to read these documents and how to build out a phased implementation plan. Building on Apple hardware? Read [BUILDER-NOTES-MACOS.md](BUILDER-NOTES-MACOS.md).

## Status

Version 0.1 — draft, open for review. This is pre-release: the specifications are complete enough to build against, but expect them to evolve as implementation surfaces questions. Discrepancies found during implementation should be raised as issues.

## The one-sentence north star

An agent can do real authenticated work, and at no point does a human ever see a secret scroll by, or find one in a log, or have to paste one in — while the operator keeps provable, revocable control over every action.
