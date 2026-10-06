# B-2 — Bulk inventory import: spec decisions

**Author:** ox-chap (Hermes, host 192.168.101.11)
**Date:** 2026-10-06
**Status:** DRAFT — for review by Heph, then ruling by Stephen
**Work order:** `~/workspace/tasks/wi-B-2.md` (pending; backlog item B-2,
MVP-GAP-REVIEW.md line 709 → P1-2 item 2, line 480)

---

## 1. Problem

D43 `pair` rows exist in the rule language, but a fleet operator still fills
them **by hand**: for each host, create a vault entry
(`local://ssh/fleet/app-01`), then edit the policy TOML to add a
`[[rule.pair]]` row. 300 hosts = 300 of each. P1-2's whole point was that
hand-maintained correlation doesn't survive a fleet; the pairs language made
the *permission set* readable, but the rows themselves are still manual.

B-2 makes rows machine-generated: `chaperone vault import` fed by an
inventory source, creating vault entries **and** the paired rule rows in one
auditable action.

## 2. Source formats (TD-1)

v1 ships **two** importers, both plain-text and both already in every SSH
operator's world:

- **`--source csv <FILE>`** — the canonical machine-generated format.
  Columns: `name,host,port,user,secret` (header row required; `port`
  optional, default 22; `secret` optional — absent means the entry gets a
  placeholder the operator must replace, see TD-5). One row per host.
- **`--source ssh-config <FILE>`** — parses an OpenSSH `ssh_config` file:
  each `Host` block with a `HostName` becomes a row; `Port`, `User`
  respected; patterns (`Host *.internal`) are **skipped with a warning**
  (they are not hosts; silently importing them would import a lie). Secrets
  are never in ssh_config, so every entry from this source takes the
  placeholder path (TD-5).

Known-hosts is explicitly **out**: `known_hosts` lists servers the client
has touched, not credentials Chaperone should broker, and it has no user or
secret notion. Mixing it in would blur what an "inventory" row means.

## 3. The one action, and what it writes (TD-2)

`chaperone vault import --store <FILE> --policy <TOML> --rule-name <NAME>
--source <KIND> <FILE> [--cred-scheme local://ssh/fleet] [--dry-run]`

One invocation writes:

1. **Vault entries** — one per row, path
   `{cred_scheme}/{name}` (default scheme `local://ssh/fleet`), value =
   the row's secret (or placeholder, TD-5). Entries that already exist are
   **left untouched and reported** as `skipped (exists)` — import never
   overwrites a live secret. No entry path may resolve inside the CA
   namespace (`chaperone/ca/`) — the CA-1 guard applies before anything is
   written, and the whole run fails closed if any row would.
2. **Policy rows** — the policy file is loaded via `Policy::from_toml`, the
   target rule (matched by exact `name == --rule-name`) gains one `Pair`
   row per successfully imported entry:
   `cred_ref = local://ssh/fleet/{name}`,
   `target_uri = ssh://{host}:{port}`. The rewritten document is produced
   by the canonical writer (`Policy::from_rules(rules).to_toml()`) and
   written back to `--policy`. Duplicate rows (same cred_ref + target_uri
   already present in the rule) are not re-added.
3. **A summary line per row** — `imported | skipped (exists) | failed
   (<reason>)` — printed to stdout, one line per inventory row, so the
   operator sees exactly what the fleet now looks like.

If `--rule-name` does not match any rule: **hard error, nothing written**
(fail closed — an import that silently adds rows to no rule is an import
that nobody can audit).

`--dry-run` performs every check and prints the full summary but writes
nothing (vault and policy both).

## 4. Ordering and atomicity (TD-3)

Within the run: **vault entries first, policy rows second** (the same
direction as the P2-1 rule-last ruling mirrored: the secret must exist
before the rule that names it, so a partial failure leaves an *unused*
secret rather than a *dangling rule row* — the hazard D46 ruled is worse).

Not transactional across the two stores: a crash between the two phases
leaves entries without rows — harmless (no rule names them), reported by a
re-run as `skipped (exists)` with rows then added. The reverse order would
leave rows naming nonexistent entries, which the gateway treats as
`cred_unresolved` denials at request time. Ordering is the cheap
atomicity.

## 5. Secrets handling (TD-4)

- CSV `secret` values go into the vault **only**. They never appear in the
  policy file, stdout summary (rows print `name`/`host`, never the secret),
  or the audit chain. The summary line prints the entry **path**, not its
  value.
- Rows with an **empty secret field** import with a placeholder value
  `<chaperone:unset>` and are flagged `placeholder` in the summary; the
  operator replaces them via `vault-set` (or the UI) before use. An attempt
  to authenticate through an unset entry fails at resolve time — the
  failure is honest, not silent.
- The `no_secret_leak` sentinel suite gains an import-path test: an import
  run's stdout, the policy diff, and the audit chain must not contain the
  imported secret text (same discipline as the mint-path test added for
  B-1).

## 6. Audit (TD-5)

One `audit.import` event per run (not per row — a 300-row import must not
produce 300 audit rows): `source_kind`, `source_file` basename, rule name,
counts (`imported` / `skipped` / `failed` / `placeholder`). No row values.
The event records that an import *happened*; the per-row truth lives in the
stdout summary the operator saw.

## 7. What B-2 deliberately does NOT do

- No host reachability checks, DNS lookups, or key generation — import is
  bookkeeping, not provisioning. A row that fails to *parse* is a `failed`
  summary line; a host that doesn't *answer* is the operator's next tool's
  problem.
- No rule *creation*. Import edits an existing rule's pair table. Creating
  the rule remains a human act (P2-1 wizard or hand-edited TOML) — an
  import that can mint rules could mint permissions.
- No UI. CLI only in v1; the UI reads the same policy file and shows the
  imported rows like any others.
- No de-duplication across *sources*. One run, one source.

## 8. Acceptance tests

1. **CSV round-trip**: a 3-row CSV imports 3 entries + 3 pair rows; the
   rewritten policy parses back via `Policy::from_toml` with the rule's
   pairs equal to the expected rows; `Policy::evaluate` proves key A is
   denied against host B under the imported rule (the P1-2 acceptance,
   now machine-generated).
2. **Idempotent re-run**: same CSV twice → second run: entries
   `skipped (exists)`, pair rows unchanged (no duplicates), policy file
   byte-identical.
3. **ssh-config source**: a config with 2 concrete hosts + 1 pattern block
   imports the 2, warns on the pattern, both take placeholder secrets.
4. **Dry-run**: `--dry-run` output shows the same summary as a real run;
   vault `list()` and the policy file are unchanged afterwards.
5. **Fail-closed rule name**: `--rule-name nope` exits nonzero, vault
   `list()` unchanged, policy file unchanged.
6. **CA-namespace guard**: a CSV row whose name would produce
   `chaperone/ca/...` fails the entire run with exit 2 before any write.
7. **No-secret-leak**: imported secret text appears in none of: stdout
   summary, policy file, audit chain (extends the B-1 mint-path sentinel).
8. **Placeholder honesty**: a placeholder entry resolves to a value that
   fails authentication at request time (existing `cred_unresolved`/
   backend-error path), and the summary marked it `placeholder`.

## 9. Sizing

~3–4.5 days: CSV + ssh-config parsers (0.5–1d), import command with
ordering/guards (1–1.5d), acceptance tests incl. leak sentinel (1d),
docs (CONNECTIVITY-MATRIX already points here — 0.5d).