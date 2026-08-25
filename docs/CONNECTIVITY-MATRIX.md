# Supported Connectivity & Application Matrix

**Purpose.** One living table answering: *what can an agent reach through
Chaperone today, how, and what is missing?* It drives our roadmap and gives
the community a concrete way to ask for (and vote on) new connectivity.
Statuses change with every release — subscribe to this file.

- ✅ **Supported** — implemented, tested, documented
- ⚠️ **Partial / caveated** — works with documented limitations
- 🗺️ **Planned** — on the roadmap, not built
- ❌ **Not planned** — anti-goal; see reasoning

Where a row says "tested", the acceptance test lives in the repo and runs in
CI (or gated behind credentials for live services).

---

## 1. Mechanisms (how agents reach things)

Every mechanism shares the same spine: signed intent → identity → policy →
(single confirmation) → fetch-late credential resolution → injection → audit.
The agent never touches a secret.

| Mechanism | Lifecycle | Credential form | Maturity | Confirmation |
|---|---|---|---|---|
| `http-bearer` | one-shot | bearer token from vault | ✅ stable | per policy |
| `http-basic` | one-shot | password from vault + username in intent | ✅ stable | per policy |
| `db-scram` (postgres) | one-shot or session | database password (SCRAM-SHA-256) | ✅ tested vs postgres 16 | per policy |
| `ssh` | session | private key from vault, parsed in memory | ✅ tested via mock channel; live-host validation ongoing | per policy |
| `local-privilege` | session (one pinned exec) | none required (sudoers/pin allowlist) | ✅ tested vs real helper binary | ALWAYS unless allowlist-pinned |

## 2. Application & service coverage

### HTTP(S) APIs — the broadest class

| Service / type | Status | How | Notes |
|---|---|---|---|
| **Any HTTPS REST API** (JSON/XML/text) | ✅ | `http-bearer` | The general case. Tested: GitHub-shaped flow incl. header injection + scoping (`tests/github_api.rs`) |
| **GitHub REST API v3** | ✅ verified | `http-bearer` + fine-grained PAT | Worked example below; offline emulator test always runs, live test gated by `CHAPERONE_TEST_GH_TOKEN`. Use a fine-grained PAT scoped to needed repos only |
| **GraphQL APIs** (GitHub v4, Hasura, …) | ✅ | `http-bearer` | POST-with-JSON rides the same injector |
| **Kubernetes API** | ⚠️ | `http-bearer` + ServiceAccount token in vault | Bearer-over-HTTPS works; **custom/private CA roots are not configurable yet** (webpki bundle) — see backlog C1 |
| Internal HTTPS services behind a **private CA** | ⚠️ blocked | — | Same root-store limitation as above (backlog C1) |
| APIs behind redirects | ⚠️ | — | Redirects are deliberately OFF (D21): a signed intent names ONE target. Call the post-redirect URL explicitly |
| OAuth2 client-credentials token endpoints | ⚠️ manual | `http-bearer`/`http-basic` twice | Fetch token into vault via operator, then call. Automatic refresh is planned with dynamic minting |
| **Git push/pull over HTTPS or SSH** | ❌ for now | — | Git transport needs multi-request auth choreography and SSH exec channels; today use the GitHub/GitLab contents API for single-file operations. Tracked as a connectivity request |
| **Multipart/binary uploads** | ⚠️ | `body_b64` | Technically supported (agent builds the multipart body); awkward for large payloads until streaming lands |

### Databases

| Service / type | Status | How | Notes |
|---|---|---|---|
| **PostgreSQL** (incl. Supabase, RDS, Cloud SQL if reachable) | ✅ | `db-scram` one-shot or session | Real SCRAM-SHA-256 via tokio-postgres; params bound as text; TLS-to-DB NOT negotiated yet (NoTls gap — D27), so restrict to networks you trust |
| MySQL / MariaDB | 🗺️ | future db engine | mysql_native_password is not SCRAM; needs its own engine adapter |
| Microsoft SQL Server | 🗺️ | future db engine | |
| Redis | 🗺️ | future session backend | Simple AUTH+command relay |

### Shell / infrastructure

| Service / type | Status | How | Notes |
|---|---|---|---|
| **SSH hosts** (interactive shell, remote commands) | ✅ | `ssh` sessions, Ed25519 keys from vault | Host-key pin store with TOFU + known_hosts import (D31); changed key ⇒ hard refusal |
| **Local privileged commands** (systemctl, apt, …) | ✅ | `local-privilege` + isolated helper | Always confirmed unless command+args are exactly pinned by the operator allowlist; helper re-checks authoritatively |
| Windows privileged commands | 🗺️ | same helper over named pipes | Helper protocol is platform-neutral; elevation story = service/UAC, untested |

### Credential backends (where secrets LIVE — the `cred_ref` targets)

| Backend | Scheme | Status | Notes |
|---|---|---|---|
| Built-in sealed local vault | `local://` | ✅ | argon2id + AES-256-GCM, platform-keyring option behind feature flag |
| **HashiCorp Vault KV-v2** | `vault://` | ✅ | Token auth; single-key direct, `path#key` selector for multi-key; dynamic engines via `mint()` post-v1 |
| AWS Secrets Manager | 🗺️ `aws://` | planned | SigV4 signing needed; deferred until a verifiable test surface (LocalStack) exists |
| GCP Secret Manager | 🗺️ `gcp://` | planned | OAuth2 service-account JWT |
| Azure Key Vault | 🗺️ `az://` | planned | Client-credential flow |
| 1Password / CyberArk | 🗺️ | evaluated on request | ARCH §2.4 table lists them; follow the connector-request process below |

### Deliberately out of scope / anti-goals

| Thing | Status | Why |
|---|---|---|
| Wrapping external client processes (`curl`, `gh`, `aws` CLI…) with injected credentials | ❌ never | Puts the secret back into agent space (env/argv/history) — the exact harm Chaperone exists to prevent. The gateway IS your HTTP client; results return to the agent instead |
| Agents holding tokens via environment variables | ❌ never | Same reasoning |
| Permissive/testing mode that bypasses policy or the gate | ❌ never | Default-deny is structural |
| Network listeners beyond the local sockets | ❌ never | Local-first is the architecture |
| Reading secrets back out of the gateway | ❌ never | No intent shape returns credential material |

## 3. Worked example: GitHub REST API

Policy (excerpt):

```toml
[[rule]]
name   = "ci agent may read github"
effect = "allow"
agent_id    = "agent:github-1"
cred_ref    = "local://prod/github/token"
target_uri  = "https://api.github.com/*"
[rule.limits]
max_response_bytes = 262144
```

Intent (what the agent signs and sends):

```json
{
  "chaperone": "0.1",
  "msg_id": "gh-u1",
  "type": "intent",
  "agent_id": "agent:github-1",
  "issued_at": "<now RFC3339>",
  "nonce": "<random>",
  "target": {"uri": "https://api.github.com/user", "label": "github-api"},
  "mechanism": "http-bearer",
  "cred_ref": "vault://prod/github/token",
  "operation": {"method": "GET",
                "headers": {"Accept": "application/vnd.github+json"}},
  "sig": "<ed25519 over JCS of everything above>"
}
```

Response to the agent: `{"type":"result","status":200,"body_b64":"…","audit_id":"aud_N"}`.
The PAT appears nowhere in it. Acceptance tests:
`crates/gateway-core/tests/github_api.rs` (offline emulator always runs;
live round-trip gated by `CHAPERONE_TEST_GH_TOKEN`).

Operational guidance: fine-grained PAT, minimal repos, short expiry; rotate
by updating the vault entry — the cred_ref never changes, so neither policy
nor agent does.

## 4. Requesting new connectivity

Open an issue using the **"Connectivity / service request"** template
(`.github/ISSUE_TEMPLATE/connectivity-request.yml`). Helpful context:

1. Service name + auth scheme (bearer/basic/SCRAM/mTLS/OAuth…)
2. Protocol shape (REST? wire protocol? interactive?)
3. Is there a FREE test surface (emulator, container, sandbox)? — this
   weighs heavily: we ship only what we can verify
4. What breaks today without it
5. Whether you can help test

Prioritization = community demand × verifiability × fit with the security
rules. Rows move up the same way this table's first entries did.
