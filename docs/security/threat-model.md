# Threat Model

> **Scope:** OpenIntelligence backend service as described in the current merged codebase. Threat analysis for feature-branch capabilities (orchestration, endpoint commands, case workflow) is included at a planning level and clearly labelled.

---

## Assets

| Asset | Classification | Notes |
|---|---|---|
| Tenant intelligence data (CVEs, IOCs, actors, victims) | Sensitive — competitive / operational | Cross-tenant leakage is a critical failure |
| Asset inventory and exposure data | Sensitive — organizational | Reveals what systems an org runs and where they are vulnerable |
| Investigation and case data | Highly sensitive — operational | May reveal IR strategy and evidence |
| API keys (secret halves) | Critical credentials | Argon2id-hashed; plaintext shown once; rotate on exposure |
| Endpoint agent mTLS certificates and CA key | Critical credentials | CA key compromise = full agent identity spoofing |
| LLM API key | High-value credential | Enables expensive AI calls; potential data exfiltration to provider |
| Connector credentials (Slack, Jira, SIEM) | High-value credentials | Enable external delivery; stored only in environment config |
| Audit log | Compliance-critical | Append-only; must not be deleted or modified |
| Database (PostgreSQL) | Infrastructure-critical | Contains all tenant data and provenance |
| Redis (rate limiter) | Infrastructure | Loss degrades to in-memory; not a data loss risk |

---

## Trust boundaries

```
[External feeds (NVD, OTX, Ransomware.live, GitHub)]
        │ HTTPS outbound; credentials in env config
        ▼
[Ingestion pipeline] ── normalizes, quarantines invalid records ──► [PostgreSQL]
        │
[API service (FastAPI)] ←── API key (X-API-Key) ── [Human users / API clients]
        │
[Agent gateway (mTLS)] ←── mTLS certificate ── [Endpoint agents]
        │
[LLM provider (OpenAI-compatible)] ←── LLM_API_KEY ── [RAG service]
        │
[Connector delivery worker] ── webhook/token ──► [Slack / Jira / SIEM]
```

**Trust boundary crossings:**
1. Public internet → ingestion (outbound only; no inbound from feeds)
2. API clients → API service (authenticated; rate-limited)
3. Endpoint agents → agent gateway (mTLS; no password auth)
4. API service → LLM provider (outbound; intelligence data may be sent)
5. Connector worker → external services (outbound; triggered by approved automation)

---

## Threats and mitigations

### T1 — Cross-tenant data access

| Attribute | Detail |
|---|---|
| **Threat** | A tenant reads or mutates another tenant's records via the API |
| **Attack vector** | Omitted or manipulated `tenant_id` filter; IDOR via predictable IDs |
| **Mitigation** | Every tenant-owned query filters on `tenant_id` derived from the authenticated principal; UUID PKs are non-sequential; 404 returned for cross-tenant resource to prevent existence oracle |
| **Residual risk** | Unit tests for tenant isolation on all tenant-owned routes are not yet complete (Phase D) |
| **Test requirement** | Principal from Tenant A must receive 404 for any resource owned by Tenant B |

---

### T2 — API key theft or unauthorized use

| Attribute | Detail |
|---|---|
| **Threat** | A stolen API key is used to exfiltrate data or trigger mutations |
| **Mitigation** | Argon2id hash with tuned parameters (time cost 3, memory cost 64 MiB); plaintext never stored or re-displayed; keys are scoped; read keys cannot trigger mutations or AI report generation; expired keys rejected; revocation is immediate and audited |
| **Residual risk** | No token binding or device attestation yet; a leaked active key has full scope until revoked |
| **Response** | Revoke immediately via `DELETE /api-keys/{key_id}`; review audit log for activity |

---

### T3 — Scope escalation

| Attribute | Detail |
|---|---|
| **Threat** | An API key holder grants themselves or another key scopes they do not hold |
| **Mitigation** | Key creation enforces that a caller cannot grant any scope they do not themselves hold; only scopes in the `GRANTABLE_SCOPES` allowlist are permitted; attempts return 403 with an explicit `missing` list |
| **Residual risk** | An `admin`-scoped key can effectively grant broad access to other keys; admin key issuance must require separation-of-duties (not yet enforced) |

---

### T4 — mTLS CA key compromise

| Attribute | Detail |
|---|---|
| **Threat** | The agent CA private key is stolen; attacker issues fraudulent agent certificates |
| **Mitigation** | CA key stored only in environment config (never in the database or repository); development CA generated locally and excluded from version control; production CA key should be in an HSM or KMS |
| **Secret handling** | `AGENT_CA_KEY_PATH` and `AGENT_CA_KEY_PASSWORD` are `SecretStr` fields; never logged or returned by API |
| **Residual risk** | Development CA key may be generated on developer machines; rotation procedure is not yet documented |
| **Response** | Revoke all issued agent certificates; regenerate CA; re-enroll all agents |

---

### T5 — Prompt injection and data exfiltration via AI

| Attribute | Detail |
|---|---|
| **Threat** | A malicious user crafts a RAG query that causes the LLM to exfiltrate cross-tenant records, bypass grounding, or execute unauthorized actions |
| **Mitigation** | RAG retrieval is filtered by `tenant_id`; the AI layer cannot approve or execute automation; no tool-use or code execution capability is exposed to the LLM; ungrounded responses are labelled `unverified` rather than generated freely |
| **Residual risk** | Prompt injection into the LLM context via malicious source data (e.g., a CVE description containing adversarial instructions) is not currently filtered; this is a known open risk |
| **LLM_BASE_URL** | Can be pointed at a self-hosted gateway to prevent intelligence data from leaving the organization's infrastructure |

---

### T6 — Unapproved automation dispatch

| Attribute | Detail |
|---|---|
| **Threat** | An AI output or alert signal triggers a connector delivery or endpoint command without analyst approval |
| **Mitigation** | All automation runs start in `proposed` state; dispatch requires explicit authorized approval; AI cannot approve its own outputs; approval is an audited event |
| **Residual risk** | Approval bypass is possible if an `admin`-scoped key is used improperly; separation of duties is not yet enforced at the role level |
| **Planned hardening** | User/role identity layer (Phase C/D) will enforce that approver ≠ proposer |

---

### T7 — Connector credential leakage

| Attribute | Detail |
|---|---|
| **Threat** | Slack webhook URL, Jira token, or SIEM token is committed to the repository or logged |
| **Mitigation** | All connector credentials are `SecretStr` fields; they are never returned by API responses; never logged by `structlog` (Pydantic `SecretStr` redacts on `repr`); `.env` is in `.gitignore` |
| **Constraint** | Connector must only be enabled when credentials and target policy are approved |
| **Response** | Rotate any credential that appears in repository history or log files before enabling the connector |

---

### T8 — Secret committed to repository

| Attribute | Detail |
|---|---|
| **Threat** | A developer accidentally commits an API key, webhook URL, or certificate key |
| **Mitigation** | `.gitignore` excludes `.env`, `certs/`, and common secret file patterns; documentation explicitly warns; all secret fields use `SecretStr` |
| **Residual risk** | No automated pre-commit secret scanning is currently enforced |
| **Response** | Rotate the credential immediately; use `git filter-repo` to purge from history; notify affected parties |

---

### T9 — Dead-letter replay abuse

| Attribute | Detail |
|---|---|
| **Threat** | An attacker replays dead-letter connector delivery records to re-trigger external actions |
| **Mitigation** | Dead-letter replay requires authorized scope (planned: `admin` minimum); idempotency keys prevent duplicate external delivery for the same outbox record |
| **Status** | Outbox and dead-letter features are in review (PR #11); not yet integrated |

---

### T10 — Ingestion of malicious source data

| Attribute | Detail |
|---|---|
| **Threat** | A compromised feed injects fabricated CVEs, IOCs, or threat actor records into the platform |
| **Mitigation** | Source health is tracked; degraded feeds are visible; each record carries source provenance; multi-source deduplication means a single rogue feed cannot overwrite records confirmed by other sources |
| **Residual risk** | No cryptographic feed verification (e.g., signed TAXII bundles) is currently implemented |

---

## Secret handling summary

| Secret | Storage | Rotation trigger |
|---|---|---|
| API key plaintext | Never stored; shown once at creation | On suspicion of compromise |
| API key hash | Argon2id in `api_keys.secret_hash` | Automatic on revocation + re-issue |
| Agent CA key | Environment config / HSM (production) | On CA compromise |
| Agent certificate | Issued to agent; not stored by server | On `cert_expires_at` or revocation |
| LLM API key | Environment config | On suspicion of compromise |
| Connector credentials | Environment config | On suspicion of compromise or rotation policy |
| Database password | Environment config | On suspicion of compromise |

**Rule:** No secret may appear in: source code, migration files, test fixtures, log output, or API responses.

---

## Tenant isolation checklist

- [ ] Every tenant-owned ORM query has `.where(Model.tenant_id == principal.tenant_id)`
- [ ] No query omits the tenant filter "for convenience"
- [ ] Cross-tenant resource requests return 404, not 403 (prevents existence oracle)
- [ ] Audit log entries include `tenant_id` for all tenant-scoped actions
- [ ] Document chunk retrieval is tenant-filtered for RAG (`tenant_id = NULL OR tenant_id = principal.tenant_id`)

---

## AI authorization boundary

| Action | AI can do | AI cannot do |
|---|---|---|
| Answer questions from platform data | ✓ | |
| Produce cited reports | ✓ | |
| Generate an ungrounded response | | ✗ — must label as unverified |
| Approve a playbook run | | ✗ |
| Dispatch a connector action | | ✗ |
| Create or close a case without approval | | ✗ |
| Execute an endpoint command | | ✗ |
| Access another tenant's records | | ✗ |
