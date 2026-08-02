# Project Status

---

## Foundation (complete)

| Area | Description |
|---|---|
| Schema and migrations | Alembic chain 0001 – 0008, single-head |
| Ingest pipeline | Connector framework, normalisation, quarantine, provenance |
| API | FastAPI v1 router: vulnerabilities, assets, agents, correlations, AI |
| Authentication | API-key service (Argon2id), scopes, rate limiting |
| Agent gateway | mTLS enrollment and heartbeat |
| Exposure matching | CPE and vendor/product rules, SLA tracking |
| AI layer | RAG chat and six report templates |
| Correlation scoring | Deterministic risk scorer, explainable factor breakdown |

---

## Feature: Server-side correlation evidence resolution (P1)

> **Status:** Implemented and unit-tested.  Pending integration and validation
> against a live database with populated feeds.

### What was delivered

| Requirement | Status |
|---|---|
| Evidence resolver service resolves vuln/KEV/exploit, asset criticality/exposure, IOC sightings, ransomware relevance from DB | ✅ Implemented (`app/services/evidence_resolver.py`) |
| Tenant-scoped lookups; caller cannot correlate another tenant's entities | ✅ Enforced in resolver and API endpoint |
| API contract changed: client supplies entity identity + optional notes only | ✅ Scoring factors removed from `CorrelationEvaluate` |
| Privileged manual override requires `admin` scope; marked `manual_input`; values preserved separately | ✅ Implemented |
| Response includes evidence snapshot with null-preserved unknowns, factor breakdown, resolution status, source refs | ✅ All fields in `CorrelationOut` |
| Resolution status: `resolved` / `partial` / `manual_input` / `unavailable` | ✅ Stored on `correlations.resolution_status` |
| Unknowns remain null, not zero/clean | ✅ `to_snapshot()` preserves None |
| Correlation scoring remains deterministic; unit-tested for all modes | ✅ `tests/test_correlation_scoring.py` (38 tests) |
| AI brief uses persisted resolved evidence; notes resolution status; withheld if no citations | ✅ Prompt updated |
| API contract tests updated | ✅ `tests/test_api_contract.py` |
| Forward-safe migration 0008 | ✅ Additive columns with server defaults |
| Documentation | ✅ `docs/features/detection-and-response.md` |

### Known limitations

- `internet_exposed` uses `ip_address IS NOT NULL` as a proxy. A dedicated
  flag or network-zone table would be more precise.
- `ransomware_relevant` is a platform-level signal (any victims in workspace),
  not entity-specific. CVE-to-ransomware-group mapping requires additional
  intelligence not yet in the schema.
- No integration tests against a live PostgreSQL database. The unit tests
  cover all resolution logic paths using pure dataclass / scorer calls.

---

## Not yet done

| Item | Notes |
|---|---|
| Prefect / Kafka orchestration layer | Connector scheduling, fan-out |
| TAXII 2.1 server | Inbound/outbound structured threat intelligence |
| OpenSearch integration | Full-text search across large corpora |
| Neo4j integration | Graph relationship queries |
| Outbound webhook emitter | Push alerts to SIEM / SOAR |
| Go endpoint agent | Lives in a separate repository |
| `internet_exposed` dedicated flag | Schema extension needed |
| CVE → ransomware-group mapping | Intelligence feed not yet sourced |
| Integration tests for evidence resolution | Requires populated PostgreSQL |
