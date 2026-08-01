# Feature Catalog

Status meanings: **Integrated** is part of the unified code path; **In progress** exists on active implementation branches but still needs integration; **Planned** is approved direction; **Deferred** is intentionally later.

| Capability | Status | Notes |
|---|---|---|
| Tenant-scoped API keys, scopes, Argon2id hashing | Integrated foundation | Scope controls must remain enforced per endpoint. |
| CTI ingestion and normalization | Integrated foundation | Provenance and source health remain required. |
| Asset inventory, vulnerability and exposure context | Integrated foundation | Endpoint telemetry enriches asset context. |
| Endpoint enrollment and heartbeat | Integrated foundation | Windows/Linux/macOS agent direction remains planned. |
| Grounded RAG chat and report generation | Integrated foundation | Citations required; no supporting evidence means unverified/withheld. |
| Intelligence Explorer search | In progress | Vulnerabilities, indicators, actors, victims, assets. |
| Actor and IOC detail | In progress | Null verdict must remain unenriched, not clean. |
| Campaign and malware intelligence | In progress | Supports evidence-bearing and disputed attribution. |
| Investigation, cases, tasks, timeline | In progress | Tenant-scoped, append-only event history. |
| Alerts and sightings | In progress | Manual intake exists; automatic rule evaluation worker is planned. |
| Correlation and AI analyst brief | In progress | Deterministic scoring; evidence must move server-side. |
| Approval-first automation | In progress | Runs begin proposed; high-risk endpoint commands need stronger identity separation. |
| Slack, Jira, SIEM connector delivery | In progress | Lease/retry reliability fixes prepared; capability/health/replay remain planned. |
| TAXII, STIX, SIEM/SOAR inbound connectors | Planned | Add after integration backbone. |
| ATT&CK coverage and detection content | Planned | Must retain source and version provenance. |
| Go endpoint agent | Planned | mTLS, signing, policy and controlled commands. |
| Production frontend | Planned | Dense professional GravityZone-style design, API-connected states. |
