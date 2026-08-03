# Priorities 1–10 implementation map

This change deliberately uses labelled synthetic fixtures only under `tests/fixtures`. It does not inject fabricated tenant telemetry into runtime pages.

1. **Identity and RBAC:** persisted users, roles, assignments, sessions, tenant uniqueness, scope validation, and access APIs. Interactive OIDC/SAML remains a separate authentication ceremony.
2. **Endpoint lifecycle:** mTLS enrollment, cross-platform inventory, heartbeat, bounded polling, nonce replay memory, and the single non-destructive `collect_inventory` command.
3. **Knowledge graph:** typed relationship evidence, confidence, validity windows, revision snapshots, and entity relationship/history APIs.
4. **Search:** tenant-aware database search and saved searches. OpenSearch remains an optional future adapter rather than a falsely healthy dependency.
5. **Ingestion operations:** connector checkpoints are persisted. Exact record replay is withheld until each connector exposes a deterministic raw-record normalizer.
6. **Write workflows:** existing allowlisted action gateway plus typed APIs for users, roles, relationships, saved searches, AI evaluations, and detection rules.
7. **AI governance:** citation postconditions, evaluation persistence, reference-recall scoring, and synthetic evaluation fixtures.
8. **Detection engineering:** versioned Sigma, YARA, Suricata, and Snort rule storage with validation metadata and ATT&CK mappings.
9. **Operations:** request correlation, low-cardinality metrics, non-leaking readiness, backup checksums, guarded restore, and explicit runtime boundaries.
10. **Supply chain:** Dependabot, CycloneDX backend inventory, frontend dependency export, container build, and Trivy high/critical gate.

## Safety decisions

- No mock data is shown as tenant data.
- No destructive endpoint command is enabled.
- No arbitrary proxy path or arbitrary shell action is introduced.
- No readiness response returns internal exception text.
- A backup command does not claim restore success; restoration requires a separate guarded command and application-level checks.
- Search results disclose their substring/database basis and do not claim semantic or OpenSearch ranking.
