# Engineering Roadmap

## Current execution order

### 1. Integration backbone — P0
- [ ] Merge the schema/router/migration consolidation after review.
- [ ] Rebase/reconcile feature PRs into one compatible implementation stack.
- [ ] Expand API route contract to every public endpoint family.
- [ ] Verify one Alembic head and upgrade path.

### 2. Detection and correlation reliability — P1
- [ ] Build deterministic alert evaluation worker.
- [ ] Enforce cooldown and auditable rule execution.
- [ ] Resolve correlation evidence from platform records server-side.
- [ ] Add scoring and tenant-isolation regression tests.
- [ ] Add audit events for AI generation and critical workflow actions.

### 3. Automation delivery platform — P1
- [ ] Connector capability registry and validation.
- [ ] Connector health, metrics, and delivery observability.
- [ ] Dead-letter browse/replay API with idempotency safeguards.
- [ ] Internal `case.create` and `report.generate` workers.
- [ ] User/role-based approval identities.

### 4. Endpoint response controls — P2
- [ ] Signed, policy-controlled endpoint command request model.
- [ ] mTLS command channel and command receipts.
- [ ] Windows, Linux, macOS agent implementation.

### 5. CTI product expansion — P2
- [ ] Intelligence Requirements and collection management.
- [ ] Data-quality/quarantine work queues.
- [ ] Import workbench.
- [ ] MITRE ATT&CK coverage and detection content.
- [ ] TAXII and inbound SIEM/SOAR integrations.

### 6. Experience and release — P3
- [ ] Next.js frontend implementing GravityZone-style professional interface.
- [ ] API-connected loading, empty, partial-data, provenance, and error states.
- [ ] Development validation, performance/security review, and controlled production rollout.

## Deferred until validation

No production claim, customer onboarding, or endpoint command execution should occur before the development validation gate passes.