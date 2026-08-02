# Security and tenancy

## Tenant isolation

Applies to every lookup, creation, worker claim, replay, command request, and AI retrieval. There is no
supported path that reads across tenants.

## Credentials

- Connector secrets live in server configuration only.
- API keys are hashed at rest, scoped, revocable, and shown once at creation.
- Capability and health responses expose availability and delivery mode, never secret material.

## Query safety

Rule evaluation and evidence resolution are bounded (`MAX_RULE_RESULTS = 100`,
`MAX_EVIDENCE_ROWS = 100`) so a single tenant cannot exhaust worker capacity.

## Idempotency

Alerts deduplicate on fingerprint with an integrity-error fallback. Delivery and replay carry
idempotency keys so retries cannot duplicate an external side effect.

## Safety invariants

```
Unknown CVSS is None, never 0.0.
Unknown values must not become false or zero.
Provenance is mandatory.
An unenriched indicator is visible, never clean.
AI must cite retrieved platform facts and never invent facts.
AI cannot autonomously execute risky actions.
Tenant isolation applies everywhere.
No endpoint command execution or delivery.
No LLM-generated report body in the internal report worker.
Sample corpus is not live tenant data.
```
