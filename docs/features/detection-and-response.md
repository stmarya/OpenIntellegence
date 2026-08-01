# Detection, Correlation & Response

## Alerting

Rules define intent; an evaluator worker performs execution. Alerts use a per-tenant fingerprint to aggregate identical occurrences during the cooldown window. Concurrent intake must update the existing alert rather than fail or duplicate it.

## Correlation

Risk scoring combines deterministic factors such as CVSS, KEV, exploit evidence, asset criticality, exposure, sightings, and ransomware relevance. The target design resolves facts server-side and retains the evidence/factor breakdown.

## Automation

Playbooks are declarative. Runs begin `proposed`, then become dispatchable only after approval. Outbox delivery is idempotent, leased, retry-aware, auditable, and dead-lettered on terminal failure.
