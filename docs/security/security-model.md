# Security Model

## Credentials and secrets

- Store API-key digests with Argon2id; only display a plaintext key at creation time.
- Store connector credentials only in environment-backed secret configuration.
- Never commit tokens, webhook URLs, provider keys, certificates, or test secrets.
- Rotate any credential exposed in repository history before development deployment.

## Endpoint security

Endpoint enrollment and future command delivery use mTLS. Command execution must additionally enforce signing, policy checks, expiry, idempotency, and approval.

## AI safety

- Retrieve platform evidence before generating factual analyst claims.
- Persist citations with generated briefs/reports.
- If evidence is absent, return an explicitly unverified response rather than inventing facts.
- AI cannot autonomously approve, dispatch, or execute destructive actions.

## Audit requirements

Persist material mutations: API-key lifecycle, rule changes, case changes, approval decisions, automation delivery, and AI-generated records. Audit logs must identify actor type, resource type, action, timestamp, and relevant detail.
