# Testing Strategy

## Test layers

| Layer | Purpose | Required examples |
|---|---|---|
| Static | Syntax, lint, import-level quality | `ruff check .` |
| Unit | Deterministic domain behavior | correlation scoring, retry classification, ADF payload |
| Contract | Public API shape and registry | route families, expected status/authorization semantics |
| Persistence | Schema/migration correctness | one Alembic head, critical metadata/constraints |
| Integration | Service behavior with disposable dependencies | Postgres migration, auth/tenant isolation, mock connectors |
| E2E | Analyst workflow | ingest → correlate → case → approval → delivery |

## Mandatory safety cases

- API key with wrong tenant cannot read or mutate another tenant record.
- Read scope cannot perform a mutation or generate stored AI output.
- Concurrent alert intake aggregates by fingerprint.
- Expired outbox lease can recover; active lease cannot be double-claimed.
- AI output with no retrieved support is labelled unverified/withheld.
- Unknown CVSS/IOC state is not converted to safe values.

## Evidence standard

A feature is not “tested” because code compiles. Record command, environment, result, and known limitations in the PR and project status tracker.
