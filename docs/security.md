# Security Model

## Non-negotiable controls

- API keys are hashed using Argon2id; raw keys are shown only at creation time.
- Every endpoint performs scope and tenant checks.
- Connector credentials are environment-only secrets and must never be logged, committed, or returned by APIs.
- Endpoint commands require mTLS, signing, policy validation, and human approval before dispatch.
- High-impact approvals must evolve to distinct user/role identity; distinct API keys alone are insufficient separation of duties.
- Database writes that trigger external delivery use an outbox with leases, bounded retry, idempotency, receipt persistence, and dead-letter handling.

## AI safety

- AI only summarizes retrieved workspace records and provides citations.
- If no supporting records are retrieved, output is `unverified` or withheld—not invented.
- AI cannot autonomously dispatch endpoint actions, create high-impact tickets, or approve automation.
- Prompts, retrieved evidence, output status, and citations should be auditable.

## Intelligence integrity

- Preserve source identity, collected time, confidence, and transformation history.
- Never translate an absent CVSS or enrichment result into a low score or clean verdict.
- Represent contested attribution as contested.
- Show source outages and stale data rather than implying complete coverage.
