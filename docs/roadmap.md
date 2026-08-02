# Roadmap and status

## P0 — foundation (merged)

Schema and migrations, source normalization, REST `/api/v1`, agent gateway groundwork, API key service
with authentication and rate limiting, initial AI layer.

## Batch A — detection and correlation remediation (code complete)

Tenant-filtered bounded rule evaluation, cooldown and fingerprint idempotency, evidence resolver limits,
feed health without operational leakage, unknown CVSS preserved, AI withholding behavior test.

## Batch B — automation reliability and endpoint request control (code complete)

Capability gating wired into creation, proposal, and dispatch; 422 before persistence; internal action
separation; endpoint intents excluded from automation; delivery worker action ownership; dead-letter
replay with fresh idempotency; capability and ownership contract tests.

## Batch C — frontend (code complete)

Global shell, fourteen routes, shared component library, safe empty and unavailable states, typed API
boundary, snapshot-backed repositories, control-plane-only endpoint intent surface.

## Next

1. Rebase and merge the branch chains into `main`.
2. Dependency install and full validation sweep.
3. Test expansion beyond contract level.
4. Connector configuration for development, then production hardening.
