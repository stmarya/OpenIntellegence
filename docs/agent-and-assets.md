# Endpoint agent and asset management

Supported platforms: Windows, Linux, macOS.

## Enrollment

1. Operator issues a scoped enrollment token for a tenant.
2. Agent presents the token and a certificate signing request.
3. Control plane issues a client certificate bound to the tenant and agent identity.
4. Subsequent traffic uses mutual TLS; the enrollment token cannot be reused.

## Heartbeat and staleness

Agents report on a fixed interval. A missed interval budget marks the asset stale. Stale is an explicit
state, never silently treated as healthy.

## Inventory

Agents report host identity, operating system, patch level, installed software, and network identifiers.
Inventory is additive and versioned so historical posture remains auditable.

## Explicit non-capabilities

The agent has no remote shell, no arbitrary command execution, and no自动 dispatch path. Only allowlisted
intents are representable, and delivery of those intents is out of scope for the current batches.
