# Automation and orchestration

## Action classes

| Class | Actions | Delivery mode |
| --- | --- | --- |
| Connector | `slack.notify`, `jira.issue.create`, `siem.push` | external connector worker |
| Internal | `case.create`, `report.generate` | internal worker |
| Control plane | `endpoint.command.request` | control plane only, never automation |

## Capability gating

`validate_action(action, settings)` is the single authority.

- Unknown action raises `unsupported_action`.
- Known connector action without configuration raises `action_not_configured`.
- Internal actions never require connector configuration.
- Capability reporting is static. It never probes an external system and never discloses a credential.

Gating runs at playbook creation, run proposal, and dispatch. Invalid steps are rejected with HTTP 422
**before** any run or outbox row is created, so no unreachable work is ever persisted.

## Delivery worker ownership

The connector delivery worker claims only actions that are both connector-class and configured, for
queued, retrying, and abandoned-lease rows alike. It therefore cannot claim, fail, or dead-letter an
internal or control-plane action. With no connector configured it performs no outbox query at all.

## Retry and dead letters

Delivery uses bounded attempts with backoff and lease expiry. Exhausted rows move to dead letters.
Replay is tenant-owned, locked against concurrent replay, and issues a fresh idempotency key so a
replay can never duplicate a delivered side effect.
