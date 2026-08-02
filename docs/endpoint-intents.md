# Endpoint intents

Endpoint intents are **requests for approval**, not commands.

## Allowlist

```
isolate_network
collect_inventory
rotate_agent_certificate
```

Free-form commands are not representable in the API or the interface.

## Policy

- The requester can never be an approver.
- Two distinct approvers are required.
- Requests expire and can be cancelled.
- State remains pending and not dispatched regardless of approval outcome.
- Delivery is always null in the current scope.

## Prohibited couplings

- An intent can never create an automation outbox row.
- The connector delivery worker can never observe an intent.
- AI can never create, approve, or advance an intent.
