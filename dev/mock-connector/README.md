# Mock connector

A MockServer 5.15 instance standing in for Slack, Jira, and a SIEM webhook so
the automation delivery worker can be exercised locally — including its
failure paths — without contacting a third party.

Salvaged from PR #21, which targets a dead branch and cannot be merged. This
was the only local connector-exercise path that existed anywhere in the
project.

## Running

```bash
docker compose -f docker-compose.yml \
               -f dev/mock-connector/docker-compose.mock.yml up
```

It is a separate overlay on purpose. The development stack should not
silently acquire a fake Slack.

Point the connector settings at it:

```bash
SLACK_WEBHOOK_URL=http://mock-connector:1080/mock/slack/webhook
JIRA_BASE_URL=http://mock-connector:1080/mock/jira
SIEM_WEBHOOK_URL=http://mock-connector:1080/mock/siem/events
```

## Forcing failures

Each endpoint has two expectations. The **first match wins**, so a request
carrying the failure header gets the failure response; everything else gets
the success response.

| Endpoint | Default | Send this header to fail |
|---|---|---|
| `POST /mock/slack/webhook` | `200 ok` | `X-Mock-Status: 503` |
| `POST /mock/jira/rest/api/3/issue` | `201` with `TEST-1` | `X-Mock-Status: 400` |
| `POST /mock/siem/events` | `200 accepted` | `X-Mock-Status: 503` |

The two failure shapes are different on purpose:

- **503** is retryable. Use it to watch `retry_delay` back off
  (30s, 60s, 120s … capped at 3600s) and to confirm an item reaches
  `dead_letter` after `connector_max_attempts`.
- **400** is a client error. A malformed Jira request will never succeed, so
  it should go terminal rather than consume the whole attempt budget.

## What this does not prove

A connector that delivers successfully here has been shown to speak HTTP to a
service that always says yes. It has **not** been shown to work against Slack,
Jira, or a real SIEM — not their auth, rate limits, payload validation, or
error vocabulary.

Connector health showing `delivered` against this overlay means the mock
answered. Do not read it as estate health, and never enable this overlay in a
deployed environment.

## Not ported from PR #21

The 48-test dev validation harness (`test_health.py`, `test_tenant_safety.py`,
`test_rag_citations.py`, `test_outbox.py`) requires a running stack. Nothing in
this repository has ever been started, so those tests cannot be honestly
landed as passing gates yet. They belong with the dev-environment work.
