# Configuration & Environment Reference

## Principles

Configuration is environment-owned. Secrets use secret-backed settings and must never be committed, returned by APIs, or stored in automation payloads.

## Connector settings

| Key | Used by | Notes |
|---|---|---|
| `SLACK_WEBHOOK_URL` | Slack delivery | Incoming webhook secret |
| `JIRA_BASE_URL` | Jira delivery | Base Cloud URL, no trailing slash |
| `JIRA_EMAIL` | Jira delivery | Connector identity |
| `JIRA_API_TOKEN` | Jira delivery | Secret; use least privilege |
| `SIEM_WEBHOOK_URL` | SIEM delivery | HTTPS endpoint |
| `SIEM_WEBHOOK_TOKEN` | SIEM delivery | Optional bearer secret |
| `CONNECTOR_DELIVERY_TIMEOUT_SECONDS` | Worker | Bounded client timeout |
| `CONNECTOR_MAX_ATTEMPTS` | Worker | Retry/dead-letter threshold |

## Pre-flight checklist

- Required database and provider settings are present for the environment.
- Connector is explicitly enabled only when credentials and target policy are approved.
- Test webhook/project targets are used before production.
- Secrets are rotated if they appear in history or logs.
