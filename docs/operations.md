# Development and Operations

## Local development validation gate

Run only in a development environment with configured dependencies:

```bash
pip install -e ".[dev]"
ruff check .
pytest
alembic upgrade head
docker compose up --build
```

## Required validation

- `/health` and `/health/ready` lifecycle behavior;
- API key authentication, scope boundaries, and tenant isolation;
- fresh migration to head and one Alembic head;
- ingestion/normalization and provenance;
- endpoint enrollment/heartbeat;
- RAG citation and no-citation behavior;
- case/task/timeline operations;
- alert deduplication and alert evaluator behavior;
- deterministic correlation scoring and AI brief authorization;
- approval state transitions;
- outbox lease recovery, retry, receipt, dead letter, and replay;
- mock Slack, Jira, and SIEM delivery.

## Connector configuration

Configuration belongs in environment variables, not repository files:

```text
SLACK_WEBHOOK_URL
JIRA_BASE_URL
JIRA_EMAIL
JIRA_API_TOKEN
SIEM_WEBHOOK_URL
SIEM_WEBHOOK_TOKEN
CONNECTOR_DELIVERY_TIMEOUT_SECONDS
CONNECTOR_MAX_ATTEMPTS
```

## Worker commands

The connector delivery worker is invoked as:

```bash
python -m app.workers.connector_delivery
```

Workers must be deployed independently from the API service. A worker crash must not strand work permanently; expired leases are recoverable.
