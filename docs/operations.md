# Operations

## Environments

| Environment | Purpose |
| --- | --- |
| Local | Docker Compose, bundled snapshot, no external connector |
| Development | Shared database, connectors optional and gated by capability checks |
| Production | Full connector configuration, mutual TLS enrollment, rate limiting enforced |

## Configuration

Configuration is environment-driven. An unset connector variable is a valid state: the action reports
as unavailable and is rejected at request time rather than failing later in a worker.

## Validation commands

Run these once the dependency environment is available. They are intentionally deferred while the work
is still code and configuration only.

```bash
pip install -e ".[dev]"
ruff check .
pytest
alembic heads
alembic upgrade head
docker compose up --build
```

Frontend:

```bash
npm install
npm run lint
npm run typecheck
npm run build
```

## Branch workflow

Feature work lands on a topic branch, then rebases onto its parent before merge. Stacked branches merge
bottom-up. When a stacked merge is unavailable, content is pushed directly to the parent branch and the
redundant pull request is closed.
