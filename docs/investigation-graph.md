# CTI Investigation Graph

The Investigation Graph is a visual read surface over persisted typed relationships. It is intentionally not a freeform source of intelligence truth.

## API

```http
GET /api/v1/graph/traverse?entity_type=indicator&entity_id=example.org&depth=2
```

Optional filters:

- `depth`: 1–3 hops; defaults to 2.
- `max_edges`: 1–500; defaults to 200.
- `relationship_types`: comma-separated exact relationship types.
- `min_confidence`: 0–1. Unknown confidence remains visible only when the threshold is 0.

The response contains stable node keys, typed edges, confidence, evidence, sources, validity windows, truncation state, and an explicit `persisted_typed_relationships` basis.

## Safety and truth boundaries

- Tenant-scoped relationships and global reference relationships are readable; another tenant's relationships are not.
- The seed is returned even when it has no known edge, so an empty graph is not misrepresented as an outage.
- No model-generated edge is included.
- A relationship remains evidence, not automatic incident confirmation.
- Visual position is presentation state and never changes the intelligence relationship.
- Traversal is capped at three hops and 500 edges to protect the API and browser.

## Frontend workflow

The `/graph` page accepts an entity type and identifier, renders a deterministic visual layout, supports node selection and evidence inspection, allows pivoting from any discovered node, filters entity and relationship types, re-centres the graph, and exports SVG or complete evidence JSON. A local snapshot stores only presentation references in the browser. The page states when the API is unavailable, the result is empty, or the response was truncated.

## Development fixture

After migrations and tenant bootstrap, seed a small, connected, labelled test graph:

```bash
docker compose exec api python -m app.cli.seed_graph_demo \
  --tenant-slug YOUR_TENANT_SLUG \
  --confirm-synthetic
```

Then open:

```text
http://localhost:3000/graph?entity_type=campaign&entity_id=synthetic-campaign-night-glass&depth=3
```

The command is idempotent, refuses to run when `ENVIRONMENT=production`, and marks every edge with:

```json
{
  "fixture_kind": "synthetic_test_only",
  "note": "Synthetic graph evidence for development testing; not tenant telemetry."
}
```

It never creates a tenant and never creates credentials.

## Verification checklist

```bash
python -m compileall -q app tests alembic
ruff check app tests
pytest -q
cd frontend
npm install
npm run lint
npm run type-check
npm run test:ci
npm run build
```

Runtime and CI success must be reported only from observable command or check output.
