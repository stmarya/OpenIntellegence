# Engineering Standards

---

## Branch and PR expectations

### Branch naming

| Pattern | Use case |
|---|---|
| `feat/<short-description>` | New feature or capability |
| `fix/<short-description>` | Bug fix or correctness improvement |
| `docs/<short-description>` | Documentation-only change |
| `refactor/<short-description>` | Internal restructuring; no behavior change |
| `chore/<short-description>` | Tooling, config, dependency updates |

### PR expectations

- **One concern per PR.** A PR that adds a feature, updates the schema, and refactors a module is three PRs.
- **Clearly state what was validated** in the PR description (see template below). Do not imply validation was done if it was not.
- **Link to the relevant feature specification** and any docs that need updating.
- **Draft PRs** are acceptable for early feedback; mark as ready for review only when validation is complete.
- **Target branch:** feature PRs target `main` or the designated integration branch; do not target another feature branch.

---

## PR description template

```
Workstream:
Status: Not started | In progress | In review | Blocked | Done
Outcome delivered:
Scope changed:
Validation executed:
  - [ ] ruff check . passes
  - [ ] pytest passes
  - [ ] Relevant safety/tenant test cases pass
  - [ ] alembic heads returns one revision (if schema change)
Known limitation / risk:
Next dependency:
Documentation updated:
  - [ ] docs/planning/project-status.md
  - [ ] Relevant feature/data/API/security doc
```

---

## Code review checklist

Reviewers must verify:

### Correctness

- [ ] Business logic matches the feature specification and ADRs
- [ ] All tenant-owned queries include `.where(Model.tenant_id == principal.tenant_id)`
- [ ] No route allows a caller to access or infer another tenant's data
- [ ] Unknown/null states are preserved; no coercion to "safe" defaults
- [ ] Error paths are handled explicitly; no silent swallowing

### Security

- [ ] No secrets, credentials, or sensitive values in code, fixtures, migrations, or documentation
- [ ] New endpoints have scope enforcement via `require_scope`
- [ ] Mutable endpoints (POST/PUT/PATCH/DELETE) require `write` scope minimum
- [ ] AI-related mutations require `report:write` or `write` scope
- [ ] No new dependency added without checking the advisory database

### API

- [ ] New routes registered exactly once in `app/api/v1/router.py`
- [ ] Response model declared as `response_model=` on all routes
- [ ] Pagination (`limit`/`offset`) present on list endpoints
- [ ] Provenance block included in list responses via `build_provenance()`

### Data

- [ ] Schema changes have a corresponding forward Alembic migration
- [ ] Migration uses `server_default` for new non-nullable columns (to avoid lock on existing rows)
- [ ] `alembic heads` returns one revision after the migration is added
- [ ] `docs/data/` is updated for schema changes

### Tests

- [ ] New domain logic has unit tests
- [ ] New route has contract tests (auth, scope, response shape)
- [ ] New tenant-owned route has an isolation test
- [ ] Validation statement in PR description matches tests actually run

### Documentation

- [ ] `docs/planning/project-status.md` updated if workstream state changed
- [ ] Relevant specification doc updated if behavior changed
- [ ] No fabricated test results or unexecuted validation claims

---

## API review checklist

When a new route or schema change is proposed:

- [ ] Path follows `/api/v1/<resource>` naming convention
- [ ] HTTP method matches semantics (GET=read, POST=create, DELETE=remove, PATCH=partial update)
- [ ] `response_model` is a Pydantic schema defined in `app/api/schemas.py`
- [ ] List endpoint returns the `ListResponse[T]` envelope
- [ ] New schema fields are not breaking changes (additive only; no removals without versioning)
- [ ] 404 scope is tenant-relative (does not reveal cross-tenant resource existence)
- [ ] Rate limit headers present in response (automatic via middleware)
- [ ] Breaking change? Document client transition path and versioning decision

---

## Migration rules

1. **Always extend, never rewrite.** Do not modify a migration that has been merged; create a new one.
2. **One head.** After adding a migration, `alembic heads` must return exactly one revision.
3. **Use `server_default`** for new non-nullable columns on existing tables to avoid long-running DDL locks.
4. **Test forward and clean-state paths** before submitting. Run `alembic upgrade head` from a blank database.
5. **No destructive operations** (column drops, type changes) without a safe data migration step and explicit approval.
6. **Do not edit `alembic_version`** in any environment to skip, reorder, or fake a migration.
7. **Migration file names** must use the format `<revision_id>_<short_description>.py`.
8. **Include `down_revision`** correctly; autogenerate may produce incorrect `down_revision` if the environment is not clean.

---

## Documentation update rules

| Change type | Required documentation update |
|---|---|
| New schema table or column | `docs/data/data-dictionary.md`, `docs/data/schema-and-provenance.md`, migration note |
| New or changed API route | `docs/api/endpoint-inventory.md`, `docs/api/api-conventions.md` if conventions change |
| New security control or threat | `docs/security/threat-model.md` |
| New connector | `docs/data/ingestion-normalization.md`, `docs/operations/configuration.md` |
| New worker | `docs/architecture/component-boundaries.md`, `docs/operations/deployment-guide.md` |
| New ADR | `docs/architecture/decision-records.md` (append-only) |
| Workstream state change | `docs/planning/project-status.md` |

**Rule:** A documentation update is not optional when the corresponding rule in this table is satisfied. It is part of the definition of done.

---

## Definition of done

A feature or fix is **Done** when:

- [ ] Code is merged to the target branch (not just submitted as a PR)
- [ ] All required checks have passed (static, unit, contract)
- [ ] Tenant filtering verified for all new tenant-owned operations
- [ ] No secrets in code, fixtures, migrations, or documentation
- [ ] Unknown/unverified/stale data states are explicit; none coerced
- [ ] New routes registered in `router.py` and covered by contract tests
- [ ] Schema changes have a forward migration with single Alembic head
- [ ] Documentation updated per the documentation update rules above
- [ ] `docs/planning/project-status.md` reflects the new state
- [ ] PR description states validation actually executed and any known limitation

A PR that is merged but has an open known issue is not **Done**; it is **In review with known limitation**. Update the project status tracker accordingly.

---

## Commit message conventions

```
<type>(<scope>): <short summary>

<optional body: what and why, not how>
```

| Type | Usage |
|---|---|
| `feat` | New feature |
| `fix` | Bug fix |
| `docs` | Documentation only |
| `refactor` | Refactoring; no behavior change |
| `test` | Test additions or modifications |
| `chore` | Build, config, tooling |
| `security` | Security fix or hardening |

**Examples:**

```
feat(ingest): add OTX pulse normalization
fix(assets): add missing tenant_id filter on exposure query
docs(api): document endpoint inventory and idempotency semantics
security(auth): enforce scope escalation check in key creation
```
