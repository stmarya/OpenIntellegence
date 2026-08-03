# Continuous integration

## What this gate is for

Until this workflow was added, no code in this repository had ever been
compiled or executed. Phases P1 through P5 were reported as complete on the
strength of static review alone. `.github/workflows/ci.yml` is the execution
gate that P0 always required and never had.

The honest reading of a red badge on the first runs is not "CI is broken".
It is "this is the accumulated cost of never having run the code". The
failures are the backlog.

## Jobs

### `backend` - Python 3.12

| Step | Command | What it catches |
|---|---|---|
| Install | `pip install -e ".[dev]"` | Unsatisfiable or conflicting dependency pins |
| Compile | `python -m compileall -q app tests alembic` | Syntax errors in modules no test imports |
| Lint | `ruff check app tests` | `E`, `F`, `I`, `UP`, `B`, `SIM` per `pyproject.toml` |
| Test | `pytest -q` | The test modules under `tests/` |

Python 3.12 is a hard floor. `app/api/schemas.py` declares
`class ListResponse[T](BaseModel)`, which is PEP 695 syntax and is a syntax
error on 3.11 and earlier.

The compile step is separate from the test step on purpose. A module can be
unreachable from every test and still be imported at runtime by a router,
so passing tests do not prove the package is syntactically sound.

### `frontend` - Next.js 14

| Step | Command | What it catches |
|---|---|---|
| Install | `npm install --no-audit --no-fund` | Dependency resolution |
| Lint | `npm run lint` | `next lint` |
| Type-check | `npm run type-check` | `tsc --noEmit` across all 53 route surfaces |
| Build | `npm run build` | `next build` |
| Test | `npm run test:ci` | Jest, currently `--passWithNoTests` |

Type-check is the step most likely to fail first. Several defects already
found by manual review were wrong-shape type declarations that TypeScript
would have caught the moment it was run — a `dict` declared as `string[]`,
for example, which made array helpers silently return their fallback.

The build does not require a reachable API. Every route declares
`export const dynamic = 'force-dynamic'`, and `server-fetch` returns an
`unavailable` outcome rather than throwing when `API_BASE_URL` is not an
absolute URL.

`npm install` is used rather than `npm ci` because no `package-lock.json` is
committed. `npm ci` would fail outright without one. The cost is that every
run resolves dependencies afresh, so the frontend job is not reproducible
between runs and neither is the `npm audit` step in the Security workflow.
Committing a lockfile is the fix and is still outstanding.

## Companion workflow: Security

`.github/workflows/security.yml` is a separate gate, documented in full in
[`security-scanning.md`](./security-scanning.md). Three jobs:

| Job | Tool | Scope |
|---|---|---|
| `secrets` | gitleaks 8.21.2 | Every commit reachable from the ref, via `fetch-depth: 0` |
| `python-dependencies` | `pip-audit --strict` | Backend dependency advisories |
| `node-dependencies` | `npm audit --audit-level=high` | Frontend dependency advisories |

It runs on push to `main`, on pull requests, weekly on a schedule, and on
demand. The schedule matters: a dependency that was clean when it merged
becomes vulnerable when an advisory is published, not when the code changes.

None of it requires GitHub Advanced Security, which is **not** enabled on this
repository. That constraint is what shaped the design rather than something
that blocked it.

## Deliberately not included

**The pinned route list from the original CI attempt.** PR #2 shipped a
`tests/test_api_contract.py` that asserted set equality against exactly 26
routes. The API now exposes far more than that, so porting it verbatim would
have produced a failure about the assertion's own staleness rather than about
the code. The route-family contract test already in `tests/` is kept instead.

**A database-backed migration job.** `alembic upgrade head` needs a live
Postgres with pgvector. `tests/test_alembic_lineage.py` already asserts the
revision graph has a single head, which is the failure mode that actually
occurred. A real migration job belongs with the dev-environment work, not
here.

## Outstanding P0 item

One item remains open, and no workflow in this repository can close it.

Credentials for **three providers** — Ransomware.live, AlienVault OTX, and
VulnCheck — were committed in plaintext to the public `NogoSecV3.1.1`
repository, across seven files, and are present on its **default branch head**
rather than only in old history. `SECURITY.md` in that repository carries the
remediation runbook and `scripts/purge-leaked-credentials.sh` performs the
history rewrite.

Rotation is the only step that revokes an attacker's access, and it can only
be performed by the account holder in each provider's console. Rewriting
history reduces retrievability; it does not un-leak anything already taken.
Until all three keys are rotated, this item is open regardless of what the
scanners report here.

## Reading the results

Workflow outcomes are readable only in the GitHub Actions tab. No claim that
CI is passing should be made from any other source, and none is made in this
repository's documentation.

## Rule

Do not add `continue-on-error` to any step, and do not delete a failing test
to pass the gate. A gate that cannot fail measures nothing, and this project
has already spent one full engagement discovering what unmeasured code costs.
