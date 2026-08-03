# Frontend

Next.js 14 App Router, dark operator console, dense information design. Every
route is a **server component**; there is no client-side data fetching except in
`SideNav` (active-route highlighting) and `GroundedChat`.

## Design tokens

| Token | Value |
| --- | --- |
| Surface | `#0E1014` |
| Sidebar | `#0A0C0F` |
| Panel | `#171A20` |
| Edge | `#2A3039` |
| Accent | `#16A9A0` |
| Base type | 13px / 1.45 |
| Radius | 4px |
| Motion | 120ms, disabled under reduced-motion |

Severity: critical `#D6383D`, high `#E06C34`, medium `#D9A036`, low `#4B92D6`.
The sidebar collapses below 720px.

## Shell

`layout.tsx` owns the topbar, sidebar navigation, and tenant scope indicator.
Route files render content only and must not re-declare the shell. Every route
declares `export const dynamic = 'force-dynamic'`.

## Shared components

| Component | Responsibility |
| --- | --- |
| `SideNav` | Seven navigation groups, active route via `usePathname` |
| `DataTable` | Typed table with an explicit empty label |
| `ResourceTable` | `DataTable` plus outcome, empty, note and pagination handling |
| `DetailShell` | Back link, title, intro and outcome wrapper for detail routes |
| `FieldTable` | Label/value pairs for detail records |
| `TabNav` | Tab strip driven by `?tab=`, resolved through `resolveTab` |
| `Pagination` | Offset paging, discloses `has_more` and unknown totals |
| `MetricCards` | Headline figures, each carrying its own basis string |
| `RiskBadge` | Risk tier where unknown is never clean |
| `StatusChip` | Neutral, pending, approved, blocked, unknown |
| `States` | Demo banner, tenant scope, empty, loading, error, feature gate |
| `GroundedChat` | Posts to `/chat/query`; withholds uncited answers |

## Data boundary

Pages never inline entity arrays.

Live routes read through `frontend/src/lib/server-fetch.ts`, which resolves
`API_BASE_URL` (absolute, server only) before
`NEXT_PUBLIC_API_BASE_URL`. A non-absolute base URL makes every fetch return
`unavailable` **without issuing a request**, so a misconfigured console reports
itself as unconfigured rather than as an empty estate. A 401 or 403 becomes
`unavailable` with an entitlement message, never a silent empty list.

```ts
type FetchOutcome<T> = { status: 'ok'; data: T } | { status: 'unavailable'; reason: string }
```

Use `fetchList` only for endpoints that return the `ListResponse` envelope. Use
`fetchJson` for the endpoints that return a bare object — see `docs/api.md` for
the list. Choosing wrongly produces a permanently empty table that is
indistinguishable from a genuine empty state, and neither TypeScript nor the
runtime will flag it.

`totalOf` returns `null` rather than `0` for an unverified figure, so a metric
with no value renders "Unavailable".

Source-backed pages (`/research`, `/data-quality`) read the pinned OTX snapshot
through `frontend/src/data/repositories/intelligence-repository.ts`. That corpus
is labelled and is not tenant data.

Browser code never receives or constructs a platform API key.

## Route surface

39 top-level route directories, 14 nested detail routes, and a root redirect to
`/overview`. All 31 information-architecture surfaces exist.

## Page contract

- A tab that could only ever be empty is not rendered; its absence is explained in prose.
- A route with no backend endpoint keeps a gate naming the missing endpoint.
- No inert buttons: the console holds no write scope, so read-only surfaces say the write action is unavailable rather than showing a disabled control.
- A list and its detail view read the same endpoint; a detail page never reuses a stale row from a list response.
- Every derived relationship states its matching basis.
