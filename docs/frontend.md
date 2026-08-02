# Frontend

Next.js App Router, dark operator console, dense information design.

## Design tokens

| Token | Value |
| --- | --- |
| Surface | `#0E1014` |
| Sidebar | `#0A0C0F` |
| Panel | `#171A20` |
| Accent | `#16A9A0` |
| Base type | 13px |
| Radius | 4px |
| Motion | 120ms, disabled under reduced-motion |

## Shell

`layout.tsx` owns the topbar, sidebar navigation, and tenant scope indicator. Route files render content
only and must not re-declare the shell.

## Shared components

| Component | Responsibility |
| --- | --- |
| `RiskBadge` | Risk tier where unknown is never clean |
| `StatusChip` | Neutral, pending, approved, blocked, unknown states |
| `DataTable` | Typed table with empty-state handling |
| `ProvenancePanel` | Source, commit, snapshot disclosure |
| `ApprovalTimeline` | Approval history without dispatch affordance |
| `States` | Demo banner, tenant scope, empty, loading, error, feature gate |
| `UnavailableState` | Route placeholder for capabilities without tenant data |

## Data boundary

Pages never inline entity arrays. Source-backed pages read from repositories over the pinned snapshot;
live pages read from the typed API client using `NEXT_PUBLIC_API_BASE_URL`. Browser code never receives
or constructs a platform API key.
