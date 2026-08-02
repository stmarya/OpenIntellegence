# Ingestion and normalization

## Pinned source corpus

The development corpus is pinned to a specific upstream commit so results are reproducible.

| File | Content |
| --- | --- |
| `cisa_kev_3months.json` | Known exploited vulnerabilities |
| `nvd_api_3months.json` | CVE records and scoring |
| `github_poc_3months.json` | Unverified research references |
| `threat_actors_last_30_days.json` | Threat actor activity |

These are historical snapshots. They are labelled as such everywhere they surface and must never be
presented as live tenant telemetry.

## Normalization rules

- Map each source record to a platform entity with an explicit identifier.
- Preserve the original source value alongside the normalized value.
- Missing fields normalize to `None`, never to a default.
- Research references are marked unverified and carry no payload or execution capability.

## Freshness

Every normalized record stores its snapshot label and observation time so the interface can display
freshness rather than implying real-time accuracy.
