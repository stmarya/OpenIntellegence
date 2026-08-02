# Frontend data contract

## Dataset classes

The frontend uses two explicit data classes:

1. **Bundled sample-data snapshot** — source-derived records stored locally for development. Current source: `stmarya/NogoSecV3.1.1` at commit `c058fa31db917305a42e2205b80d3c21ff4970ed`, directory `API_Testing/OTX/collected_data`.
2. **Synthetic fixture — development only** — deterministic, minimal data used only when no source-derived data or API response exists. It must never be labelled as live telemetry or source-derived data.

Every view model must retain its `provenance`: dataset kind, repository, commit, directory, file and source file SHA. Unknown values remain `null`; they must not become `0`, `false`, or a fabricated value.

## Directory rules

- `src/data/raw/` contains immutable curated snapshots and synthetic fixture files only.
- `src/data/adapters/` contains pure mappers from source records to UI view models.
- `src/data/repositories/` is the only frontend access path for page data. It is the replacement seam for the future typed API client.
- Pages and UI components must not import from `src/data/raw/`, define inline entity arrays, or apply source-specific transformations.

## Current limitations

The bundled data is a historical snapshot, not tenant telemetry and not a live feed. Assets, endpoint requests, tenant alerts/cases, approvals, connector health and AI responses must use an explicit unavailable or empty state unless a backed API response exists.

GitHub research records are displayed as **unverified research references**. The UI must not provide exploit execution, payload generation, or command-delivery interactions.
