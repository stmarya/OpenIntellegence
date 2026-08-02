# Detection and Response — Correlation Evidence Resolution

> **Status:** Feature work — pending integration and validation against a live
> database.  The service and API are implemented and unit-tested; end-to-end
> validation against PostgreSQL and a populated dataset has not been performed.

---

## Overview

Correlation evaluation previously accepted all scoring factors directly from
the API caller.  That design allowed untrusted values (e.g. a manipulated CVSS
score) to drive risk decisions.  This feature replaces that model with
**server-side evidence resolution**: the backend resolves every scoring factor
from persisted platform records, and clients supply only entity identity plus
optional analyst notes.

---

## Resolved factors

| Factor | Source table | Notes |
|---|---|---|
| `cvss_score` | `vulnerabilities` | `NULL` when NVD has not scored the CVE — never coerced to 0 |
| `is_kev` | `vulnerabilities` | Set by the CISA KEV feed ingest |
| `exploit_maturity` | `vulnerabilities` | Worst maturity across all ingested exploits |
| `asset_criticality` | `assets` (tenant-scoped) | Highest-criticality asset exposed to this CVE |
| `internet_exposed` | `assets` (tenant-scoped) | `ip_address IS NOT NULL` proxy; dedicated flag planned |
| `sighting_count` | `sightings` (tenant-scoped) | Count of matching entity sightings in tenant |
| `ransomware_relevant` | `ransomware_victims` | Platform-level signal: victims exist in workspace |

### Resolution status

Every correlation record carries a `resolution_status` value:

| Value | Meaning |
|---|---|
| `resolved` | All key scoring fields found in platform records |
| `partial` | Some fields resolved; others unknown (null, not zero) |
| `manual_input` | Caller supplied values directly (requires `admin` scope) |
| `unavailable` | No matching platform records for this entity |

**Unknown values remain `null`** in the evidence snapshot.  A null field means
*"not assessed"*, never *"absent/clean"*.  A UI must render null as an em-dash,
not as 0.

---

## API contract

### `POST /api/v1/correlations/evaluate`

**Scope required:** `write`

**Request body:**

```json
{
  "title": "CVE-2024-1234 on critical assets",
  "primary_entity_type": "vulnerability",
  "primary_entity_id": "CVE-2024-1234",
  "notes": "Analyst confirmed exploitation in staging."
}
```

The following fields from the old contract are **removed** and must not be
supplied by clients:

- `cvss_score`, `is_kev`, `exploit_maturity`
- `asset_criticality`, `internet_exposed`
- `sighting_count`, `ransomware_relevant`, `source_refs`

Supplying any of these fields will result in a validation error.

**Manual evidence override (development / analyst mode):**

Requires `admin` scope.  Use sparingly; the result is clearly labelled.

```json
{
  "title": "Manual override for CVE-2024-1234",
  "primary_entity_type": "vulnerability",
  "primary_entity_id": "CVE-2024-1234",
  "notes": "Pre-production environment assessment.",
  "manual_evidence": {
    "cvss_score": 9.5,
    "is_kev": true,
    "asset_criticality": "critical"
  }
}
```

When `manual_evidence` is provided:
- The result's `resolution_status` is always `manual_input`.
- Supplied values are forwarded to the scorer and preserved in
  `manual_evidence` in the stored record.
- They are **never** blended with source-resolved evidence.
- The response will never show `resolved` or `partial` for a manual assessment.

**Response body:**

```json
{
  "id": "...",
  "title": "...",
  "primary_entity_type": "vulnerability",
  "primary_entity_id": "CVE-2024-1234",
  "evidence": {
    "entity_type": "vulnerability",
    "entity_id": "CVE-2024-1234",
    "cvss_score": 9.8,
    "is_kev": true,
    "exploit_maturity": "weaponized",
    "asset_criticality": "critical",
    "internet_exposed": true,
    "sighting_count": 2,
    "ransomware_relevant": true,
    "source_refs": [
      {"type": "vulnerability", "id": "...", "source": "nvd"},
      {"type": "asset", "id": "...", "tenant_id": "..."}
    ],
    "resolution_status": "resolved",
    "resolved_fields": ["cvss_score", "is_kev", ...],
    "unresolved_fields": []
  },
  "factor_breakdown": [...],
  "risk_score": 95,
  "risk_tier": "critical",
  "resolution_status": "resolved",
  "automation_candidates": [...],
  "evaluated_at": "..."
}
```

---

## Tenant isolation

Every evidence lookup is scoped to the authenticated caller's `tenant_id`:

- Asset lookups filter `Asset.tenant_id == principal.tenant_id`.
- Sighting counts filter `Sighting.tenant_id == principal.tenant_id`.
- A caller cannot resolve assets, sightings, or correlations belonging to
  another tenant.
- A 404 is returned for unknown correlations in the same way as for
  correlations belonging to a different tenant — the responses are
  indistinguishable.

---

## AI brief generation

`POST /api/v1/correlations/{id}/ai-brief` uses the **persisted** resolved
evidence snapshot stored at evaluation time, not re-resolved facts.  This
guarantees that the brief reflects what was true when the correlation was
created, not what may have changed since.

The brief is labelled `unverified` when:
- No workspace records were retrieved by the RAG query.
- The resolution status is `unavailable`.

The brief prompt explicitly notes when `resolution_status` is `partial` or
`manual_input` so the model can flag gaps in its output.

---

## Known limitations / pending work

- `internet_exposed` uses `ip_address IS NOT NULL` as a proxy.  A dedicated
  boolean flag or network zone tagging would be more precise.
- `ransomware_relevant` is a platform-level signal (any victims exist),
  not entity-specific.  CVE-to-ransomware-group toolchain mapping requires
  additional intelligence data not yet in the schema.
- End-to-end integration tests against a live PostgreSQL database with
  populated vulnerability, asset and sighting records have not been run.
