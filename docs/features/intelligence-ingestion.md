# Intelligence Ingestion

## Purpose

Ingest heterogeneous CTI sources and normalize them into queryable, provenance-bearing records without erasing source-specific uncertainty.

## Core entities

Indicators, vulnerabilities, threat actors, ransomware victims, campaigns, malware, source health, documents, and chunks for retrieval.

## Rules

- Normalize identifiers and timestamps but retain raw source references.
- Preserve null/unknown values.
- Deduplicate records using stable source/entity keys; merge evidence rather than overwrite it.
- Source degradation must be observable and eligible for alerting.

## Acceptance criteria

Records expose provenance; ingestion is tenant-safe where applicable; malformed source data is quarantined or marked as partial rather than silently interpreted.
