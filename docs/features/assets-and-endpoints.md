# Assets & Endpoints

## Purpose

Connect threat intelligence to the assets that create real organizational exposure.

## Scope

Asset inventory, installed software, vulnerability/exposure context, endpoint enrollment, certificate-based identity, and heartbeat/staleness state for Windows, Linux, and macOS.

## Rules

- Assets are tenant-scoped.
- Agent staleness is visible; missing heartbeat is never treated as healthy.
- Exposure score factors remain explainable: criticality, internet exposure, vulnerability/KEV relevance, and observed activity.
- Future commands require signed policy checks and approval; a heartbeat credential alone is insufficient.
