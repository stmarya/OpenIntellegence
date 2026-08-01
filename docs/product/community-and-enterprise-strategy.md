# Community-to-Enterprise Product Strategy

## Product statement

OpenIntelligence is one cyber threat intelligence platform that connects community threat sharing with organization-specific assets, telemetry, investigation, and controlled response.

It is **not** two disconnected products. The same intelligence core serves both audiences, while private organization context is always isolated.

## Audience outcomes

### Community

Community users need fast access to actionable intelligence and safe collaboration.

- Share IOC, CVE, malware, campaign, actor, victim, and TTP intelligence.
- Publish cited advisories and AI-assisted reports.
- Build sector, region, campaign, and research collections.
- Contribute data through reviewable states: `draft`, `pending_review`, `verified`, `disputed`, `deprecated`.
- Use STIX/TAXII, webhooks, and community integrations in future iterations.

### Enterprise

Enterprise users need internal relevance, auditability, and controlled action.

- Map external intelligence to tenant-owned assets, software, exposure, and endpoint signals.
- Prioritize explainable risk using CVSS, KEV, exploit evidence, criticality, exposure, sightings, and ransomware relevance.
- Investigate through cases, tasks, evidence, SLA context, and append-only timelines.
- Use approval-first automation for reports, cases, Slack, Jira, SIEM, and future endpoint workflows.
- Retain audit, provenance, secret-management, and tenant-isolation guarantees.

## Data boundary

```text
Community/public intelligence → may enrich enterprise analysis
Enterprise/private data       → must never be shared outward automatically
```

Enterprise-to-community sharing is an explicit export workflow that must support review, redaction, and provenance. It must never be an implicit side effect of ingestion, correlation, AI generation, automation, or reporting.

## Shared intelligence contract

Every claim must preserve source, source record reference when available, observed/published/ingested time, confidence, enrichment/review status, and unknown/partial state. Unknown CVSS is not `0`; an unenriched IOC is not clean; disputed attribution is not certain.

## Differentiators

1. **Community-to-enterprise bridge:** public/community intelligence gains operational context without exposing organization data.
2. **Provenance-first:** analysts see where intelligence came from and how reliable/complete it is.
3. **Asset-aware prioritization:** threat relevance depends on actual enterprise exposure, not a generic feed score.
4. **Grounded AI:** AI generates cited analysis and withholds unsupported factual claims.
5. **Explainable correlation:** scoring persists factor breakdown and evidence.
6. **Approval-first response:** automation proposes, analysts approve, workers deliver auditable results.
7. **Progressive adoption:** communities can start with sharing/reports; enterprises can layer in agents, automation, and governance.

## Delivery tracks

| Track | Near-term scope | Later scope |
|---|---|---|
| Community | Intelligence explorer, reports, collections, contributor/review states | STIX/TAXII distribution, sharing/redaction workflow, community connectors |
| Enterprise | Assets, endpoint visibility, correlation, cases, alerts, approval-first orchestration | Identity/RBAC/SSO, compliance controls, production endpoint command delivery |

## Guardrails

- Identity/RBAC/login/SSO are deliberately deferred, but API-key scopes and tenant isolation remain mandatory.
- Community data quality/review and enterprise governance are complementary; neither may weaken provenance.
- Automation and AI must not publish or execute high-impact actions autonomously.
- A feature is only marked ready after integration, review, and required validation—not when a draft PR exists.
