# OpenIntellegence documentation

Modular documentation for the OpenIntellegence cyber threat intelligence platform.
Each document is self-contained so it can be revised without rewriting the whole set.

| Document | Scope |
| --- | --- |
| [architecture.md](architecture.md) | System decomposition, services, data flow |
| [data-model.md](data-model.md) | Core entities, tenancy, provenance columns |
| [ingestion.md](ingestion.md) | Source corpus, normalization, freshness |
| [api.md](api.md) | REST surface, authentication, error contract |
| [agent-and-assets.md](agent-and-assets.md) | Endpoint agent, enrollment, asset inventory |
| [automation.md](automation.md) | Playbooks, capability gating, delivery, replay |
| [endpoint-intents.md](endpoint-intents.md) | Control-plane request and approval policy |
| [ai-layer.md](ai-layer.md) | Retrieval, grounding, citations, report generation |
| [frontend.md](frontend.md) | Application shell, routes, shared components |
| [security.md](security.md) | Tenant isolation, secrets, safety invariants |
| [operations.md](operations.md) | Environments, configuration, validation commands |
| [roadmap.md](roadmap.md) | Delivery batches and current status |

## Non-negotiable invariants

Every document in this set is subordinate to these rules.

- Unknown values stay unknown. An unknown CVSS is `None`, never `0.0`, and never renders as safe.
- Provenance is mandatory for every intelligence record.
- An unenriched indicator is visible as unenriched, never as clean.
- AI output must cite retrieved platform facts and must never invent them.
- AI can never autonomously execute a risky action.
- Tenant isolation applies to every lookup, write, worker, replay, and command request.
- Sample corpus data is never presented as live tenant telemetry.
