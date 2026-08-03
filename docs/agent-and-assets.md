# Endpoint agent and asset management

Supported platforms: Windows, Linux, macOS.

## Enrollment

1. Operator issues a single-use enrollment key scoped to a tenant.
2. Agent presents the key and a certificate signing request to `POST /agents/enroll`.
3. Control plane signs a client certificate bound to the tenant and agent identity.
4. The enrollment key is revoked on success, with `revoked_reason` recording which agent consumed it.
5. Subsequent traffic uses mutual TLS.

The key is burned deliberately. A key that could enroll an unlimited number of
endpoints would, once leaked from a single installer image, let anyone join the
fleet.

## Heartbeat and staleness

Agents check in on a fixed interval via `POST /agents/heartbeat`, authenticated
by the client certificate rather than by an API key. The response reports
certificate expiry and sets `certificate_renewal_due` within 14 days of expiry.

A heartbeat records **last contact, not current health**. An agent shown as
active stopped being verified the moment it last checked in. Stale agents stay
in the fleet list and are reported as stale; an endpoint that stopped reporting
is the one you most need to see, so it is never dropped.

Enrollment count is not reporting count, and the two are never presented as one
figure.

## Inventory

A heartbeat may carry an installed-software inventory. When it does,
`apply_software_inventory` stores it and `recompute_exposure` immediately
rematches that asset against known CVEs.

Each package row keeps `first_seen` and `last_seen`. This answers when a package
appeared and when it was last confirmed — it is **not** a version history, and
the platform cannot reconstruct what a host looked like on an arbitrary past
date.

An absent inventory means nothing was reported, never that no software is
installed.

### Unmatchable software

A package reported without a CPE identifier cannot be matched to CVE data at
all. `GET /agents/{agent_id}/software` therefore reports `unmatched_count`
alongside `count`, and the console shows it, so an exposure figure is read as a
floor rather than as a complete assessment.

Exposure rows record `matched_via`, the join that produced them, so a false
positive can be traced to its rule instead of argued about.

## Read endpoints

| Endpoint | Returns |
| --- | --- |
| `GET /agents` | Fleet list, `ListResponse[AgentOut]` |
| `GET /agents/{agent_id}` | One agent, read fresh, `AgentOut` |
| `GET /agents/{agent_id}/software` | Bare object: `agent_id`, `asset_id`, `count`, `unmatched_count`, `software[]` |
| `GET /assets` | `ListResponse[AssetOut]` with unresolved CVE counts |
| `GET /assets/{asset_id}/exposure` | Asset plus its exposure rows and matching basis |

The single-agent endpoint exists so the detail view never copies
`last_heartbeat_at` out of a list response. That is the field where a stale copy
does the most damage: it is the difference between an endpoint that checked in a
minute ago and one that went quiet an hour ago.

## Explicit non-capabilities

The agent has no remote shell, no arbitrary command execution, and no autonomous
dispatch path. Only allowlisted intents are representable
(`isolate_network`, `collect_inventory`, `rotate_agent_certificate`), and
delivery remains **control-plane only**: `endpoint_command_delivery` reports
`not_implemented`. An approved intent is a recorded decision, not an action
taken on a host.

Intent approval requires two distinct approvers and the requester may not
approve their own request. Elapsed pending intents are moved to `expired` by
`app/workers/intent_expiry_runner.py`, so the approval window closes on a
schedule rather than only when something happens to call the sweep.
