# Security and tenancy

## Tenant isolation

Every record that describes a customer's own environment is tenant scoped:
assets, agents, exposure, cases, investigations, alerts, sightings, alert rules,
correlations, endpoint intents, API keys, audit log entries, and AI retrieval.
There is no supported path that reads another tenant's observations.

### Deliberate exceptions

Shared reference knowledge is **not** tenant scoped, because it is not tenant
data. `campaigns` and `malware` carry no `tenant_id` column at all, and every
tenant reads the same rows. The absence of a tenant filter in
`app/api/v1/domains.py` is therefore correct rather than a leak.

This is recorded explicitly because the distinction is easy to lose: a campaign
visible in the console says nothing about whether it has touched the reading
tenant's estate, and both detail pages state so on the page itself.

There is also **no cross-tenant sharing mechanism**. The sharing surface says so
rather than implying a capability that does not exist.

## Identity

Identity in this platform is an **API key, not a person**. There is no `User`
table, no role model, and no session. Audit entries record
`api_key:<id>` as the actor, and alert acknowledgement records the same. Any
report that attributes an action to a named human would be inventing one.

## Credentials

- Connector secrets live in server configuration only.
- API keys are hashed with Argon2 at rest, scoped to one tenant, revocable, and shown once at creation.
- A missing key still triggers a decoy verification, so response timing does not reveal whether a key exists.
- Revoked keys stay listed and publish `revoked_reason`.
- Revoking the key you are authenticating with returns 409 rather than locking you out silently.
- Capability and health responses expose availability and delivery mode, never secret material. `configured` is never reported as `reachable`.
- Browser code never receives or constructs a platform API key; the console reads server-side.

### Secret scanning

The rules above govern how credentials are handled at runtime. They say nothing
about credentials committed to the repository itself, which is a separate
failure mode and has already occurred on a sibling repository.

`.github/workflows/security.yml` runs gitleaks across **every commit reachable
from the ref**, not just the working tree. A scan limited to the current
checkout reports clean while a key remains retrievable from an older commit,
which is the more dangerous outcome because it comes with a green badge.
Findings are redacted in the log, since Actions output is itself a publication
channel and a scanner that prints what it found republishes it.

`.gitleaks.toml` narrows the default ruleset so the scan stays credible against
a corpus full of hashes and indicator values. The allowlist exists to prevent
noise, never to silence a true finding. A scan that people learn to ignore is
worse than no scan.

Full rationale, including what the scan does **not** prove, is in
[`security-scanning.md`](./security-scanning.md).

### Known outstanding exposure

Credentials for Ransomware.live, AlienVault OTX, and VulnCheck were committed
in plaintext to the public `NogoSecV3.1.1` repository and are present on its
default branch head. Scanning, purge tooling, and a runbook are in place there;
**rotation is not**, and only rotation revokes access. Treat those keys as used
rather than merely exposed until each provider's usage log says otherwise.

## Agent authentication

Enrollment consumes a single-use key, which is revoked on success with the
consuming agent recorded in `revoked_reason`. Heartbeats authenticate with the
issued client certificate rather than an API key, because a body-supplied agent
id would be trivially spoofable.

## Query safety

Rule evaluation and evidence resolution are bounded (`MAX_RULE_RESULTS = 100`,
`MAX_EVIDENCE_ROWS = 100`) so a single tenant cannot exhaust worker capacity.
Rate limiting is applied per key.

## Idempotency

Alerts deduplicate on fingerprint with an integrity-error fallback. Delivery and
replay carry idempotency keys so retries cannot duplicate an external side
effect. `sweep_expired_intents` selects only pending rows, so overlapping
supervision produces no duplicate audit entries.

## Endpoint actions

`endpoint.command.request` is **control plane only**;
`endpoint_command_delivery` reports `not_implemented`. An approved intent is a
recorded decision, not an action taken on a host. Approval requires two distinct
approvers and the requester may not approve their own request. Elapsed requests
are expired on a schedule by `app/workers/intent_expiry_runner.py`, so an
approval window closes on time rather than whenever something happens to call
the sweep.

`app/services/endpoint_command_envelope.py` can sign an HMAC-SHA256 command
envelope with a hard 3600-second TTL cap, but it is wired to nothing. Signing
authority is not authorization: the intent allowlist is checked even for a
valid signature, and there is no replay detection, so the nonce is signed but
never stored.

## Safety invariants

```
Unknown CVSS is None, never 0.0.
Unknown values must not become false or zero.
Provenance is mandatory.
An unenriched indicator is visible, never clean.
Absence from KEV is unknown exploitation, never safe.
An outage must never render as a clean environment.
A heartbeat records last contact, not current health.
An empty inventory means nothing was reported, not that nothing is installed.
Software without a CPE cannot be matched, so exposure counts are a floor.
Understating capability is as inaccurate as overstating it.
AI must cite retrieved platform facts and never invent facts.
AI cannot autonomously execute risky actions.
No LLM-generated report body in the internal report worker.
No endpoint command execution or delivery.
Identity is an API key, not a person.
Tenant isolation applies to all tenant observation; reference knowledge is global and labelled.
Sample corpus is labelled and is not live tenant data.
A secret scan must cover full history and must redact; a working-tree scan reports clean over a live leak.
Purging history does not revoke a credential. Only rotation does.
A CI gate whose results cannot be observed is an unverified claim, not a passing build.
```
