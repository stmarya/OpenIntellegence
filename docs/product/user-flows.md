# User Flows

> **Truthfulness note:** These flows describe intended analyst workflows based on the current architecture and feature specifications. Routes from feature branches (PRs #3–#13) are labelled as **[planned]**. Flows that depend on planned features cannot be executed end-to-end until integration is complete. See `docs/planning/project-status.md` for current execution state.

---

## 1. Intelligence exploration

**Analyst goal:** Understand the current threat landscape relevant to the organization's environment.

### Happy path

1. **List current high-severity CVEs:**
   ```
   GET /api/v1/vulnerabilities?severity=critical&is_kev=true
   ```
   Response includes `cvss_score`, `exploit_maturity`, and provenance sources.

2. **Check CVE detail and exploits:**
   ```
   GET /api/v1/vulnerabilities/{cve_id}
   ```
   Response includes associated `exploits` and their `confidence` scores.

3. **Browse threat actors:**
   ```
   GET /api/v1/actors
   ```

4. **Search indicators of compromise:**
   ```
   GET /api/v1/iocs?indicator_type=ipv4&verdict=malicious
   ```

5. **Review ransomware victims:**
   ```
   GET /api/v1/ransomware/victims
   ```

6. **Check dashboard KPIs:**
   ```
   GET /api/v1/stats/summary
   ```

### Failure / partial-data behavior

| Scenario | What the analyst sees |
|---|---|
| A feed is degraded | `provenance.degraded` includes the feed name; `provenance.note` explains the gap |
| `cvss_score` is `null` | Field displays as "Unknown" — never as 0.0 or "Safe" |
| IOC `verdict` is `null` | Displays as "Unenriched" — never as "Clean" |
| Source feed never ran | Feed appears in `GET /feeds` with `status: never_run` |

---

## 2. Asset exposure investigation

**Analyst goal:** Determine which assets are exposed to a specific CVE or threat category.

### Happy path

1. **List assets:**
   ```
   GET /api/v1/assets
   ```

2. **Check exposure for a specific asset:**
   ```
   GET /api/v1/assets/{asset_id}/exposure
   ```
   Response includes matched CVEs, `matched_via`, `detected_at`, `sla_due_at`.

3. **Verify installed software:**
   ```
   GET /api/v1/agents/{agent_id}/software
   ```

4. **Cross-reference CVE detail:**
   ```
   GET /api/v1/vulnerabilities/{cve_id}
   ```

5. **Ask the AI assistant for context:**
   ```
   POST /api/v1/chat/query
   { "question": "Which of our assets are most at risk from this CVE?" }
   ```

### Failure / partial-data behavior

| Scenario | What the analyst sees |
|---|---|
| Agent is stale | `status: "stale"` visible in listing; not hidden or marked healthy |
| CPE match unavailable | `matched_via: null`; exposure may be incomplete |
| OS end-of-life | `os_eol: true` shown on asset; analyst must consider patching availability |
| `risk_score` is null | Not computed yet; displayed as "Not scored" |

---

## 3. Investigation and case workflow [planned]

> **Status:** depends on PR #6 (Investigation & Cases). Not executable until integrated.

**Analyst goal:** Collect evidence, assign tasks, and track an incident to resolution.

### Intended happy path

1. **Create an investigation:**
   ```
   POST /api/v1/investigations
   { "title": "APT28 activity on VPN cluster", "tenant_id": "..." }
   ```

2. **Link relevant entities:**
   ```
   POST /api/v1/investigations/{id}/entities
   { "entity_type": "vulnerability", "entity_id": "CVE-2024-12345" }
   ```

3. **Escalate to a case:**
   ```
   POST /api/v1/cases
   { "investigation_id": "...", "title": "IR Case: APT28", "severity": "high" }
   ```

4. **Add case tasks:**
   ```
   POST /api/v1/cases/{id}/tasks
   { "title": "Isolate affected host", "assignee": "...", "due_at": "..." }
   ```

5. **Review the timeline:**
   ```
   GET /api/v1/cases/{id}/timeline
   ```
   Timeline is append-only; no events are deleted or rewritten.

### Failure / partial-data behavior

| Scenario | What the analyst sees |
|---|---|
| Investigation has no entities | Empty entity list; workflow continues |
| Case task overdue | `due_at` in the past; analyst must manually resolve or extend |
| Automation proposes case creation | Case appears in `proposed` state; analyst must approve before it becomes active |

---

## 4. Alert triage [planned]

> **Status:** depends on PR #7 (Alerts & Sightings). Not executable until integrated.

**Analyst goal:** Review triggered alerts, acknowledge relevant ones, and suppress false positives.

### Intended happy path

1. **List open alerts:**
   ```
   GET /api/v1/alerts?status=open
   ```

2. **Review alert detail and fingerprint:**
   ```
   GET /api/v1/alerts/{id}
   ```
   Fingerprint shows how identical signals were aggregated.

3. **Acknowledge an alert:**
   ```
   POST /api/v1/alerts/{id}/acknowledge
   ```

4. **Record a sighting:**
   ```
   POST /api/v1/sightings
   { "indicator_id": "...", "asset_id": "...", "observed_at": "..." }
   ```

### Failure / partial-data behavior

| Scenario | What the analyst sees |
|---|---|
| Alert rule disabled | No new alerts generated; analyst should check rule status |
| Duplicate alert signals | Signals aggregated by fingerprint; count incremented; not duplicated |
| Alert with no supporting evidence | Alert visible with explicit "no enrichment" state |

---

## 5. Correlation brief review [planned]

> **Status:** depends on PR #8 (Correlation & AI). Not executable until integrated.

**Analyst goal:** Review a machine-produced correlation brief that scores risk across CVE, asset exposure, and threat actor context.

### Intended happy path

1. **List available correlation results:**
   ```
   GET /api/v1/correlations
   ```

2. **Review a correlation brief with citations:**
   ```
   GET /api/v1/correlations/{id}
   ```
   Brief includes a `risk_score`, factor breakdown (CVSS, KEV, exploit evidence, asset criticality, sightings), and a list of cited platform records.

3. **Read the AI-generated context section:**
   AI output is grounded in the cited records; if no supporting evidence was retrieved, the section is explicitly labelled `unverified`.

### Failure / partial-data behavior

| Scenario | What the analyst sees |
|---|---|
| AI generation fails | `status: failed`; `error_message` present; factor breakdown still visible |
| No AI context available | Brief shows factor scores only; AI section shows explicit "unverified" label |
| Disputed attribution | `origin_country` and actor labels include "disputed" qualifier |

---

## 6. Automation approval workflow [planned]

> **Status:** depends on PRs #9 and #10 (Orchestration, Connector Runtime). Not executable until integrated.

**Analyst goal:** Review a proposed automation action and approve or reject it before external delivery.

### Intended happy path

1. **List proposed playbook runs:**
   ```
   GET /api/v1/playbooks/runs?status=proposed
   ```

2. **Review the run details:**
   ```
   GET /api/v1/playbooks/runs/{run_id}
   ```
   Shows the triggering signal, proposed action, target connector, and payload summary.

3. **Approve:**
   ```
   POST /api/v1/playbooks/runs/{run_id}/approve
   ```
   Run transitions to `dispatching`; connector delivery worker picks it up.

4. **Reject:**
   ```
   POST /api/v1/playbooks/runs/{run_id}/reject
   ```
   Run transitions to `rejected`; reason is persisted in the audit log.

### Failure / partial-data behavior

| Scenario | What the analyst sees |
|---|---|
| Connector is unconfigured | Run remains in `proposed`; connector health shows `unconfigured` |
| Delivery fails after approval | Run transitions to `failed`; dead-letter record created; operator must triage |
| AI-proposed run | Run appears in `proposed` state; AI cannot self-approve |
| Approval without sufficient scope | 403 with required scope named |

---

## 7. AI intelligence report workflow

**Analyst goal:** Generate a comprehensive intelligence report for a reporting period.

### Happy path (currently available)

1. **List available templates:**
   ```
   GET /api/v1/reports/templates
   ```

2. **Queue a report:**
   ```
   POST /api/v1/reports/generate
   {
     "template": "threat_landscape",
     "title": "Weekly CTI Brief — 2026-W31",
     "period_start": "2026-07-25T00:00:00Z",
     "period_end": "2026-08-01T00:00:00Z"
   }
   ```
   Returns `202 Accepted` with `status: "queued"`.
   Requires `report:write` scope.

3. **Poll for completion:**
   ```
   GET /api/v1/reports/{report_id}
   ```
   Poll until `status` is `"complete"` or `"failed"`. Typical generation time: 40–120 seconds.

4. **Read the report:**
   Response includes `content_markdown`, `citations`, and `generation_seconds`.

5. **List previous reports:**
   ```
   GET /api/v1/reports
   ```

### Failure / partial-data behavior

| Scenario | What the analyst sees |
|---|---|
| LLM provider unavailable | `status: "failed"`, `error_message` contains provider error; retry with `POST /reports/generate` |
| No intelligence data in period | Report generated but includes explicit "no supporting evidence" note in relevant sections |
| Report generation in progress | `status: "generating"`, `progress` field 0–100 |
| `read`-scoped key attempts report generation | 403; requires `report:write` |
| RAG returns no context | Report section labelled `unverified`; citations array empty for that section |
