# Detection and Response

## Alert Evaluation Worker (P1 feature branch)

A tenant-scoped alert evaluation worker now exists in feature work (`app/workers/alert_evaluation.py`) with:
- run-once execution (`AlertEvaluationWorker.run_once()`)
- continuous loop entrypoint (`python -m app.workers.alert_evaluation`)
- supported trigger evaluation for `ioc_sighting`, `agent_stale`, `kev_exposure`, `ransomware_relevance`, and `feed_degraded`
- explicit skip logging for unsupported `custom` rules
- cooldown-aware alert aggregation/dedup using alert fingerprinting and `last_triggered_at`

Current scope intentionally does **not** auto-run external automation or auto-create cases from raised alerts. If `auto_create_case` is set on a rule, the worker records a `pending_approval` candidate state in alert payload only.

This is feature-branch work on top of the P0 integration branch and is not yet merged/validated for production deployment.
