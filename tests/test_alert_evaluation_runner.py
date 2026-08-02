"""Worker entrypoint regression contracts."""

from __future__ import annotations

import inspect

from app.workers import alert_evaluation_runner


def test_alert_evaluation_runner_commits_single_evaluation_unit() -> None:
    source = inspect.getsource(alert_evaluation_runner.run_once)
    assert "AlertEvaluationWorker().evaluate" in source
    assert "await session.commit()" in source


def test_alert_evaluation_runner_has_no_delivery_or_execution_path() -> None:
    source = inspect.getsource(alert_evaluation_runner)
    assert "httpx" not in source
    assert "subprocess" not in source
    assert "command" not in source
