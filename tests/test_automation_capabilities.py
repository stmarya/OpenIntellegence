"""Batch B control-plane safety contracts."""
from __future__ import annotations
import inspect
from app.services import automation_capabilities
from app.workers import internal_automation

def test_endpoint_intent_is_control_plane_only() -> None:
 assert automation_capabilities.ENDPOINT_INTENT_ACTIONS=={"endpoint.command.request"}
 assert "endpoint.command.execute" not in automation_capabilities.ALL_ACTIONS

def test_internal_worker_has_no_network_or_llm_execution_path() -> None:
 source=inspect.getsource(internal_automation)
 for forbidden in ("httpx","subprocess","RagService","AsyncClient","socket"):
  assert forbidden not in source
 assert "body_generated\":False" in source

def test_only_explicit_action_families_are_supported() -> None:
 assert automation_capabilities.ALL_ACTIONS=={"slack.notify","jira.issue.create","siem.push","case.create","report.generate","endpoint.command.request"}
