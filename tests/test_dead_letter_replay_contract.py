"""Replay policy must never cross tenant or endpoint-control boundaries."""
from app.services.dead_letter_replay import NON_REPLAYABLE

def test_endpoint_and_internal_actions_are_never_replayable() -> None:
 assert {"endpoint.command.request","case.create","report.generate"}.issubset(NON_REPLAYABLE)

def test_replay_policy_has_no_connector_or_command_delivery() -> None:
 import inspect
 from app.services import dead_letter_replay
 source=inspect.getsource(dead_letter_replay)
 for forbidden in ("httpx","subprocess","AsyncClient","deliver("):
  assert forbidden not in source
 assert "with_for_update" in source
 assert "replay:" in source
