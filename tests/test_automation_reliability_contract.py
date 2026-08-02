from app.main import create_app

def test_replay_route_is_registered_without_delivery_route() -> None:
 paths=create_app().openapi()["paths"]
 assert "/api/v1/automation-outbox/{outbox_id}/replay" in paths
 assert not any("delivery" in p for p in paths if "automation-outbox" in p)

def test_internal_runner_only_claims_internal_actions() -> None:
 import inspect
 from app.workers import internal_automation_runner
 source=inspect.getsource(internal_automation_runner)
 assert "AutomationOutbox.action.in_(INTERNAL_ACTIONS)" in source
 assert "skip_locked=True" in source
