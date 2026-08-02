from datetime import UTC, datetime, timedelta
from app.services.endpoint_intents import can_dispatch, validate_intent

def test_requester_cannot_self_approve() -> None:
 result=validate_intent("isolate_network","requester",["requester","second"],datetime.now(UTC)+timedelta(hours=1),datetime.now(UTC))
 assert result.state=="rejected"

def test_two_distinct_non_requester_approvals_required() -> None:
 now=datetime.now(UTC); assert validate_intent("collect_inventory","requester",["one"],now+timedelta(hours=1),now).state=="pending"
 assert validate_intent("collect_inventory","requester",["one","two"],now+timedelta(hours=1),now).state=="approved"

def test_control_plane_intents_cannot_dispatch() -> None:
 assert can_dispatch("approved") is False
