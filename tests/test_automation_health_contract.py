from app.main import create_app

def test_automation_capability_route_is_registered() -> None:
 schema=create_app().openapi()
 assert "/api/v1/automation/capabilities" in schema["paths"]

def test_capability_route_is_read_only() -> None:
 methods=set(create_app().openapi()["paths"]["/api/v1/automation/capabilities"])
 assert methods=={"get"}
