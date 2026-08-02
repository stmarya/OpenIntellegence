from app.main import create_app

def test_endpoint_intent_routes_are_control_plane_only() -> None:
 paths=create_app().openapi()["paths"]
 assert "/api/v1/endpoint-intents" in paths
 assert "/api/v1/endpoint-intents/{intent_id}/approve" in paths
 assert "/api/v1/endpoint-intents/{intent_id}/cancel" in paths
 assert not any("dispatch" in path or "execute" in path or "deliver" in path for path in paths if "endpoint-intents" in path)
