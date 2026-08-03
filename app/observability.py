"""Low-cardinality Prometheus metrics and request correlation."""
from __future__ import annotations
from prometheus_client import CONTENT_TYPE_LATEST, Counter, Histogram, generate_latest
from starlette.responses import Response
REQUESTS = Counter("openintel_http_requests_total", "HTTP requests", ("method", "route", "status"))
LATENCY = Histogram("openintel_http_request_duration_seconds", "HTTP latency", ("method", "route"), buckets=(0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10))
WORKER_RUNS = Counter("openintel_worker_runs_total", "Worker runs", ("worker", "outcome"))
def observe(method: str, route: str, status_code: int, seconds: float) -> None:
    safe_route = route if route.startswith("/") else "unknown"; REQUESTS.labels(method, safe_route, str(status_code)).inc(); LATENCY.labels(method, safe_route).observe(seconds)
def metrics_response() -> Response: return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)
