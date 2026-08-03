"""Low-cardinality Prometheus metrics and request correlation."""
from __future__ import annotations
from prometheus_client import Counter, Histogram, generate_latest, CONTENT_TYPE_LATEST
from starlette.responses import Response
REQUESTS=Counter("openintel_http_requests_total","HTTP requests",("method","route","status"))
LATENCY=Histogram("openintel_http_request_duration_seconds","HTTP latency",("method","route"),buckets=(.01,.025,.05,.1,.25,.5,1,2.5,5,10))
WORKER_RUNS=Counter("openintel_worker_runs_total","Worker runs",("worker","outcome"))
def observe(method:str,route:str,status_code:int,seconds:float)->None:
 safe_route=route if route.startswith("/") else "unknown";REQUESTS.labels(method,safe_route,str(status_code)).inc();LATENCY.labels(method,safe_route).observe(seconds)
def metrics_response()->Response:return Response(generate_latest(),media_type=CONTENT_TYPE_LATEST)
