"""AI brief safety contracts."""
from __future__ import annotations
import inspect
from app.api.v1 import correlations

def test_unavailable_evidence_short_circuits_before_rag_creation() -> None:
    source = inspect.getsource(correlations.generate_ai_brief)
    unavailable = source.index('unavailable =')
    rag = source.index('service = _rag')
    assert unavailable < rag
