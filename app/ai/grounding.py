"""Post-generation grounding checks independent of any model provider."""
from __future__ import annotations
import re
from collections.abc import Sequence
from app.api.schemas import Citation

WITHHELD_ANSWER = (
    "The model returned an answer that did not preserve valid evidence citations. "
    "The narrative has been withheld; review the retrieved sources below instead."
)
_MARKER = re.compile(r"\[(\d+)]")

def enforce_citation_contract(answer: str, citations: Sequence[Citation], *, generated: bool) -> tuple[str, bool]:
    """Withhold model prose unless every citation marker resolves to retrieved evidence."""
    if not generated:
        return answer, True
    markers = [int(value) for value in _MARKER.findall(answer)]
    valid = bool(citations) and bool(markers) and all(1 <= value <= len(citations) for value in markers)
    return (answer, True) if valid else (WITHHELD_ANSWER, False)
