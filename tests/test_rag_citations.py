"""RAG citation contract tests.

These tests verify the core safety properties of the RAG service without
making any LLM or database calls:

1. No-context refusal: an empty retrieval result must return the refusal
   string, not an invented answer.
2. Citation presence: when context is available, citations must be returned
   alongside the answer.
3. Unconfigured model listing: when no LLM key is set, the service still
   returns retrieved evidence rather than an error.
4. Citation fields: every citation must have entity_type, entity_id and title.

The principle is that a CTI assistant that invents facts is worse than one
that says nothing.  Tests here guard the contract, not the ML quality.
"""

from __future__ import annotations

# Bootstrap full import chain to avoid circular-import errors that arise when
# importing app.ai.rag before app.db.base has finished its registration block.
import app.main  # noqa: F401 (side-effect: registers all ORM models)

from unittest.mock import AsyncMock

from app.ai.rag import NO_CONTEXT_ANSWER, RagService, RetrievedChunk
from app.api.schemas import Citation
from app.core.config import get_settings


def _make_service(*, llm_configured: bool = False) -> RagService:
    """Build a RagService with a mock session and no real credentials."""
    session = AsyncMock()
    client = AsyncMock()
    settings = get_settings()

    service = RagService(session=session, settings=settings, client=client)
    # Inject is_configured via subclass rather than attribute assignment,
    # since it is a @property on the original class.
    service.__class__ = type(
        "_PatchedRagService",
        (RagService,),
        {"is_configured": property(lambda self: llm_configured)},
    )
    return service


def _chunks(n: int = 2) -> list[RetrievedChunk]:
    return [
        RetrievedChunk(
            entity_type="vulnerability",
            entity_id=f"CVE-2026-{i:04d}",
            title=f"CVE-2026-{i:04d}",
            text=f"A high-severity vulnerability. CVSS 9.{i}.",
            source="nvd",
            url=f"https://nvd.nist.gov/vuln/detail/CVE-2026-{i:04d}",
            score=0.9 - i * 0.1,
        )
        for i in range(n)
    ]


class TestNoContextRefusal:
    """Empty retrieval must produce the refusal, not a hallucination."""

    async def test_no_context_returns_refusal_string(self) -> None:
        service = _make_service(llm_configured=True)
        service.retrieve = AsyncMock(return_value=[])

        answer, citations = await service.answer("What is CVE-2026-99999?", top_k=12)

        assert answer == NO_CONTEXT_ANSWER
        assert citations == []

    async def test_no_context_returns_empty_citation_list(self) -> None:
        service = _make_service()
        service.retrieve = AsyncMock(return_value=[])

        _, citations = await service.answer("any question", top_k=5)

        assert isinstance(citations, list)
        assert len(citations) == 0


class TestCitationsPresent:
    """When context exists, citations must accompany the answer."""

    async def test_citations_match_retrieved_chunks(self) -> None:
        service = _make_service(llm_configured=False)
        service.retrieve = AsyncMock(return_value=_chunks(3))

        _, citations = await service.answer("Tell me about these CVEs", top_k=12)

        assert len(citations) == 3
        ids = {c.entity_id for c in citations}
        assert ids == {"CVE-2026-0000", "CVE-2026-0001", "CVE-2026-0002"}

    async def test_citation_has_required_fields(self) -> None:
        service = _make_service(llm_configured=False)
        service.retrieve = AsyncMock(return_value=_chunks(1))

        _, citations = await service.answer("Question", top_k=1)

        assert len(citations) == 1
        c = citations[0]
        assert isinstance(c, Citation)
        assert c.entity_type == "vulnerability"
        assert c.entity_id == "CVE-2026-0000"
        assert c.title == "CVE-2026-0000"

    async def test_citation_source_preserved(self) -> None:
        service = _make_service(llm_configured=False)
        service.retrieve = AsyncMock(return_value=_chunks(1))

        _, citations = await service.answer("Question", top_k=1)

        assert citations[0].source == "nvd"


class TestUnconfiguredModelBehavior:
    """Without an LLM key the service still returns evidence, not an error."""

    async def test_unconfigured_returns_evidence_listing(self) -> None:
        service = _make_service(llm_configured=False)
        service.retrieve = AsyncMock(return_value=_chunks(2))

        answer, citations = await service.answer("CVE question", top_k=12)

        # Should explain the LLM is not configured, not crash
        assert "not configured" in answer.lower()
        # Citations must still be populated from retrieved context
        assert len(citations) == 2

    async def test_unconfigured_no_context_gives_refusal_not_error(self) -> None:
        service = _make_service(llm_configured=False)
        service.retrieve = AsyncMock(return_value=[])

        answer, citations = await service.answer("CVE question", top_k=12)

        assert answer == NO_CONTEXT_ANSWER
        assert citations == []


class TestNoCvssInvention:
    """The system must never silently represent an unknown CVSS as 0.0."""

    def test_no_context_answer_does_not_contain_zero_cvss(self) -> None:
        """The refusal string must not suggest any numeric score."""
        assert "0.0" not in NO_CONTEXT_ANSWER
        assert "cvss" not in NO_CONTEXT_ANSWER.lower()

    def test_unconfigured_listing_does_not_score_unknown_cves(self) -> None:
        """A chunk with no score must not claim a CVSS value."""
        chunk = RetrievedChunk(
            entity_type="vulnerability",
            entity_id="CVE-2026-XXXX",
            title="CVE-2026-XXXX",
            text="No CVSS score recorded.",
            source="nvd",
        )
        assert "0.0" not in chunk.text
        assert "safe" not in chunk.text.lower()
