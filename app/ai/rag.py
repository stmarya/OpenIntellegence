"""Retrieval-augmented chat over the intelligence store.

Design position: the model is never allowed to answer from its own memory.
Every response is assembled from rows retrieved out of this workspace's own
database, and every claim carries a citation back to the row that produced
it. An answer with no retrieved context returns a refusal, not a guess — a
CTI assistant that invents a CVE is worse than one that says nothing.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import UTC, datetime

import httpx
import structlog
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.schemas import Citation
from app.core.config import Settings
from app.db.models import DocumentChunk, RansomwareVictim, Vulnerability
from app.ingest.normalize import extract_cve_ids

log = structlog.get_logger(__name__)

SYSTEM_PROMPT = """You are the analyst assistant for a cyber threat intelligence platform.

Rules you must follow:
1. Answer only from the CONTEXT provided below. Never use prior knowledge
   about specific CVEs, actors or victims.
2. Cite the context item id in square brackets after each claim, e.g. [3].
3. If the context does not answer the question, say so plainly and name what
   is missing. Do not speculate.
4. When a CVSS score is absent, say "not yet scored". Never write 0.0.
5. Give figures exactly as they appear in the context. Do not round or
   extrapolate.
6. Answer in the language the user asked in.
"""

NO_CONTEXT_ANSWER = (
    "I could not find anything in your intelligence store that answers this. "
    "This may mean the relevant feed has not run yet, or the question falls "
    "outside the data currently collected. I will not answer from general "
    "knowledge, because that would not reflect your environment."
)


@dataclass(slots=True)
class RetrievedChunk:
    entity_type: str
    entity_id: str
    title: str
    text: str
    source: str | None = None
    url: str | None = None
    score: float = 0.0


class EmbeddingError(RuntimeError):
    pass


class LlmError(RuntimeError):
    pass


class RagService:
    def __init__(
        self, session: AsyncSession, settings: Settings, client: httpx.AsyncClient
    ) -> None:
        self.session = session
        self.settings = settings
        self.client = client

    @property
    def is_configured(self) -> bool:
        return self.settings.llm_api_key is not None

    # ------------------------------------------------------------------
    # Embeddings
    # ------------------------------------------------------------------

    async def embed(self, text: str) -> list[float]:
        if not self.is_configured:
            raise EmbeddingError("LLM_API_KEY is not configured.")

        response = await self.client.post(
            f"{self.settings.llm_base_url}/embeddings",
            headers={
                "Authorization": f"Bearer {self.settings.llm_api_key.get_secret_value()}"
            },
            json={"model": self.settings.embedding_model, "input": text},
            timeout=30.0,
        )
        if response.status_code >= 400:
            raise EmbeddingError(f"embedding failed: {response.status_code} {response.text}")

        return response.json()["data"][0]["embedding"]

    # ------------------------------------------------------------------
    # Retrieval
    # ------------------------------------------------------------------

    async def retrieve(self, question: str, top_k: int) -> list[RetrievedChunk]:
        """Hybrid retrieval: exact identifiers first, then semantic search.

        Analysts overwhelmingly ask about a specific CVE. Vector similarity
        is unreliable for identifier lookup because embeddings of near
        identical strings collide, so an exact match is tried first and
        always wins.
        """
        chunks: list[RetrievedChunk] = []

        for cve_id in extract_cve_ids(question):
            vuln = (
                await self.session.execute(
                    select(Vulnerability).where(Vulnerability.cve_id == cve_id.upper())
                )
            ).scalar_one_or_none()
            if vuln is not None:
                chunks.append(self._vulnerability_chunk(vuln))

        if len(chunks) < top_k:
            chunks.extend(await self._semantic(question, top_k - len(chunks)))

        if not chunks:
            chunks.extend(await self._keyword_fallback(question, top_k))

        # De-duplicate while preserving the exact-match-first ordering.
        seen: set[tuple[str, str]] = set()
        unique: list[RetrievedChunk] = []
        for chunk in chunks:
            key = (chunk.entity_type, chunk.entity_id)
            if key not in seen:
                seen.add(key)
                unique.append(chunk)

        return unique[:top_k]

    def _vulnerability_chunk(self, vuln: Vulnerability) -> RetrievedChunk:
        score = "not yet scored" if vuln.cvss_score is None else str(vuln.cvss_score)
        text = (
            f"{vuln.cve_id}. CVSS: {score}. Severity: {vuln.severity or 'unknown'}. "
            f"Known exploited (CISA KEV): {'yes' if vuln.is_kev else 'no'}. "
            f"Exploit maturity: {vuln.exploit_maturity.value}. "
            f"Vendor: {vuln.vendor or 'unknown'}. Product: {vuln.product or 'unknown'}. "
            f"Published: {vuln.published_at.isoformat() if vuln.published_at else 'unknown'}. "
            f"Sources: {', '.join(vuln.sources or []) or 'unknown'}. "
            f"Description: {vuln.description or 'none recorded'}"
        )
        return RetrievedChunk(
            entity_type="vulnerability",
            entity_id=vuln.cve_id,
            title=vuln.cve_id,
            text=text,
            source=", ".join(vuln.sources or []) or None,
            score=1.0,
        )

    async def _semantic(self, question: str, limit: int) -> list[RetrievedChunk]:
        if limit <= 0 or not self.is_configured:
            return []

        try:
            vector = await self.embed(question)
        except EmbeddingError as exc:
            # Degrade to keyword search rather than failing the request.
            log.warning("embedding_unavailable", error=str(exc))
            return []

        rows = (
            await self.session.execute(
                select(DocumentChunk)
                .order_by(DocumentChunk.embedding.cosine_distance(vector))
                .limit(limit)
            )
        ).scalars().all()

        return [
            RetrievedChunk(
                entity_type=row.entity_type,
                entity_id=row.entity_id,
                title=row.title,
                text=row.content,
                source=row.source,
            )
            for row in rows
        ]

    async def _keyword_fallback(self, question: str, limit: int) -> list[RetrievedChunk]:
        """Plain text search, used when embeddings are unavailable."""
        term = f"%{question.strip()[:80].lower()}%"

        victims = (
            await self.session.execute(
                select(RansomwareVictim)
                .where(func.lower(RansomwareVictim.display_name).like(term))
                .limit(limit)
            )
        ).scalars().all()

        return [
            RetrievedChunk(
                entity_type="ransomware_victim",
                entity_id=str(v.id),
                title=v.display_name,
                text=(
                    f"{v.display_name} was listed by {v.group_name} on "
                    f"{v.discovered_at.isoformat()}. Country: {v.country or 'unknown'}. "
                    f"Sector: {v.sector or 'unknown'}. "
                    f"Sources: {', '.join(v.sources or []) or 'unknown'}."
                ),
                source=", ".join(v.sources or []) or None,
            )
            for v in victims
        ]

    # ------------------------------------------------------------------
    # Generation
    # ------------------------------------------------------------------

    async def answer(self, question: str, top_k: int) -> tuple[str, list[Citation]]:
        chunks = await self.retrieve(question, top_k)
        if not chunks:
            return NO_CONTEXT_ANSWER, []

        context = "\n\n".join(
            f"[{i}] ({chunk.entity_type}) {chunk.title}\n{chunk.text}"
            for i, chunk in enumerate(chunks, 1)
        )

        citations = [
            Citation(
                entity_type=chunk.entity_type,
                entity_id=chunk.entity_id,
                title=chunk.title,
                source=chunk.source,
                url=chunk.url,
            )
            for chunk in chunks
        ]

        if not self.is_configured:
            # Still useful without a model: return the evidence itself
            # rather than pretending the feature is broken.
            listing = "\n".join(f"- [{i}] {c.title}" for i, c in enumerate(chunks, 1))
            return (
                "The language model is not configured, so I cannot compose a "
                f"narrative answer. These records match your question:\n\n{listing}",
                citations,
            )

        answer = await self._complete(
            [
                {"role": "system", "content": SYSTEM_PROMPT},
                {
                    "role": "user",
                    "content": (
                        f"CONTEXT (retrieved {datetime.now(UTC).isoformat()}):\n"
                        f"{context}\n\nQUESTION: {question}"
                    ),
                },
            ]
        )
        return answer, citations

    async def _complete(self, messages: list[dict[str, str]]) -> str:
        response = await self.client.post(
            f"{self.settings.llm_base_url}/chat/completions",
            headers={
                "Authorization": f"Bearer {self.settings.llm_api_key.get_secret_value()}"
            },
            json={
                "model": self.settings.llm_model,
                "messages": messages,
                # Low temperature: this is reporting, not writing.
                "temperature": 0.1,
            },
            timeout=120.0,
        )
        if response.status_code >= 400:
            raise LlmError(f"completion failed: {response.status_code} {response.text}")

        try:
            return response.json()["choices"][0]["message"]["content"]
        except (KeyError, IndexError, json.JSONDecodeError) as exc:
            raise LlmError(f"unexpected completion response: {exc}") from exc
