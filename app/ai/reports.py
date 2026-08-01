"""AI report generation.

A report is produced in two stages. First we run deterministic SQL to gather
the figures; then the model is asked to write prose around numbers it was
handed. The model never counts anything itself. This is the difference
between a report you can defend in an audit and one that merely reads well.

Every generated report stores its citations. Without them an AI report is an
unfalsifiable claim.
"""

from __future__ import annotations

import time
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta

import structlog
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.ai.rag import LlmError, RagService
from app.db.models import (
    Asset,
    AssetExposure,
    Indicator,
    RansomwareVictim,
    Report,
    ReportStatus,
    Vulnerability,
)
from app.services.provenance import build_provenance

log = structlog.get_logger(__name__)


@dataclass(frozen=True, slots=True)
class TemplateSpec:
    key: str
    title: str
    instruction: str
    default_period_days: int


TEMPLATES: dict[str, TemplateSpec] = {
    "executive_brief": TemplateSpec(
        key="executive_brief",
        title="Executive Brief",
        instruction=(
            "Write for a non-technical executive. Lead with business risk, not "
            "CVE numbers. Maximum 600 words. Sections: Situation, What Changed, "
            "Exposure, Recommended Decisions. State plainly if the picture is "
            "incomplete because a feed failed."
        ),
        default_period_days=7,
    ),
    "threat_advisory": TemplateSpec(
        key="threat_advisory",
        title="Threat Advisory",
        instruction=(
            "Write for a security engineer. Focus on the specified CVE or the "
            "highest-exposure vulnerability. Sections: Summary, Technical Detail, "
            "Affected Assets, Exploitation Status, Mitigation, Detection. Be "
            "precise about what is confirmed versus inferred."
        ),
        default_period_days=7,
    ),
    "ransomware_landscape": TemplateSpec(
        key="ransomware_landscape",
        title="Ransomware Landscape",
        instruction=(
            "Analyse leak-site activity for the period. Sections: Overview, "
            "Most Active Groups, Sector and Geography, Notable Victims, Outlook. "
            "State the de-duplication rate and note that leak-site claims are "
            "unverified assertions by the attacker."
        ),
        default_period_days=30,
    ),
    "asset_exposure": TemplateSpec(
        key="asset_exposure",
        title="Asset Exposure Report",
        instruction=(
            "Report on fleet exposure. Sections: Coverage, Exposure by "
            "Criticality, SLA Breaches, Unmatchable Inventory, Priorities. "
            "Always state agent coverage, because exposure figures are only "
            "meaningful relative to how much of the fleet reports in."
        ),
        default_period_days=7,
    ),
    "compliance_pack": TemplateSpec(
        key="compliance_pack",
        title="Compliance Pack",
        instruction=(
            "Map the current posture to ISO 27001 A.12.6 (technical "
            "vulnerability management) and SOC 2 CC7.1. Sections: Scope, "
            "Control Evidence, Gaps, Remediation Plan. Cite counts as evidence "
            "and mark any control you cannot evidence as 'not evidenced'."
        ),
        default_period_days=90,
    ),
    "ioc_hunting_pack": TemplateSpec(
        key="ioc_hunting_pack",
        title="IOC Hunting Pack",
        instruction=(
            "Produce a hunting package. Sections: Indicator Summary, Hunting "
            "Queries, Confidence Notes. Separate enriched indicators from "
            "unenriched ones and never present an unenriched indicator as "
            "confirmed malicious."
        ),
        default_period_days=30,
    ),
}


class ReportGenerator:
    def __init__(self, session: AsyncSession, rag: RagService) -> None:
        self.session = session
        self.rag = rag

    async def generate(self, report: Report, *, focus_cve_id: str | None = None) -> Report:
        started = time.monotonic()
        spec = TEMPLATES[report.template]

        report.status = ReportStatus.RUNNING
        report.progress = 10
        await self.session.flush()

        try:
            facts, citations = await self._collect_facts(report, spec, focus_cve_id)
            report.progress = 55
            await self.session.flush()

            markdown = await self._write(spec, report, facts)

            report.content_markdown = markdown
            report.citations = citations
            report.status = ReportStatus.COMPLETED
            report.progress = 100

        except LlmError as exc:
            # A failed report is marked failed. It is never silently saved
            # half-written, because a partial report reads like a complete one.
            report.status = ReportStatus.FAILED
            report.error_message = str(exc)
            log.warning("report_failed", report_id=str(report.id), error=str(exc))

        report.generation_seconds = round(time.monotonic() - started, 2)
        await self.session.flush()
        return report

    # ------------------------------------------------------------------
    # Deterministic fact collection
    # ------------------------------------------------------------------

    async def _collect_facts(
        self, report: Report, spec: TemplateSpec, focus_cve_id: str | None
    ) -> tuple[str, list[dict]]:
        end = report.period_end or datetime.now(UTC)
        start = report.period_start or end - timedelta(days=spec.default_period_days)

        lines: list[str] = [
            f"Reporting period: {start.isoformat()} to {end.isoformat()}",
        ]
        citations: list[dict] = []

        provenance = await build_provenance(self.session, sources=None)
        lines.append(
            "Feeds contributing: "
            + (", ".join(provenance.sources_included) or "none")
        )
        if provenance.sources_degraded:
            lines.append(
                "Feeds NOT contributing (data is incomplete): "
                + ", ".join(provenance.sources_degraded)
            )

        total_vulns = await self.session.scalar(select(func.count(Vulnerability.id))) or 0
        kev = (
            await self.session.scalar(
                select(func.count(Vulnerability.id)).where(Vulnerability.is_kev.is_(True))
            )
            or 0
        )
        unscored = (
            await self.session.scalar(
                select(func.count(Vulnerability.id)).where(Vulnerability.cvss_score.is_(None))
            )
            or 0
        )
        lines += [
            f"Vulnerabilities tracked: {total_vulns}",
            f"Known exploited (CISA KEV): {kev}",
            f"Vulnerabilities with no CVSS score yet: {unscored}",
        ]

        top_rows = (
            await self.session.execute(
                select(
                    Vulnerability,
                    func.count(AssetExposure.id).label("asset_count"),
                )
                .join(AssetExposure, AssetExposure.vulnerability_id == Vulnerability.id)
                .where(AssetExposure.resolved_at.is_(None))
                .group_by(Vulnerability.id)
                .order_by(func.count(AssetExposure.id).desc())
                .limit(10)
            )
        ).all()

        if top_rows:
            lines.append("Highest-exposure vulnerabilities (by affected asset count):")
            for vuln, count in top_rows:
                score = "not yet scored" if vuln.cvss_score is None else vuln.cvss_score
                lines.append(
                    f"  - {vuln.cve_id}: {count} assets, CVSS {score}, "
                    f"KEV {'yes' if vuln.is_kev else 'no'}, "
                    f"exploit {vuln.exploit_maturity.value}"
                )
                citations.append(
                    {
                        "entity_type": "vulnerability",
                        "entity_id": vuln.cve_id,
                        "title": vuln.cve_id,
                        "source": ", ".join(vuln.sources or []) or None,
                    }
                )
        else:
            lines.append(
                "No asset exposures recorded. Either no agents report in, or no "
                "installed software matched a known CVE."
            )

        if focus_cve_id:
            focus = (
                await self.session.execute(
                    select(Vulnerability).where(Vulnerability.cve_id == focus_cve_id.upper())
                )
            ).scalar_one_or_none()
            if focus is not None:
                lines.append(f"Focus vulnerability: {self.rag._vulnerability_chunk(focus).text}")
                citations.append(
                    {
                        "entity_type": "vulnerability",
                        "entity_id": focus.cve_id,
                        "title": focus.cve_id,
                        "source": ", ".join(focus.sources or []) or None,
                    }
                )
            else:
                lines.append(
                    f"Focus vulnerability {focus_cve_id} is NOT present in the dataset."
                )

        lines += await self._ransomware_facts(start, end, citations)
        lines += await self._asset_facts()
        lines += await self._indicator_facts()

        return "\n".join(lines), citations

    async def _ransomware_facts(
        self, start: datetime, end: datetime, citations: list[dict]
    ) -> list[str]:
        victims = (
            await self.session.scalar(
                select(func.count(RansomwareVictim.id)).where(
                    RansomwareVictim.discovered_at.between(start, end)
                )
            )
            or 0
        )
        needs_review = (
            await self.session.scalar(
                select(func.count(RansomwareVictim.id)).where(
                    RansomwareVictim.needs_review.is_(True)
                )
            )
            or 0
        )

        groups = (
            await self.session.execute(
                select(RansomwareVictim.group_name, func.count(RansomwareVictim.id))
                .where(RansomwareVictim.discovered_at.between(start, end))
                .group_by(RansomwareVictim.group_name)
                .order_by(func.count(RansomwareVictim.id).desc())
                .limit(10)
            )
        ).all()

        lines = [
            f"Ransomware victims disclosed in period: {victims}",
            f"Victim records whose name could not be normalised: {needs_review}",
        ]
        if groups:
            lines.append("Most active groups: " + ", ".join(f"{g} ({c})" for g, c in groups))
            for group_name, count in groups[:5]:
                citations.append(
                    {
                        "entity_type": "ransomware_group",
                        "entity_id": group_name,
                        "title": f"{group_name} ({count} victims)",
                        "source": "leak-site feeds",
                    }
                )
        return lines

    async def _asset_facts(self) -> list[str]:
        total = await self.session.scalar(select(func.count(Asset.id))) or 0
        breached = (
            await self.session.scalar(
                select(func.count(AssetExposure.id)).where(
                    AssetExposure.resolved_at.is_(None),
                    AssetExposure.sla_due_at.is_not(None),
                    AssetExposure.sla_due_at < datetime.now(UTC),
                )
            )
            or 0
        )
        return [
            f"Assets under management: {total}",
            f"Open exposures past their remediation SLA: {breached}",
        ]

    async def _indicator_facts(self) -> list[str]:
        total = await self.session.scalar(select(func.count(Indicator.id))) or 0
        unenriched = (
            await self.session.scalar(
                select(func.count(Indicator.id)).where(Indicator.verdict.is_(None))
            )
            or 0
        )
        malicious = (
            await self.session.scalar(
                select(func.count(Indicator.id)).where(Indicator.verdict == "malicious")
            )
            or 0
        )
        return [
            f"Indicators stored: {total}",
            f"Indicators confirmed malicious: {malicious}",
            f"Indicators not yet enriched: {unenriched}",
        ]

    # ------------------------------------------------------------------
    # Narrative
    # ------------------------------------------------------------------

    async def _write(self, spec: TemplateSpec, report: Report, facts: str) -> str:
        if not self.rag.is_configured:
            # Without a model, emit the verified figures rather than nothing.
            return (
                f"# {report.title}\n\n"
                "> The language model is not configured, so this report contains "
                "the verified figures without narrative analysis.\n\n"
                f"```\n{facts}\n```\n"
            )

        prompt = (
            f"{spec.instruction}\n\n"
            "You are given VERIFIED FIGURES computed directly from the database. "
            "Use them exactly as written. Do not compute new totals, do not "
            "estimate, and do not introduce any CVE, group or asset that does "
            "not appear below. Where the figures say data is incomplete, say so "
            "in the report.\n\n"
            f"VERIFIED FIGURES:\n{facts}\n\n"
            f"Write the report in Markdown. Title it: {report.title}"
        )

        return await self.rag._complete(
            [
                {
                    "role": "system",
                    "content": (
                        "You are a senior threat intelligence analyst writing a "
                        "formal report. You never invent figures. You state "
                        "uncertainty explicitly."
                    ),
                },
                {"role": "user", "content": prompt},
            ]
        )


def template_keys() -> Sequence[str]:
    return tuple(TEMPLATES)
