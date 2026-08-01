"""Concrete connectors for the 14 upstream sources.

Each connector fixes a specific defect measured in the legacy collector:

* :class:`NvdConnector` — the legacy URL was built with a malformed f-string
  that emitted literal braces. Query parameters are passed structurally here
  so the bug class cannot recur.
* :class:`CxSecurityConnector` — the legacy parser read ``<lastBuildDate>``
  (a channel-level tag, identical for every item) instead of ``<pubDate>``,
  so all 40 records shared one timestamp.
* :class:`GithubPocConnector` — applies a confidence score, because a raw
  "CVE" repository search returns CV templates and unrelated tooling.
* :class:`RansomwareLiveConnector` — reads its key from settings and skips
  itself when absent, instead of shipping a hardcoded credential.
"""

from __future__ import annotations

import re
from collections.abc import AsyncIterator
from datetime import UTC, datetime, timedelta
from typing import Any
from xml.etree import ElementTree

import httpx

from app.ingest.base import (
    Connector,
    ConnectorError,
    EntityKind,
    FetchResult,
    NormalizedRecord,
    Quarantine,
    registry,
)
from app.ingest.normalize import (
    NormalizationError,
    canonical_victim_key,
    extract_cve_ids,
    extract_domain,
    normalize_cvss,
    normalize_group_name,
    normalize_timestamp,
    severity_from_cvss,
    strip_status_prefix,
)


def _victim_record(
    *,
    source: str,
    raw: dict[str, Any],
    victim_name: str,
    group_name: str | None,
    discovered_raw: Any,
    country: str | None = None,
    sector: str | None = None,
    website: str | None = None,
    screenshot: str | None = None,
) -> FetchResult:
    """Shared normalisation for the three ransomware leak-site feeds."""
    if not victim_name or not str(victim_name).strip():
        return Quarantine(source=source, reason="empty victim_name", raw=raw)

    group = normalize_group_name(group_name)
    if not group:
        return Quarantine(source=source, reason="missing group_name", raw=raw)

    try:
        discovered = normalize_timestamp(discovered_raw, source=source)
    except NormalizationError as exc:
        return Quarantine(source=source, reason=str(exc), raw=raw)

    if discovered is None:
        return Quarantine(source=source, reason="missing discovered_at", raw=raw)

    cleaned, status = strip_status_prefix(str(victim_name))
    key = canonical_victim_key(str(victim_name))
    domain = extract_domain(cleaned) or (extract_domain(website) if website else None)

    # Flag rows whose display name is still a URL or carries a status marker,
    # so the UI can show "not yet normalised" honestly instead of hiding it.
    needs_review = bool(status) or cleaned != str(victim_name).strip() or "://" in str(
        victim_name
    )

    return NormalizedRecord(
        kind=EntityKind.RANSOMWARE_VICTIM,
        source=source,
        dedupe_key=f"{key}|{group}|{discovered.isoformat()}",
        observed_at=discovered,
        raw=raw,
        payload={
            "canonical_key": key,
            "display_name": cleaned or str(victim_name).strip(),
            "raw_names": [str(victim_name)],
            "domain": domain,
            "group_name": group,
            "country": country,
            "sector": sector,
            "website": website,
            "screenshot_url": screenshot,
            "disclosure_status": status,
            "discovered_at": discovered,
            "needs_review": needs_review,
        },
    )


# ==========================================================================
# Vulnerability feeds
# ==========================================================================


@registry.register
class NvdConnector(Connector):
    name = "nvd"
    kind = EntityKind.VULNERABILITY
    label = "NVD API"
    rate_limit_per_minute = 50

    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    PAGE_SIZE = 200

    async def fetch(self, *, since: datetime | None = None) -> AsyncIterator[FetchResult]:
        start = since or datetime.now(UTC) - timedelta(days=90)
        end = datetime.now(UTC)

        headers = {}
        if self.settings.nvd_api_key:
            headers["apiKey"] = self.settings.nvd_api_key.get_secret_value()

        offset = 0
        while True:
            # Structural params. The legacy collector interpolated these into
            # an f-string with doubled braces and shipped literal "{" to NVD.
            params = {
                "pubStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000"),
                "pubEndDate": end.strftime("%Y-%m-%dT%H:%M:%S.000"),
                "resultsPerPage": self.PAGE_SIZE,
                "startIndex": offset,
            }
            try:
                response = await self.client.get(self.BASE_URL, params=params, headers=headers)
                response.raise_for_status()
                data = response.json()
            except (httpx.HTTPError, ValueError) as exc:
                raise ConnectorError(f"NVD request failed: {exc}") from exc

            items = data.get("vulnerabilities", [])
            for item in items:
                yield self._normalize(item)

            offset += len(items)
            if not items or offset >= data.get("totalResults", 0):
                break

    def _normalize(self, item: dict[str, Any]) -> FetchResult:
        cve = item.get("cve") or {}
        cve_id = cve.get("id")
        if not cve_id:
            return Quarantine(source=self.name, reason="missing cve id", raw=item)

        descriptions = cve.get("descriptions") or []
        description = next(
            (d.get("value") for d in descriptions if d.get("lang") == "en"), None
        )

        # v3.1 preferred, v3.0 as fallback — matching the legacy behaviour but
        # without collapsing a missing score to the string "N/A".
        metrics = cve.get("metrics") or {}
        metric = next(
            (m for key in ("cvssMetricV31", "cvssMetricV30") for m in metrics.get(key, [])),
            None,
        )
        score = vector = None
        if metric:
            cvss = metric.get("cvssData") or {}
            score = normalize_cvss(cvss.get("baseScore"))
            vector = cvss.get("vectorString")

        try:
            published = normalize_timestamp(cve.get("published"), source=self.name)
            modified = normalize_timestamp(cve.get("lastModified"), source=self.name)
        except NormalizationError as exc:
            return Quarantine(source=self.name, reason=str(exc), raw=item)

        cpes = [
            match["criteria"]
            for config in cve.get("configurations", [])
            for node in config.get("nodes", [])
            for match in node.get("cpeMatch", [])
            if match.get("criteria")
        ]

        return NormalizedRecord(
            kind=EntityKind.VULNERABILITY,
            source=self.name,
            dedupe_key=cve_id.upper(),
            observed_at=published,
            raw=item,
            payload={
                "cve_id": cve_id.upper(),
                "description": description,
                "cvss_score": score,
                "cvss_vector": vector,
                "severity": severity_from_cvss(score),
                "published_at": published,
                "last_modified_at": modified,
                "cpe_uris": cpes,
            },
        )


@registry.register
class CisaKevConnector(Connector):
    """CISA Known Exploited Vulnerabilities.

    The only feed with trustworthy vendor and product fields, which makes it
    the anchor for matching CVEs against asset inventory.
    """

    name = "cisa_kev"
    kind = EntityKind.VULNERABILITY
    label = "CISA KEV"

    URL = (
        "https://www.cisa.gov/sites/default/files/feeds/"
        "known_exploited_vulnerabilities.json"
    )

    async def fetch(self, *, since: datetime | None = None) -> AsyncIterator[FetchResult]:
        try:
            response = await self.client.get(self.URL)
            response.raise_for_status()
            data = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise ConnectorError(f"CISA KEV request failed: {exc}") from exc

        for item in data.get("vulnerabilities", []):
            cve_id = item.get("cveID")
            if not cve_id:
                yield Quarantine(source=self.name, reason="missing cveID", raw=item)
                continue

            try:
                added = normalize_timestamp(item.get("dateAdded"), source=self.name)
                due = normalize_timestamp(item.get("dueDate"), source=self.name)
            except NormalizationError as exc:
                yield Quarantine(source=self.name, reason=str(exc), raw=item)
                continue

            if since and added and added < since:
                continue

            yield NormalizedRecord(
                kind=EntityKind.VULNERABILITY,
                source=self.name,
                dedupe_key=cve_id.upper(),
                observed_at=added,
                raw=item,
                payload={
                    "cve_id": cve_id.upper(),
                    "title": item.get("vulnerabilityName"),
                    "description": item.get("shortDescription"),
                    "vendor": item.get("vendorProject"),
                    "product": item.get("product"),
                    "is_kev": True,
                    "kev_added_at": added,
                    "kev_due_at": due,
                    # Presence in KEV is the definition of weaponised.
                    "exploit_maturity": "weaponized",
                },
            )


@registry.register
class CxSecurityConnector(Connector):
    """CXSecurity WLB RSS feed."""

    name = "cxsecurity"
    kind = EntityKind.EXPLOIT
    label = "CXSecurity"

    URL = "https://cxsecurity.com/wlb/rss/all"

    async def fetch(self, *, since: datetime | None = None) -> AsyncIterator[FetchResult]:
        try:
            response = await self.client.get(self.URL)
            response.raise_for_status()
            root = ElementTree.fromstring(response.text)
        except (httpx.HTTPError, ElementTree.ParseError) as exc:
            raise ConnectorError(f"CXSecurity request failed: {exc}") from exc

        for item in root.iterfind(".//item"):
            title = (item.findtext("title") or "").strip()
            link = (item.findtext("link") or "").strip()

            # The defect: the legacy parser read <lastBuildDate>, a
            # channel-level tag, so every one of the 40 records carried an
            # identical timestamp. <pubDate> is the per-item tag.
            published_raw = item.findtext("pubDate")

            raw = {"title": title, "link": link, "pubDate": published_raw}
            if not title or not link:
                yield Quarantine(source=self.name, reason="missing title or link", raw=raw)
                continue

            try:
                published = normalize_timestamp(published_raw, source=self.name)
            except NormalizationError as exc:
                yield Quarantine(source=self.name, reason=str(exc), raw=raw)
                continue

            if since and published and published < since:
                continue

            yield NormalizedRecord(
                kind=EntityKind.EXPLOIT,
                source=self.name,
                dedupe_key=link,
                observed_at=published,
                raw=raw,
                payload={
                    "external_id": link.rstrip("/").rsplit("/", 1)[-1] or link,
                    "title": title,
                    "url": link,
                    "published_at": published,
                    # No structured CVE field exists; recover it from the title.
                    "cve_ids": extract_cve_ids(title),
                    "confidence": 0.7,
                },
            )


@registry.register
class GithubPocConnector(Connector):
    """GitHub repository search for public proof-of-concept exploits.

    This feed is the noisiest of the fourteen. A bare ``CVE`` search returned
    a LaTeX CV template and an unrelated key-management tool. Rather than
    dropping or trusting everything, each hit gets a confidence score and the
    API filters on it.
    """

    name = "github_poc"
    kind = EntityKind.EXPLOIT
    label = "GitHub PoC"

    URL = "https://api.github.com/search/repositories"
    MIN_CONFIDENCE = 0.4

    @property
    def is_enabled(self) -> bool:
        # Unauthenticated search is limited to 10 requests/minute, which is
        # not enough to be useful.
        return self.settings.github_token is not None

    async def fetch(self, *, since: datetime | None = None) -> AsyncIterator[FetchResult]:
        start = since or datetime.now(UTC) - timedelta(days=90)
        headers = {"Accept": "application/vnd.github+json"}
        if self.settings.github_token:
            headers["Authorization"] = (
                f"Bearer {self.settings.github_token.get_secret_value()}"
            )

        params = {
            "q": f"CVE created:>={start.date().isoformat()}",
            "sort": "updated",
            "order": "desc",
            "per_page": 100,
        }
        try:
            response = await self.client.get(self.URL, params=params, headers=headers)
            response.raise_for_status()
            data = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise ConnectorError(f"GitHub search failed: {exc}") from exc

        for item in data.get("items", []):
            record = self._normalize(item)
            if record is not None:
                yield record

    def _normalize(self, item: dict[str, Any]) -> FetchResult | None:
        full_name = item.get("full_name")
        if not full_name:
            return Quarantine(source=self.name, reason="missing full_name", raw=item)

        description = item.get("description") or ""
        cve_ids = extract_cve_ids(full_name, description)
        confidence = self._score(full_name, description, cve_ids, item.get("stargazers_count", 0))

        # Below the floor this is almost certainly not an exploit PoC.
        if confidence < self.MIN_CONFIDENCE:
            return None

        try:
            created = normalize_timestamp(item.get("created_at"), source=self.name)
        except NormalizationError as exc:
            return Quarantine(source=self.name, reason=str(exc), raw=item)

        return NormalizedRecord(
            kind=EntityKind.EXPLOIT,
            source=self.name,
            dedupe_key=full_name,
            observed_at=created,
            raw=item,
            payload={
                "external_id": full_name,
                "title": full_name,
                "url": item.get("html_url"),
                "stars": item.get("stargazers_count"),
                "published_at": created,
                "cve_ids": cve_ids,
                "confidence": confidence,
            },
        )

    @staticmethod
    def _score(
        full_name: str, description: str, cve_ids: list[str], stars: int
    ) -> float:
        """Heuristic confidence that a repository is a genuine exploit PoC."""
        score = 0.0
        haystack = f"{full_name} {description}".lower()

        # A well-formed CVE id in the name is the strongest single signal.
        if any(cve.lower() in full_name.lower() for cve in cve_ids):
            score += 0.5
        elif cve_ids:
            score += 0.25

        for term in ("exploit", "poc", "rce", "lpe", "payload", "vulnerab", "0day"):
            if term in haystack:
                score += 0.12

        # Known false-positive shapes seen in the sample data.
        for term in ("curriculum", "resume", "cv_temp", "cv-template", "awesome-"):
            if term in haystack:
                score -= 0.45

        if stars >= 50:
            score += 0.15
        elif stars >= 5:
            score += 0.05

        return max(0.0, min(1.0, score))


@registry.register
class ExploitDbConnector(Connector):
    name = "exploitdb"
    kind = EntityKind.EXPLOIT
    label = "Exploit-DB"

    URL = "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"

    async def fetch(self, *, since: datetime | None = None) -> AsyncIterator[FetchResult]:
        import csv
        import io

        try:
            response = await self.client.get(self.URL, timeout=120.0)
            response.raise_for_status()
        except httpx.HTTPError as exc:
            raise ConnectorError(f"Exploit-DB request failed: {exc}") from exc

        reader = csv.DictReader(io.StringIO(response.text))
        for row in reader:
            try:
                published = normalize_timestamp(row.get("date_published"), source=self.name)
            except NormalizationError as exc:
                yield Quarantine(source=self.name, reason=str(exc), raw=dict(row))
                continue

            if since and published and published < since:
                continue

            exploit_id = row.get("id")
            if not exploit_id:
                yield Quarantine(source=self.name, reason="missing id", raw=dict(row))
                continue

            yield NormalizedRecord(
                kind=EntityKind.EXPLOIT,
                source=self.name,
                dedupe_key=exploit_id,
                observed_at=published,
                raw=dict(row),
                payload={
                    "external_id": exploit_id,
                    "title": row.get("description"),
                    "url": f"{{https://www.exploit-db.com/exploits/{exploit_id}}}",
                    "author": row.get("author"),
                    "platform": row.get("platform"),
                    "published_at": published,
                    # One field can pack several CVEs; split rather than store
                    # the raw string.
                    "cve_ids": extract_cve_ids(row.get("codes"), row.get("description")),
                    "confidence": 0.9,
                },
            )


@registry.register
class OsvConnector(Connector):
    """OSV.dev package vulnerability queries."""

    name = "osv"
    kind = EntityKind.VULNERABILITY
    label = "OSV.dev"

    URL = "https://api.osv.dev/v1/query"

    # The legacy script hardcoded eight packages. Keeping the list explicit
    # and visible is better than pretending the coverage is universal.
    WATCHED = (
        ("PyPI", "jinja2"), ("PyPI", "django"), ("PyPI", "flask"),
        ("PyPI", "requests"), ("PyPI", "urllib3"), ("PyPI", "numpy"),
        ("npm", "express"), ("npm", "lodash"),
    )

    async def fetch(self, *, since: datetime | None = None) -> AsyncIterator[FetchResult]:
        seen: set[str] = set()
        for ecosystem, package in self.WATCHED:
            body = {"package": {"name": package, "ecosystem": ecosystem}}
            try:
                response = await self.client.post(self.URL, json=body)
                response.raise_for_status()
                data = response.json()
            except (httpx.HTTPError, ValueError) as exc:
                raise ConnectorError(f"OSV request failed for {package}: {exc}") from exc

            for vuln in data.get("vulns", []):
                osv_id = vuln.get("id")
                if not osv_id or osv_id in seen:
                    continue
                seen.add(osv_id)

                try:
                    published = normalize_timestamp(vuln.get("published"), source=self.name)
                    modified = normalize_timestamp(vuln.get("modified"), source=self.name)
                except NormalizationError as exc:
                    yield Quarantine(source=self.name, reason=str(exc), raw=vuln)
                    continue

                if since and published and published < since:
                    continue

                aliases = [a for a in vuln.get("aliases", []) if a.upper().startswith("CVE-")]
                yield NormalizedRecord(
                    kind=EntityKind.VULNERABILITY,
                    source=self.name,
                    dedupe_key=(aliases[0].upper() if aliases else osv_id),
                    observed_at=published,
                    raw=vuln,
                    payload={
                        "cve_id": aliases[0].upper() if aliases else osv_id,
                        "title": vuln.get("summary"),
                        "description": vuln.get("details"),
                        "published_at": published,
                        "last_modified_at": modified,
                        "package": package,
                        "ecosystem": ecosystem,
                    },
                )


# ==========================================================================
# Ransomware feeds
# ==========================================================================


@registry.register
class RansomwareLiveConnector(Connector):
    name = "ransomware_live"
    kind = EntityKind.RANSOMWARE_VICTIM
    label = "Ransomware.live"

    URL = "https://api-pro.ransomware.live/victims/recent"

    @property
    def is_enabled(self) -> bool:
        # The legacy script embedded this key in source. Absent a configured
        # key the connector reports itself disabled rather than failing.
        return self.settings.ransomware_live_api_key is not None

    async def fetch(self, *, since: datetime | None = None) -> AsyncIterator[FetchResult]:
        if not self.is_enabled:
            raise ConnectorError("RANSOMWARE_LIVE_API_KEY is not configured")

        headers = {"X-API-KEY": self.settings.ransomware_live_api_key.get_secret_value()}
        try:
            response = await self.client.get(self.URL, headers=headers)
            response.raise_for_status()
            data = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise ConnectorError(f"Ransomware.live request failed: {exc}") from exc

        for item in data if isinstance(data, list) else data.get("victims", []):
            yield _victim_record(
                source=self.name,
                raw=item,
                victim_name=item.get("victim_name") or item.get("victim") or "",
                group_name=item.get("group_name") or item.get("group"),
                discovered_raw=item.get("discovered_at") or item.get("discovered"),
                country=item.get("country"),
                sector=item.get("sector"),
                website=item.get("website"),
                screenshot=item.get("screenshot"),
            )


@registry.register
class RansomLookConnector(Connector):
    name = "ransomlook"
    kind = EntityKind.RANSOMWARE_VICTIM
    label = "RansomLook"

    URL = "https://www.ransomlook.io/api/posts"

    async def fetch(self, *, since: datetime | None = None) -> AsyncIterator[FetchResult]:
        try:
            response = await self.client.get(self.URL, timeout=90.0)
            response.raise_for_status()
            data = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise ConnectorError(f"RansomLook request failed: {exc}") from exc

        for item in data if isinstance(data, list) else []:
            yield _victim_record(
                source=self.name,
                raw=item,
                victim_name=item.get("post_title") or item.get("victim_name") or "",
                group_name=item.get("group_name"),
                discovered_raw=item.get("discovered") or item.get("discovered_at"),
            )


@registry.register
class DlsMonitorConnector(Connector):
    """dls-monitor leak-site tracker.

    Emits naive timestamps; :data:`NAIVE_SOURCE_TIMEZONES` pins the feed to
    UTC so ingest does not depend on the worker's local zone.
    """

    name = "dls_monitor"
    kind = EntityKind.RANSOMWARE_VICTIM
    label = "dls-monitor"

    URL = "https://raw.githubusercontent.com/cyberiskvision/dls-monitor/main/posts.json"

    async def fetch(self, *, since: datetime | None = None) -> AsyncIterator[FetchResult]:
        try:
            response = await self.client.get(self.URL)
            response.raise_for_status()
            data = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise ConnectorError(f"dls-monitor request failed: {exc}") from exc

        for item in data if isinstance(data, list) else data.get("posts", []):
            yield _victim_record(
                source=self.name,
                raw=item,
                victim_name=item.get("victim_name") or item.get("title") or "",
                group_name=item.get("group_name") or item.get("group"),
                discovered_raw=item.get("discovered_at") or item.get("date"),
            )


@registry.register
class RansomwhereConnector(Connector):
    """Ransomwhere crypto-payment tracker.

    The sample dump for this feed was seed data: placeholder wallet addresses
    such as ``bc1qxyz1234567890abcde`` and an identical ``reported_at`` on
    every row. :meth:`_looks_like_seed_data` refuses to ingest that shape so
    fake figures never reach a report.
    """

    name = "ransomwhere"
    kind = EntityKind.INDICATOR
    label = "Ransomwhere"

    URL = "https://api.ransomwhe.re/submittedAddresses"

    _PLACEHOLDER = re.compile(r"(1234567890|abcde|xyz|test|sample|placeholder)", re.IGNORECASE)

    async def fetch(self, *, since: datetime | None = None) -> AsyncIterator[FetchResult]:
        try:
            response = await self.client.get(self.URL)
            response.raise_for_status()
            data = response.json()
        except (httpx.HTTPError, ValueError) as exc:
            raise ConnectorError(f"Ransomwhere request failed: {exc}") from exc

        for item in data.get("result", []) if isinstance(data, dict) else data:
            address = item.get("address")
            if not address:
                yield Quarantine(source=self.name, reason="missing address", raw=item)
                continue

            if self._looks_like_seed_data(address):
                yield Quarantine(
                    source=self.name,
                    reason="address matches placeholder/seed pattern",
                    raw=item,
                )
                continue

            try:
                reported = normalize_timestamp(
                    item.get("createdAt") or item.get("reported_at"), source=self.name
                )
            except NormalizationError as exc:
                yield Quarantine(source=self.name, reason=str(exc), raw=item)
                continue

            yield NormalizedRecord(
                kind=EntityKind.INDICATOR,
                source=self.name,
                dedupe_key=f"btc-address|{address}",
                observed_at=reported,
                raw=item,
                payload={
                    "indicator_type": "btc-address",
                    "value": address,
                    "verdict": "malicious",
                    "tags": [t for t in (item.get("family"),) if t],
                    "first_seen": reported,
                },
            )

    @classmethod
    def _looks_like_seed_data(cls, address: str) -> bool:
        return bool(cls._PLACEHOLDER.search(address))
