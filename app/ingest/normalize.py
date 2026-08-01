"""Normalisation primitives shared by every connector.

This module exists because of concrete defects measured in the legacy
``collected_data/`` dump. Each function below is a direct answer to one of
them, and the docstrings name the defect so the intent survives refactoring.

Observed problems
-----------------
1. Three mutually incompatible timestamp formats across ransomware feeds:
   - dls-monitor      ``2026-02-22 18:50:27.653790``      (naive, no zone)
   - Ransomware.live  ``2026-05-22T12:22:53.893934+00:00``
   - RansomLook       ``2026-04-22T13:51:40.383126Z``
   - CXSecurity       ``2026-05-19 21:17:49 CET``          (zone abbreviation)
2. ``victim_name`` arrives as a company name, a bare domain, a full URL, or a
   name carrying a ``[DISCLOSED]`` status prefix — sometimes without a space
   after the bracket. Exact string matching across feeds does not work.
3. Records carry no ``source`` field; provenance lived only in the filename
   and was destroyed on merge.
4. ``cvss_score`` falls back to the string ``"N/A"``, producing a column with
   mixed float and string types.
5. Exploit-DB packs multiple CVEs into one ``cve_codes`` string.
6. CXSecurity and GitHub PoC have no structured CVE field at all.
"""

from __future__ import annotations

import re
import unicodedata
from datetime import UTC, datetime, timedelta, timezone
from urllib.parse import urlparse

from dateutil import parser as date_parser
from dateutil import tz

# --------------------------------------------------------------------------
# Timestamps
# --------------------------------------------------------------------------

# Feeds that emit naive timestamps and the zone they are actually in.
# dls-monitor publishes from a UTC pipeline despite omitting the offset;
# assuming local time here would silently shift every record by hours.
NAIVE_SOURCE_TIMEZONES: dict[str, str] = {
    "dls_monitor": "UTC",
    "ransomwhere": "UTC",
}

# ``dateutil`` refuses to resolve bare zone abbreviations without a hint.
# CET/CEST are given as fixed offsets so that the same abbreviation always
# resolves the same way regardless of when the worker runs, avoiding
# DST-sensitive output when the feed writes the abbreviation explicitly.
_TZ_ABBREVIATIONS = {
    "UTC": tz.UTC,
    "GMT": tz.UTC,
    "CET": timezone(timedelta(hours=1)),
    "CEST": timezone(timedelta(hours=2)),
    "EST": timezone(timedelta(hours=-5)),
    "EDT": timezone(timedelta(hours=-4)),
    "PST": timezone(timedelta(hours=-8)),
    "PDT": timezone(timedelta(hours=-7)),
    "WIB": timezone(timedelta(hours=7)),
}


class NormalizationError(ValueError):
    """Raised when a value cannot be normalised and must be quarantined."""


def normalize_timestamp(value: str | datetime | None, *, source: str) -> datetime | None:
    """Coerce any feed timestamp into a timezone-aware UTC ``datetime``.

    Naive inputs are interpreted using :data:`NAIVE_SOURCE_TIMEZONES` for the
    given ``source`` rather than the server's local zone, so ingest results do
    not depend on where the worker happens to run.

    Returns ``None`` for empty input. Raises :class:`NormalizationError` for
    input that is present but unparseable, so the caller can quarantine the
    record instead of storing a wrong time.
    """
    if value is None:
        return None

    if isinstance(value, datetime):
        dt = value
    else:
        raw = value.strip()
        if not raw or raw.upper() in {"N/A", "NA", "NULL", "-", "\u2014"}:
            return None
        try:
            dt = date_parser.parse(raw, tzinfos=_TZ_ABBREVIATIONS)
        except (ValueError, OverflowError) as exc:
            raise NormalizationError(f"unparseable timestamp {raw!r} from {source}") from exc

    if dt.tzinfo is None:
        zone_name = NAIVE_SOURCE_TIMEZONES.get(source, "UTC")
        zone = tz.gettz(zone_name) or UTC
        dt = dt.replace(tzinfo=zone)

    return dt.astimezone(UTC)


# --------------------------------------------------------------------------
# CVE identifiers
# --------------------------------------------------------------------------

CVE_PATTERN = re.compile(r"CVE-(?:19|20)\d{2}-\d{4,7}", re.IGNORECASE)


def extract_cve_ids(*values: str | None) -> list[str]:
    """Pull every distinct CVE id out of arbitrary free text.

    Handles Exploit-DB's packed ``cve_codes`` string as well as CXSecurity
    titles and GitHub PoC repository names, none of which expose a structured
    CVE field. Results are upper-cased and de-duplicated with order preserved,
    which keeps ingest output byte-stable and therefore diffable.
    """
    seen: dict[str, None] = {}
    for value in values:
        if not value:
            continue
        for match in CVE_PATTERN.finditer(value):
            seen.setdefault(match.group(0).upper(), None)
    return list(seen)


# --------------------------------------------------------------------------
# CVSS
# --------------------------------------------------------------------------


def normalize_cvss(value: object) -> float | None:
    """Return a CVSS score as a float, or ``None`` when genuinely absent.

    The upstream collector wrote the literal string ``"N/A"`` into this field,
    giving the column mixed types. A missing score is modelled as ``None`` and
    must be rendered as an explicit em dash in the UI — never as ``0.0``,
    which would wrongly read as "harmless".
    """
    if value is None or isinstance(value, bool):
        return None
    if isinstance(value, int | float):
        score = float(value)
    else:
        raw = str(value).strip()
        if not raw or raw.upper() in {"N/A", "NA", "NULL", "NONE", "-", "\u2014"}:
            return None
        try:
            score = float(raw)
        except ValueError:
            return None

    # Scores outside the specification are corrupt, not merely odd.
    return score if 0.0 <= score <= 10.0 else None


def severity_from_cvss(score: float | None) -> str | None:
    """CVSS v3.1 qualitative rating."""
    if score is None:
        return None
    if score == 0.0:
        return "none"
    if score < 4.0:
        return "low"
    if score < 7.0:
        return "medium"
    if score < 9.0:
        return "high"
    return "critical"


# --------------------------------------------------------------------------
# Victim names
# --------------------------------------------------------------------------

_STATUS_PREFIX = re.compile(r"^\s*\[\s*([A-Z ]{3,20})\s*\]\s*", re.IGNORECASE)

_CORPORATE_SUFFIXES = {
    "inc", "llc", "ltd", "limited", "corp", "corporation", "co", "company",
    "gmbh", "ag", "sa", "sas", "srl", "spa", "bv", "nv", "plc", "pty",
    "pt", "cv", "tbk", "group", "holdings", "holding",
}

_WWW = re.compile(r"^www\d*\.")


def strip_status_prefix(name: str) -> tuple[str, str | None]:
    """Split a leading ``[DISCLOSED]``-style marker off a victim name.

    Both ``"[DISCLOSED] Irec Sas"`` and ``"[DISCLOSED]Bioptik Technology"``
    occur in the wild; the missing space is why a naive ``split()`` fails.
    """
    match = _STATUS_PREFIX.match(name)
    if not match:
        return name.strip(), None
    return name[match.end() :].strip(), match.group(1).strip().upper()


def extract_domain(value: str) -> str | None:
    """Return a bare registrable-ish domain from a URL or hostname.

    ``https://www.pyramisgroup.com/x`` and ``thinlinetech.com`` both appear as
    ``victim_name`` values, so this has to accept either shape.
    """
    raw = value.strip().lower()
    if not raw:
        return None

    if "://" in raw:
        host = urlparse(raw).netloc
    elif "/" in raw:
        host = raw.split("/", 1)[0]
    else:
        host = raw

    host = host.split("@")[-1].split(":")[0].strip().strip(".")
    if not host or " " in host or "." not in host:
        return None

    host = _WWW.sub("", host)
    # Reject things that merely contain a dot, like "Corp. Holdings".
    if not re.fullmatch(r"[a-z0-9.-]+\.[a-z]{2,24}", host):
        return None
    return host


def canonical_victim_key(name: str) -> str:
    """Build a stable join key for cross-feed victim de-duplication.

    The same organisation appears across RansomLook, Ransomware.live and
    dls-monitor in different shapes. This collapses casing, punctuation,
    accents, corporate suffixes and URL wrappers so the three can be matched.

    A domain always wins over a display name, because domains are the one
    identifier the feeds agree on.
    """
    cleaned, _status = strip_status_prefix(name)

    domain = extract_domain(cleaned)
    if domain:
        return domain

    text = unicodedata.normalize("NFKD", cleaned)
    text = text.encode("ascii", "ignore").decode("ascii").lower()
    text = re.sub(r"[^a-z0-9\s]", " ", text)

    tokens = [t for t in text.split() if t and t not in _CORPORATE_SUFFIXES]
    return " ".join(tokens) if tokens else cleaned.strip().lower()


def normalize_group_name(name: str | None) -> str | None:
    """Canonicalise a ransomware group name.

    Feeds disagree on casing and spacing (``"LockBit 3.0"`` / ``"lockbit3"``,
    ``"money message"`` / ``"Money Message"``).
    """
    if not name:
        return None
    text = unicodedata.normalize("NFKD", name)
    text = text.encode("ascii", "ignore").decode("ascii").lower().strip()
    text = re.sub(r"[^a-z0-9]+", "", text)
    return text or None
