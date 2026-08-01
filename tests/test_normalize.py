"""Tests for the normalisation layer.

Each test here corresponds to a defect measured in the legacy collectors.
They are regression tests for real bugs, not coverage padding.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

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


class TestTimestamps:
    """The four feeds emit four different timestamp formats."""

    def test_iso_with_offset(self) -> None:
        result = normalize_timestamp(
            "2026-05-22T12:22:53.893934+00:00", source="ransomware_live"
        )
        assert result == datetime(2026, 5, 22, 12, 22, 53, 893934, tzinfo=UTC)

    def test_iso_with_z_suffix(self) -> None:
        result = normalize_timestamp("2026-04-22T13:51:40.383126Z", source="ransomlook")
        assert result is not None
        assert result.tzinfo is not None
        assert result.utcoffset().total_seconds() == 0

    def test_naive_timestamp_uses_declared_source_timezone(self) -> None:
        """dls-monitor emits no timezone at all.

        Guessing the server's local zone would silently shift every record.
        The source's zone is declared explicitly instead.
        """
        result = normalize_timestamp("2026-02-22 18:50:27.653790", source="dls_monitor")
        assert result is not None
        assert result.tzinfo is not None
        assert result.hour == 18

    def test_named_timezone_abbreviation(self) -> None:
        """CXSecurity emits 'CET', which stdlib parsers reject."""
        result = normalize_timestamp("2026-05-19 21:17:49 CET", source="cxsecurity")
        assert result is not None
        assert result.tzinfo is not None
        # CET is UTC+1, so 21:17 local is 20:17 UTC.
        assert result.astimezone(UTC).hour == 20

    def test_every_result_is_timezone_aware(self) -> None:
        samples = [
            ("2026-05-22T12:22:53.893934+00:00", "ransomware_live"),
            ("2026-04-22T13:51:40.383126Z", "ransomlook"),
            ("2026-02-22 18:50:27.653790", "dls_monitor"),
            ("2026-05-19 21:17:49 CET", "cxsecurity"),
        ]
        for value, source in samples:
            result = normalize_timestamp(value, source=source)
            assert result is not None and result.tzinfo is not None, value

    @pytest.mark.parametrize("value", [None, "", "   ", "N/A"])
    def test_empty_values_are_none(self, value) -> None:
        assert normalize_timestamp(value, source="nvd") is None

    def test_unparseable_raises_so_caller_can_quarantine(self) -> None:
        """Silently dropping a bad date is how parser bugs go unnoticed."""
        with pytest.raises(NormalizationError):
            normalize_timestamp("not a date at all", source="cxsecurity")


class TestCveExtraction:
    def test_extracts_from_packed_string(self) -> None:
        """Exploit-DB packs several CVEs into one field."""
        assert extract_cve_ids("CVE-2026-33824;CVE-2026-31431") == [
            "CVE-2026-33824",
            "CVE-2026-31431",
        ]

    def test_case_insensitive_and_uppercased(self) -> None:
        assert extract_cve_ids("cve-2026-2905") == ["CVE-2026-2905"]

    def test_deduplicates_preserving_order(self) -> None:
        assert extract_cve_ids("CVE-2026-1 CVE-2026-9999 CVE-2026-9999") == ["CVE-2026-9999"]

    def test_ignores_non_cve_text(self) -> None:
        assert extract_cve_ids("CV_temp corridorkey_ofx thread-analyzer") == []

    def test_reads_multiple_fields(self) -> None:
        assert extract_cve_ids("CVE-2026-1111", None, "see CVE-2026-2222") == [
            "CVE-2026-1111",
            "CVE-2026-2222",
        ]


class TestCvss:
    def test_na_string_becomes_none_not_zero(self) -> None:
        """NVD returns the string 'N/A'.

        Coercing that to 0.0 would file an unscored CVE as harmless.
        """
        assert normalize_cvss("N/A") is None

    @pytest.mark.parametrize("value", [None, "", "unknown", "-"])
    def test_missing_variants_become_none(self, value) -> None:
        assert normalize_cvss(value) is None

    def test_valid_scores_parse(self) -> None:
        assert normalize_cvss("9.8") == 9.8
        assert normalize_cvss(7) == 7.0

    @pytest.mark.parametrize("value", ["-1", "10.1", "99"])
    def test_out_of_range_rejected(self, value) -> None:
        assert normalize_cvss(value) is None

    def test_zero_is_a_real_score(self) -> None:
        """0.0 is valid CVSS and must survive, unlike a missing value."""
        assert normalize_cvss("0.0") == 0.0

    def test_severity_bands(self) -> None:
        assert severity_from_cvss(9.8) == "critical"
        assert severity_from_cvss(7.8) == "high"
        assert severity_from_cvss(5.0) == "medium"
        assert severity_from_cvss(2.0) == "low"
        assert severity_from_cvss(None) is None


class TestVictimNames:
    def test_strips_prefix_with_space(self) -> None:
        assert strip_status_prefix("[DISCLOSED] Irec Sas") == ("Irec Sas", "DISCLOSED")

    def test_strips_prefix_without_space(self) -> None:
        """The feed is inconsistent about the separating space."""
        assert strip_status_prefix("[DISCLOSED]Bioptik Technology") == (
            "Bioptik Technology",
            "DISCLOSED",
        )

    def test_leaves_clean_names_untouched(self) -> None:
        assert strip_status_prefix("Acme Corp") == ("Acme Corp", None)

    def test_extracts_domain_from_url(self) -> None:
        assert extract_domain("https://www.pyramisgroup.com") == "pyramisgroup.com"

    def test_extracts_bare_domain(self) -> None:
        assert extract_domain("thinlinetech.com") == "thinlinetech.com"

    def test_company_name_is_not_a_domain(self) -> None:
        assert extract_domain("Bioptik Technology") is None

    def test_domain_wins_as_canonical_key(self) -> None:
        """The same victim appears as a URL in one feed and a name in another."""
        from_url = canonical_victim_key("https://www.pyramisgroup.com")
        from_bare = canonical_victim_key("pyramisgroup.com")
        assert from_url == from_bare

    def test_corporate_suffixes_ignored_when_matching(self) -> None:
        assert canonical_victim_key("PT Nusantara Digital") == canonical_victim_key(
            "Nusantara Digital"
        )

    def test_group_names_are_case_folded(self) -> None:
        assert normalize_group_name("LockBit 3.0") == normalize_group_name("lockbit 3.0")
        assert normalize_group_name("  Play ") == "play"
