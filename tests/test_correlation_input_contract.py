"""Request-model contracts that prevent client-supplied correlation scoring."""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from app.api.v1.correlations import CorrelationEvaluate


def test_supported_entity_identity_is_accepted() -> None:
    item = CorrelationEvaluate(title="Investigate CVE", primary_entity_type="vulnerability", primary_entity_id="cve-row")
    assert item.primary_entity_type == "vulnerability"


@pytest.mark.parametrize("entity_type", ["host", "source_run", "campaign", "unknown"])
def test_unsupported_entity_type_is_rejected_before_handler(entity_type: str) -> None:
    with pytest.raises(ValidationError):
        CorrelationEvaluate(title="Invalid type", primary_entity_type=entity_type, primary_entity_id="row")


@pytest.mark.parametrize("field,value", [("cvss_score", 10), ("is_kev", True), ("sighting_count", 99), ("risk_score", 100)])
def test_client_scoring_fields_are_forbidden(field: str, value: object) -> None:
    with pytest.raises(ValidationError):
        CorrelationEvaluate.model_validate({"title": "No client score", "primary_entity_type": "asset", "primary_entity_id": "asset-row", field: value})


def test_annotation_is_separate_from_scoring_input() -> None:
    item = CorrelationEvaluate(title="Analyst annotation", primary_entity_type="indicator", primary_entity_id="indicator-row", manual_annotation={"note": "needs review"})
    assert item.manual_annotation == {"note": "needs review"}
