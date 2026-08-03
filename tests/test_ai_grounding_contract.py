from app.ai.grounding import WITHHELD_ANSWER, enforce_citation_contract
from app.api.schemas import Citation

def citation() -> Citation:
    return Citation(entity_type="vulnerability", entity_id="CVE-2026-0001", title="CVE-2026-0001", source="nvd", url=None)

def test_accepts_valid_marker() -> None:
    answer, valid = enforce_citation_contract("Observed in the record [1].", [citation()], generated=True)
    assert valid and answer.endswith("[1].")

def test_withholds_uncited_model_prose() -> None:
    answer, valid = enforce_citation_contract("Confident but unsupported.", [citation()], generated=True)
    assert not valid and answer == WITHHELD_ANSWER

def test_withholds_out_of_range_marker() -> None:
    answer, valid = enforce_citation_contract("Unsupported [2].", [citation()], generated=True)
    assert not valid and answer == WITHHELD_ANSWER

def test_non_model_evidence_listing_is_preserved() -> None:
    answer, valid = enforce_citation_contract("Matching records: [1]", [citation()], generated=False)
    assert valid and answer == "Matching records: [1]"
