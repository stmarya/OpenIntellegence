"""Contract tests for deterministic investigation-graph helpers."""

from app.api.v1.graph import label_from_evidence, node_key, upsert_node


def test_node_key_keeps_type_and_identifier_unambiguous() -> None:
    assert node_key("indicator", "example.org") == "indicator:example.org"
    assert node_key("asset", "example.org") != node_key("indicator", "example.org")


def test_evidence_label_is_used_only_when_persisted() -> None:
    evidence = {"source_label": "APT Example"}
    assert label_from_evidence(evidence, "source", "actor-1") == "APT Example"
    assert label_from_evidence(evidence, "target", "asset-1") == "asset-1"


def test_blank_evidence_label_falls_back_to_identifier() -> None:
    assert label_from_evidence({"source_label": ""}, "source", "cve-1") == "cve-1"
    assert label_from_evidence({}, "source", "cve-1") == "cve-1"


def test_persisted_label_enriches_an_id_only_seed() -> None:
    seed = ("campaign", "campaign-1")
    nodes = {
        node_key(*seed): {
            "key": node_key(*seed),
            "entity_type": seed[0],
            "entity_id": seed[1],
            "label": seed[1],
            "is_seed": True,
        }
    }
    upsert_node(nodes, seed, seed, "Named campaign")
    assert nodes[node_key(*seed)]["label"] == "Named campaign"
    assert nodes[node_key(*seed)]["is_seed"] is True
