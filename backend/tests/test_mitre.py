"""Tests for official MITRE ATT&CK STIX lookup and standardization."""

import json

import httpx
import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.models.incident import EvidenceType, IndicatorType
from app.services.mitre_client import (
    MITREClient,
    MITREInvalidTechniqueIDError,
    MITRENotFoundError,
    MITREResponseError,
)

TECHNIQUE = {
    "type": "attack-pattern",
    "id": "attack-pattern--sample",
    "name": "Spearphishing Link",
    "description": "Adversaries may send spearphishing emails with a malicious link.",
    "external_references": [
        {"source_name": "mitre-attack", "external_id": "T1566.002", "url": "https://attack.mitre.org/techniques/T1566/002/"},
        {"source_name": "example", "url": "https://example.test/reference", "description": "Related material"},
    ],
    "kill_chain_phases": [{"kill_chain_name": "mitre-attack", "phase_name": "initial-access"}],
    "x_mitre_platforms": ["Office 365", "SaaS"],
    "x_mitre_is_subtechnique": True,
    "custom_property": "preserved",
}


def make_transport(objects=None, status=200, malformed=False):
    def handler(request):
        if malformed:
            return httpx.Response(200, content="not json")
        return httpx.Response(status, json={"type": "bundle", "objects": objects or []})
    return httpx.MockTransport(handler)


def test_valid_technique_lookup_preserves_metadata_and_provenance():
    technique = MITREClient().get_technique("t1566.002", make_transport([TECHNIQUE]))
    assert technique.technique_id == "T1566.002"
    assert technique.name == "Spearphishing Link"
    assert technique.tactics == ["initial-access"]
    assert technique.platforms == ["Office 365", "SaaS"]
    assert technique.is_subtechnique is True
    assert technique.parent_technique_id == "T1566"
    assert technique.source == "MITRE ATT&CK"
    assert technique.provenance == "MITRE ATT&CK STIX 2.1"
    assert technique.raw["custom_property"] == "preserved"
    assert len(technique.references) == 2


def test_invalid_technique_id():
    with pytest.raises(MITREInvalidTechniqueIDError):
        MITREClient().get_technique("T12.2", make_transport([TECHNIQUE]))


def test_not_found():
    with pytest.raises(MITRENotFoundError):
        MITREClient().get_technique("T9999", make_transport([]))


def test_conversion_to_indicator_and_evidence():
    client = MITREClient()
    technique = client.get_technique("T1566.002", make_transport([TECHNIQUE]))
    indicator, evidence = client.convert_to_standardized_evidence(technique)
    assert indicator.indicator_type == IndicatorType.MITRE_ATTACK.value
    assert indicator.value == "T1566.002"
    assert indicator.confidence is None
    assert evidence.evidence_type == EvidenceType.THREAT_INTEL_FEED.value
    assert evidence.confidence is None
    assert evidence.raw_reference.endswith("T1566/002/")
    assert evidence.metadata["technique_name"] == "Spearphishing Link"
    assert evidence.metadata["provenance"] == "MITRE ATT&CK STIX 2.1"
    assert evidence.metadata["raw"]["custom_property"] == "preserved"


def test_malformed_data():
    with pytest.raises(MITREResponseError):
        MITREClient().get_technique("T1566.002", make_transport(malformed=True))


def test_api_route(monkeypatch):
    from app.api.v1 import intelligence
    monkeypatch.setattr(intelligence.mitre_client, "get_technique_and_convert",
                        lambda technique_id: MITREClient().get_technique_and_convert(technique_id, make_transport([TECHNIQUE])))
    response = TestClient(app).get("/api/v1/intelligence/mitre/T1566.002")
    assert response.status_code == 200
    assert response.json()["indicator"]["value"] == "T1566.002"
