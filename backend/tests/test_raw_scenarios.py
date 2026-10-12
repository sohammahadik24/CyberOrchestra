"""Tests for Step 2B simulated incident scenarios under backend/data/raw/incidents/."""

import ipaddress
import json
from pathlib import Path
import re
import pytest

from app.models.incident import Incident, IndicatorType
from app.services.normalizer import DataNormalizer

SCENARIO_FILES = [
    "incident_001_network.json",
    "incident_002_phishing.json",
    "incident_003_endpoint.json",
    "incident_004_vulnerability.json",
    "incident_005_multi_signal.json",
]

DOC_IP_NETWORKS = [
    ipaddress.ip_network("192.0.2.0/24"),    # TEST-NET-1 (RFC 5737)
    ipaddress.ip_network("198.51.100.0/24"), # TEST-NET-2 (RFC 5737)
    ipaddress.ip_network("203.0.113.0/24"),  # TEST-NET-3 (RFC 5737)
]

SAFE_DOMAINS = ("example.com", "example.org", "example.net", ".test", ".simulated")


@pytest.fixture
def incidents_dir() -> Path:
    return Path(__file__).resolve().parent.parent / "data" / "raw" / "incidents"


@pytest.fixture
def normalizer() -> DataNormalizer:
    return DataNormalizer()


def test_all_five_scenarios_exist(incidents_dir: Path):
    """Verify that all five required scenario files exist in backend/data/raw/incidents/."""
    assert incidents_dir.is_dir(), f"Directory not found: {incidents_dir}"
    for filename in SCENARIO_FILES:
        filepath = incidents_dir / filename
        assert filepath.is_file(), f"Missing required scenario file: {filename}"


def test_scenarios_load_and_normalize(incidents_dir: Path, normalizer: DataNormalizer):
    """Verify each scenario loads as valid JSON and successfully normalizes into an Incident."""
    for filename in SCENARIO_FILES:
        filepath = incidents_dir / filename
        with open(filepath, "r", encoding="utf-8") as f:
            raw_data = json.load(f)

        assert isinstance(raw_data, dict), f"{filename} content must be a JSON object"

        # Pass through normalizer
        normalized = normalizer.normalize(raw_data)

        # Validate Pydantic Incident model compliance
        assert isinstance(normalized, Incident)
        assert bool(normalized.incident_id.strip())
        assert bool(normalized.incident_type.strip())
        assert bool(normalized.description.strip())
        assert bool(normalized.source.strip())
        assert normalized.timestamp is not None
        assert len(normalized.indicators) > 0
        assert len(normalized.evidence) > 0


def test_source_provenance_preserved(incidents_dir: Path, normalizer: DataNormalizer):
    """Verify that source provenance is maintained across all indicators and evidence items."""
    for filename in SCENARIO_FILES:
        filepath = incidents_dir / filename
        with open(filepath, "r", encoding="utf-8") as f:
            raw_data = json.load(f)

        normalized = normalizer.normalize(raw_data)

        # Root source
        assert normalized.source == raw_data.get("source")

        # Indicators provenance
        for idx, ind in enumerate(normalized.indicators):
            raw_ind = raw_data["indicators"][idx]
            expected_src = raw_ind.get("source") or raw_data["source"]
            assert ind.source == expected_src, f"Indicator {idx} source mismatch in {filename}"

        # Evidence provenance
        for idx, ev in enumerate(normalized.evidence):
            raw_ev = raw_data["evidence"][idx]
            expected_src = raw_ev.get("source") or raw_data["source"]
            assert ev.source == expected_src, f"Evidence {idx} source mismatch in {filename}"


def test_safety_rfc5737_and_doc_domains(incidents_dir: Path, normalizer: DataNormalizer):
    """Verify that all IP addresses and domains in the scenarios strictly follow RFC safety rules."""
    for filename in SCENARIO_FILES:
        filepath = incidents_dir / filename
        with open(filepath, "r", encoding="utf-8") as f:
            raw_data = json.load(f)

        normalized = normalizer.normalize(raw_data)

        for ind in normalized.indicators:
            if ind.indicator_type == IndicatorType.IP.value:
                # Must be in RFC 5737 documentation subnets
                ip_obj = ipaddress.ip_address(ind.value)
                is_safe_doc_ip = any(ip_obj in net for net in DOC_IP_NETWORKS)
                assert is_safe_doc_ip, f"IP {ind.value} in {filename} is not in RFC 5737 documentation range!"

            elif ind.indicator_type in (IndicatorType.DOMAIN.value, IndicatorType.URL.value):
                # Must use safe documentation domains
                is_safe_domain = any(domain in ind.value for domain in SAFE_DOMAINS)
                assert is_safe_domain, f"Domain/URL {ind.value} in {filename} does not use documentation domains!"


def test_scenario_1_network_content(incidents_dir: Path, normalizer: DataNormalizer):
    """Specific content validation for Scenario 1: Suspicious Network Activity."""
    filepath = incidents_dir / "incident_001_network.json"
    with open(filepath, "r", encoding="utf-8") as f:
        data = json.load(f)

    incident = normalizer.normalize(data)
    assert incident.incident_id == "INC-001-NET"
    assert incident.incident_type == "suspicious_network_activity"

    ip_indicators = [i for i in incident.indicators if i.indicator_type == "ip"]
    assert len(ip_indicators) >= 1
    assert ip_indicators[0].value == "203.0.113.45"

    net_evidence = [e for e in incident.evidence if e.evidence_type == "network_log"]
    assert len(net_evidence) >= 1


def test_scenario_2_phishing_content(incidents_dir: Path, normalizer: DataNormalizer):
    """Specific content validation for Scenario 2: Phishing Email."""
    filepath = incidents_dir / "incident_002_phishing.json"
    with open(filepath, "r", encoding="utf-8") as f:
        data = json.load(f)

    incident = normalizer.normalize(data)
    assert incident.incident_id == "INC-002-PHISH"
    assert incident.incident_type == "phishing_email"

    urls = [i for i in incident.indicators if i.indicator_type == "url"]
    assert len(urls) >= 1
    assert "example.org" in urls[0].value

    mitre = [i for i in incident.indicators if i.indicator_type == "mitre_attack"]
    assert len(mitre) >= 1
    assert mitre[0].value == "T1566.002"


def test_scenario_3_endpoint_content(incidents_dir: Path, normalizer: DataNormalizer):
    """Specific content validation for Scenario 3: Endpoint Malware Alert."""
    filepath = incidents_dir / "incident_003_endpoint.json"
    with open(filepath, "r", encoding="utf-8") as f:
        data = json.load(f)

    incident = normalizer.normalize(data)
    assert incident.incident_id == "INC-003-EP"
    assert incident.incident_type == "endpoint_malware_alert"

    hashes = [i for i in incident.indicators if i.indicator_type == "file_hash"]
    assert len(hashes) >= 1
    assert len(hashes[0].value) == 64  # Valid SHA-256 length

    cve = [i for i in incident.indicators if i.indicator_type == "cve"]
    assert len(cve) >= 1


def test_scenario_4_vulnerability_content(incidents_dir: Path, normalizer: DataNormalizer):
    """Specific content validation for Scenario 4: Vulnerable Service."""
    filepath = incidents_dir / "incident_004_vulnerability.json"
    with open(filepath, "r", encoding="utf-8") as f:
        data = json.load(f)

    incident = normalizer.normalize(data)
    assert incident.incident_id == "INC-004-VULN"
    assert incident.incident_type == "vulnerable_service"

    cve = [i for i in incident.indicators if i.indicator_type == "cve"]
    assert len(cve) >= 1
    assert cve[0].value == "CVE-2026-20002"

    vuln_ev = [e for e in incident.evidence if e.evidence_type == "vulnerability_report"]
    assert len(vuln_ev) >= 1


def test_scenario_5_multi_signal_content(incidents_dir: Path, normalizer: DataNormalizer):
    """Specific content validation for Scenario 5: Multi-Signal Correlated Incident."""
    filepath = incidents_dir / "incident_005_multi_signal.json"
    with open(filepath, "r", encoding="utf-8") as f:
        data = json.load(f)

    incident = normalizer.normalize(data)
    assert incident.incident_id == "INC-005-MULTI"
    assert incident.incident_type == "multi_signal_correlated_incident"

    types_present = {ind.indicator_type for ind in incident.indicators}
    assert "url" in types_present
    assert "domain" in types_present
    assert "file_hash" in types_present
    assert "ip" in types_present
    assert "cve" in types_present
    assert "mitre_attack" in types_present

    ev_types = {e.evidence_type for e in incident.evidence}
    assert "network_log" in ev_types
    assert "system_log" in ev_types
    assert "vulnerability_report" in ev_types
    assert "authentication_log" in ev_types
