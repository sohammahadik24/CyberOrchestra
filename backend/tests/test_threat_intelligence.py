"""Focused tests for combined external intelligence collection."""

from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from app.models.incident import Evidence, Incident, Indicator, IndicatorType
from app.services.threat_intelligence import ThreatIntelligenceService


def incident_with(*indicators):
    return Incident(
        incident_id="INC-TEST",
        incident_type="test",
        description="Test incident",
        source="test",
        indicators=list(indicators),
    )


def indicator(kind, value):
    return Indicator(indicator_type=kind, value=value, source="test")


def result(kind, value, source, provenance):
    standardized = Indicator(
        indicator_type=kind,
        value=value,
        source=source,
        metadata={"provenance": provenance},
    )
    evidence = Evidence(
        evidence_id=f"E-{source}-{value}",
        evidence_type="threat_intel_feed",
        source=source,
        description=f"Evidence for {value}",
        metadata={"provenance": provenance},
    )
    return SimpleNamespace(indicator=standardized, evidence=evidence)


@pytest.fixture
def clients():
    return {
        "abuseipdb": Mock(),
        "urlhaus": Mock(),
        "nvd": Mock(),
        "mitre": Mock(),
    }


def service(clients):
    return ThreatIntelligenceService(**clients)


def test_multi_indicator_incident_routes_to_each_source_and_aggregates(clients):
    clients["abuseipdb"].check_and_convert.return_value = result("ip", "203.0.113.10", "AbuseIPDB", "AbuseIPDB API v2")
    clients["urlhaus"].check_and_convert.return_value = result("url", "https://example.test/a", "URLhaus", "URLhaus API v1")
    clients["nvd"].get_cve_and_convert.return_value = result("cve", "CVE-2024-12345", "NVD", "NVD CVE API 2.0")
    clients["mitre"].get_technique_and_convert.return_value = result("mitre_attack", "T1566.002", "MITRE ATT&CK", "MITRE ATT&CK STIX 2.1")

    output = service(clients).collect(incident_with(
        indicator("ip", "203.0.113.10"),
        indicator("url", "https://example.test/a"),
        indicator("cve", "CVE-2024-12345"),
        indicator("mitre_attack", "T1566.002"),
    ))

    clients["abuseipdb"].check_and_convert.assert_called_once_with("203.0.113.10")
    clients["urlhaus"].check_and_convert.assert_called_once_with("https://example.test/a")
    clients["nvd"].get_cve_and_convert.assert_called_once_with("CVE-2024-12345")
    clients["mitre"].get_technique_and_convert.assert_called_once_with("T1566.002")
    assert len(output.indicators) == len(output.evidence) == 4
    assert output.failures == []


def test_missing_indicator_types_do_not_query_sources(clients):
    clients["abuseipdb"].check_and_convert.return_value = result("ip", "192.0.2.2", "AbuseIPDB", "AbuseIPDB")
    output = service(clients).collect(incident_with(indicator("ip", "192.0.2.2")))
    assert len(output.evidence) == 1
    clients["urlhaus"].check_and_convert.assert_not_called()
    clients["nvd"].get_cve_and_convert.assert_not_called()
    clients["mitre"].get_technique_and_convert.assert_not_called()


def test_one_source_failure_does_not_stop_other_sources(clients):
    clients["abuseipdb"].check_and_convert.side_effect = RuntimeError("upstream unavailable")
    clients["nvd"].get_cve_and_convert.return_value = result("cve", "CVE-2024-12345", "NVD", "NVD CVE API 2.0")
    output = service(clients).collect(incident_with(
        indicator("ip", "203.0.113.10"), indicator("cve", "CVE-2024-12345")
    ))
    assert len(output.evidence) == 1
    assert output.evidence[0].source == "NVD"
    assert output.failures == [{
        "indicator_type": "ip", "indicator": "203.0.113.10",
        "source": "AbuseIPDB", "error": "upstream unavailable",
    }]


def test_source_and_provenance_are_preserved(clients):
    clients["mitre"].get_technique_and_convert.return_value = result(
        "mitre_attack", "T1566.002", "MITRE ATT&CK", "MITRE ATT&CK STIX 2.1"
    )
    output = service(clients).collect(incident_with(indicator("mitre_attack", "T1566.002")))
    assert output.indicators[0].source == "MITRE ATT&CK"
    assert output.evidence[0].source == "MITRE ATT&CK"
    assert output.evidence[0].metadata["provenance"] == "MITRE ATT&CK STIX 2.1"

