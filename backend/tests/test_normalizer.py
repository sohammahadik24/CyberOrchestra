"""Unit tests for the DataNormalizer service and schema models."""

import json
from pathlib import Path
import pytest

from app.models.incident import Incident, IndicatorType
from app.services.normalizer import DataNormalizer, NormalizationError, normalize_incident


@pytest.fixture
def normalizer() -> DataNormalizer:
    return DataNormalizer()


def test_valid_incident_normalization(normalizer: DataNormalizer):
    """Test standard normalization of a valid raw incident dictionary."""
    raw = {
        "incident_id": "INC-001",
        "incident_type": "suspicious_network_activity",
        "description": "Multiple connections to a suspicious external IP",
        "severity": "medium",
        "source": "simulated_firewall",
        "indicators": [
            {
                "type": "ip",
                "value": "203.0.113.10",
                "source": "simulated",
                "confidence": 0.85,
            }
        ],
        "evidence": [
            {
                "evidence_id": "EVID-001",
                "evidence_type": "network_log",
                "source": "simulated_firewall",
                "description": "Firewall blocked outbound packets on port 443",
            }
        ],
    }

    result = normalizer.normalize(raw)

    assert isinstance(result, Incident)
    assert result.incident_id == "INC-001"
    assert result.incident_type == "suspicious_network_activity"
    assert result.description == "Multiple connections to a suspicious external IP"
    assert result.severity == "medium"
    assert result.source == "simulated_firewall"
    assert len(result.indicators) == 1
    assert result.indicators[0].indicator_type == "ip"
    assert result.indicators[0].value == "203.0.113.10"
    assert result.indicators[0].source == "simulated"
    assert result.indicators[0].confidence == 0.85
    assert len(result.evidence) == 1
    assert result.evidence[0].evidence_id == "EVID-001"
    assert result.evidence[0].evidence_type == "network_log"


def test_missing_incident_id(normalizer: DataNormalizer):
    """Test that missing or empty incident ID raises a NormalizationError."""
    raw_missing = {
        "incident_type": "unauthorized_access",
        "description": "Failed login brute force detected",
    }
    with pytest.raises(NormalizationError, match="Missing required field: 'incident_id'"):
        normalizer.normalize(raw_missing)

    raw_empty = {
        "incident_id": "   ",
        "incident_type": "unauthorized_access",
        "description": "Failed login brute force detected",
    }
    with pytest.raises(NormalizationError, match="Missing required field: 'incident_id'"):
        normalizer.normalize(raw_empty)


def test_missing_required_fields(normalizer: DataNormalizer):
    """Test that missing required fields like description or incident_type fail validation."""
    raw_no_type = {
        "incident_id": "INC-002",
        "description": "Suspicious activity detected",
    }
    with pytest.raises(NormalizationError, match="Missing required field: 'incident_type'"):
        normalizer.normalize(raw_no_type)

    raw_no_desc = {
        "incident_id": "INC-003",
        "incident_type": "phishing",
    }
    with pytest.raises(NormalizationError, match="Missing required field: 'description'"):
        normalizer.normalize(raw_no_desc)


def test_indicator_normalization(normalizer: DataNormalizer):
    """Test indicator type synonym normalization across diverse forms."""
    raw = {
        "incident_id": "INC-004",
        "incident_type": "multi_vector_alert",
        "description": "Correlation across endpoints and perimeter",
        "source": "test_siem",
        "indicators": [
            {"type": "IPv4", "value": "198.51.100.1"},
            {"type": "URL", "value": "https://example.com/test"},
            {"type": "DOMAIN_NAME", "value": "example.com"},
            {"type": "sha256", "value": "0000000000000000000000000000000000000000000000000000000000000000"},
            {"type": "cve_id", "value": "CVE-2026-99999"},
            {"type": "mitre_technique", "value": "T1071.001"},
            {"type": "log_event", "value": "EventID:4625"},
            {"type": "malware_family", "value": "SimulatedAgent"},
        ],
    }

    result = normalizer.normalize(raw)
    types = [ind.indicator_type for ind in result.indicators]

    assert types == [
        IndicatorType.IP.value,
        IndicatorType.URL.value,
        IndicatorType.DOMAIN.value,
        IndicatorType.FILE_HASH.value,
        IndicatorType.CVE.value,
        IndicatorType.MITRE_ATTACK.value,
        IndicatorType.LOG_EVENT.value,
        IndicatorType.MALWARE.value,
    ]


def test_optional_fields_and_defaults(normalizer: DataNormalizer):
    """Test that missing optional fields (severity, confidence, evidence_id, timestamps) default safely."""
    raw = {
        "incident_id": "INC-005",
        "incident_type": "reconnaissance",
        "description": "Port scan sweep against edge router",
        "indicators": [
            {
                "type": "ip",
                "value": "192.0.2.1",
            }
        ],
        "evidence": [
            {
                "type": "network",
                "description": "Port scan detected on ports 22, 80, 443",
            }
        ],
    }

    result = normalizer.normalize(raw)

    # Severity should be None (not calculated)
    assert result.severity is None
    # Timestamp should default to a valid datetime
    assert result.timestamp is not None
    # Source should default/infer
    assert result.source in ("unspecified", "simulated", "unknown") or len(result.source) > 0
    # Indicator default source and confidence
    assert result.indicators[0].confidence is None
    assert result.indicators[0].source == result.source
    # Evidence ID should be automatically generated
    assert result.evidence[0].evidence_id == "INC-005-EVID-1"
    assert result.evidence[0].evidence_type == "network_log"
    assert result.evidence[0].confidence is None


def test_preservation_of_source_information(normalizer: DataNormalizer):
    """Test that source provenance and raw metadata are preserved without alteration."""
    raw = {
        "incident_id": "INC-006",
        "incident_type": "credential_stuffing",
        "description": "Anomalous authentications from novel ASN",
        "source": "AbuseIPDB",
        "indicators": [
            {
                "type": "ip",
                "value": "203.0.113.50",
                "source": "AbuseIPDB",
                "confidence": 95,  # Percentage should be converted to 0.95
                "abuse_score": 100,
                "country": "XX",
            }
        ],
        "evidence": [
            {
                "evidence_id": "EV-999",
                "evidence_type": "auth_log",
                "source": "Azure_AD",
                "description": "Multiple conditional access failures",
                "raw_reference": "tenant-id://xyz/signin/123",
                "custom_flag": True,
            }
        ],
    }

    result = normalizer.normalize(raw)

    assert result.source == "AbuseIPDB"
    assert result.indicators[0].source == "AbuseIPDB"
    assert result.indicators[0].confidence == 0.95
    assert result.indicators[0].metadata.get("abuse_score") == 100
    assert result.indicators[0].metadata.get("country") == "XX"

    assert result.evidence[0].source == "Azure_AD"
    assert result.evidence[0].evidence_type == "authentication_log"
    assert result.evidence[0].raw_reference == "tenant-id://xyz/signin/123"
    assert result.evidence[0].metadata.get("custom_flag") is True


def test_reject_clearly_malformed_input(normalizer: DataNormalizer):
    """Test that non-dict or corrupt payloads are rejected deterministically."""
    with pytest.raises(NormalizationError, match="must be a JSON object"):
        normalizer.normalize("not a dictionary")

    with pytest.raises(NormalizationError, match="must be a JSON object"):
        normalizer.normalize(["INC-001", "malware"])

    with pytest.raises(NormalizationError, match="must be a JSON object"):
        normalizer.normalize(None)

    with pytest.raises(NormalizationError, match="Field 'indicators' must be a list"):
        normalizer.normalize({
            "incident_id": "INC-ERR",
            "incident_type": "test",
            "description": "test",
            "indicators": "invalid_not_a_list",
        })

    with pytest.raises(NormalizationError, match="missing a required 'value'"):
        normalizer.normalize({
            "incident_id": "INC-ERR-2",
            "incident_type": "test",
            "description": "test",
            "indicators": [{"type": "ip"}],  # missing value
        })


def test_raw_data_files_normalization(normalizer: DataNormalizer):
    """Test that all documentation-safe sample raw files normalize properly."""
    raw_dir = Path(__file__).resolve().parent.parent / "data" / "raw"
    sample_files = list(raw_dir.glob("*.json"))
    assert len(sample_files) >= 3, f"Expected at least 3 raw sample files in {raw_dir}"

    for sample_file in sample_files:
        with open(sample_file, "r", encoding="utf-8") as f:
            data = json.load(f)
        normalized = normalizer.normalize(data)
        assert isinstance(normalized, Incident)
        assert normalized.incident_id.startswith("INC-SIM-")
        assert len(normalized.indicators) > 0
