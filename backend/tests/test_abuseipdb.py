"""Unit tests for AbuseIPDB client, models, and evidence conversion.

All unit tests strictly mock external HTTP requests via httpx and do NOT
depend on the live AbuseIPDB service.
"""

from datetime import datetime, timezone
import json
import pytest
import httpx
from fastapi.testclient import TestClient

from app.main import app
from app.models.abuseipdb import AbuseIPDBResponse, IPReputationResult
from app.models.incident import Evidence, EvidenceType, Indicator, IndicatorType
from app.services.abuseipdb_client import (
    AbuseIPDBAuthError,
    AbuseIPDBClient,
    AbuseIPDBConfigError,
    AbuseIPDBConnectionError,
    AbuseIPDBRateLimitError,
    AbuseIPDBResponseError,
)

MOCK_SUCCESSFUL_DATA = {
    "data": {
        "ipAddress": "198.51.100.99",
        "isPublic": True,
        "ipVersion": 4,
        "isWhitelisted": False,
        "abuseConfidenceScore": 85,
        "countryCode": "US",
        "usageType": "Data Center/Web Hosting/Transit",
        "isp": "Simulated Cloud Services LLC",
        "domain": "simulatedcloud.example.com",
        "hostnames": ["node-99.simulatedcloud.example.com"],
        "isTor": False,
        "totalReports": 14,
        "numDistinctUsers": 7,
        "lastReportedAt": "2026-09-29T14:30:00+00:00",
    }
}


@pytest.fixture
def mock_client() -> AbuseIPDBClient:
    """Client with a dummy API key for testing."""
    return AbuseIPDBClient(api_key="mock_test_key_abc123")


def test_missing_api_key():
    """Verify that calling the client without an API key raises AbuseIPDBConfigError."""
    client = AbuseIPDBClient(api_key="")
    # Ensure settings also don't provide a key for this isolated check
    client._api_key = None
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr("app.core.config.settings.ABUSEIPDB_API_KEY", None)
        with pytest.raises(AbuseIPDBConfigError, match="API key is not configured"):
            client.check_ip("198.51.100.99")


def test_invalid_ip_format(mock_client: AbuseIPDBClient):
    """Verify that syntactically invalid IP strings are rejected before any network call."""
    with pytest.raises(ValueError, match="Invalid IP address format"):
        mock_client.check_ip("invalid-ip-string")

    with pytest.raises(ValueError, match="Invalid IP address format"):
        mock_client.check_ip("999.999.999.999")


def test_successful_api_response(mock_client: AbuseIPDBClient):
    """Test successful query and parsing of AbuseIPDB response data."""
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers.get("Key") == "mock_test_key_abc123"
        assert request.headers.get("Accept") == "application/json"
        assert "ipAddress=198.51.100.99" in str(request.url)
        return httpx.Response(200, json=MOCK_SUCCESSFUL_DATA)

    transport = httpx.MockTransport(handler)
    reputation = mock_client.check_ip("198.51.100.99", transport=transport)

    assert isinstance(reputation, AbuseIPDBResponse)
    assert reputation.ip_address == "198.51.100.99"
    assert reputation.ip_version == 4
    assert reputation.abuse_confidence_score == 85
    assert reputation.total_reports == 14
    assert reputation.country_code == "US"
    assert reputation.usage_type == "Data Center/Web Hosting/Transit"
    assert reputation.is_whitelisted is False
    assert reputation.source == "AbuseIPDB"
    assert reputation.last_reported_at is not None
    assert reputation.metadata.get("isp") == "Simulated Cloud Services LLC"
    assert reputation.metadata.get("domain") == "simulatedcloud.example.com"


def test_api_authentication_failure(mock_client: AbuseIPDBClient):
    """Test handling of HTTP 401/403 authorization failures."""
    def handler_401(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, text="The API key is invalid or missing.")

    transport = httpx.MockTransport(handler_401)
    with pytest.raises(AbuseIPDBAuthError, match="authentication failed \\(HTTP 401\\)"):
        mock_client.check_ip("198.51.100.99", transport=transport)


def test_rate_limit_response(mock_client: AbuseIPDBClient):
    """Test handling of HTTP 429 rate limit exceeded response."""
    def handler_429(request: httpx.Request) -> httpx.Response:
        return httpx.Response(429, text="Daily request limit reached.")

    transport = httpx.MockTransport(handler_429)
    with pytest.raises(AbuseIPDBRateLimitError, match="rate limit exceeded"):
        mock_client.check_ip("198.51.100.99", transport=transport)


def test_timeout_network_error(mock_client: AbuseIPDBClient):
    """Test handling of request timeout and network failures."""
    def handler_timeout(request: httpx.Request) -> httpx.Response:
        raise httpx.TimeoutException("Read timeout after 10 seconds")

    transport = httpx.MockTransport(handler_timeout)
    with pytest.raises(AbuseIPDBConnectionError, match="timed out"):
        mock_client.check_ip("198.51.100.99", transport=transport)


def test_malformed_api_response(mock_client: AbuseIPDBClient):
    """Test handling of malformed or non-dictionary JSON responses."""
    def handler_corrupt(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"unexpected_root": []})

    transport = httpx.MockTransport(handler_corrupt)
    with pytest.raises(AbuseIPDBResponseError, match="does not contain expected 'data' object"):
        mock_client.check_ip("198.51.100.99", transport=transport)


def test_evidence_and_indicator_conversion(mock_client: AbuseIPDBClient):
    """Verify evidence and indicator conversion adheres strictly to CyberOrchestra schema.

    Crucially, confidence must be None and NOT derived from abuseConfidenceScore.
    """
    reputation = mock_client._parse_abuseipdb_data(MOCK_SUCCESSFUL_DATA["data"])
    indicator, evidence = mock_client.convert_to_standardized_evidence(reputation)

    # Validate Indicator
    assert isinstance(indicator, Indicator)
    assert indicator.indicator_type == IndicatorType.IP.value
    assert indicator.value == "198.51.100.99"
    assert indicator.source == "AbuseIPDB"
    assert indicator.confidence is None  # CRITICAL: Not mapped to AI confidence!
    assert indicator.metadata["abuse_confidence_score"] == 85
    assert indicator.metadata["total_reports"] == 14
    assert indicator.metadata["country_code"] == "US"

    # Validate Evidence
    assert isinstance(evidence, Evidence)
    assert evidence.evidence_id == "EVID-ABUSEIPDB-198_51_100_99"
    assert evidence.evidence_type == EvidenceType.NETWORK_REPUTATION.value
    assert evidence.source == "AbuseIPDB"
    assert evidence.confidence is None  # CRITICAL: Left for future reasoning agents
    assert "85%" in evidence.description
    assert "14 abuse reports" in evidence.description
    assert evidence.raw_reference == "https://www.abuseipdb.com/check/198.51.100.99"
    assert evidence.metadata["abuse_confidence_score"] == 85
    assert evidence.metadata["isp"] == "Simulated Cloud Services LLC"


def test_preservation_of_abuseipdb_specific_fields(mock_client: AbuseIPDBClient):
    """Verify that unmapped or specialized external fields are preserved in metadata."""
    data = dict(MOCK_SUCCESSFUL_DATA["data"])
    data["custom_provider_tag"] = "test_tag_alpha"
    data["asn"] = 64512

    reputation = mock_client._parse_abuseipdb_data(data)
    assert reputation.metadata.get("custom_provider_tag") == "test_tag_alpha"
    assert reputation.metadata.get("asn") == 64512

    indicator, evidence = mock_client.convert_to_standardized_evidence(reputation)
    assert indicator.metadata.get("custom_provider_tag") == "test_tag_alpha"
    assert evidence.metadata.get("asn") == 64512


def test_api_route_successful_query(monkeypatch):
    """Test the GET /api/v1/intelligence/ip/{ip} route with a mocked client."""
    reputation_obj = AbuseIPDBResponse(
        ip_address="198.51.100.99",
        ip_version=4,
        abuse_confidence_score=90,
        total_reports=20,
        last_reported_at=datetime(2026, 9, 30, 10, 0, 0, tzinfo=timezone.utc),
        country_code="US",
        usage_type="Commercial",
        is_whitelisted=False,
        source="AbuseIPDB",
        metadata={"isp": "Simulated Corp"},
    )
    client_instance = AbuseIPDBClient(api_key="mock_key")
    ind, ev = client_instance.convert_to_standardized_evidence(reputation_obj)
    mock_result = IPReputationResult(
        ip_address="198.51.100.99",
        reputation=reputation_obj,
        indicator=ind,
        evidence=ev,
    )

    monkeypatch.setattr(
        "app.api.v1.intelligence.abuseipdb_client.check_and_convert",
        lambda ip_address, max_age_in_days: mock_result,
    )

    test_client = TestClient(app)
    response = test_client.get("/api/v1/intelligence/ip/198.51.100.99")
    assert response.status_code == 200

    data = response.json()
    assert data["ip_address"] == "198.51.100.99"
    assert data["indicator"]["indicator_type"] == "ip"
    assert data["indicator"]["value"] == "198.51.100.99"
    assert data["indicator"]["source"] == "AbuseIPDB"
    assert data["indicator"]["confidence"] is None
    assert data["evidence"]["evidence_type"] == "network_reputation"
    assert data["reputation"]["abuse_confidence_score"] == 90


def test_api_route_missing_key(monkeypatch):
    """Test that missing API key returns HTTP 503 from the route."""
    def raise_config_err(*args, **kwargs):
        raise AbuseIPDBConfigError("Missing key")

    monkeypatch.setattr(
        "app.api.v1.intelligence.abuseipdb_client.check_and_convert",
        raise_config_err,
    )

    test_client = TestClient(app)
    response = test_client.get("/api/v1/intelligence/ip/198.51.100.99")
    assert response.status_code == 503
    assert "Intelligence source not configured" in response.json()["detail"]


def test_api_route_invalid_ip():
    """Test that invalid IP parameter returns HTTP 400 from the route."""
    test_client = TestClient(app)
    response = test_client.get("/api/v1/intelligence/ip/not-a-valid-ip")
    assert response.status_code == 400
    assert "Invalid IP address parameter" in response.json()["detail"]
