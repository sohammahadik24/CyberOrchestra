"""Unit tests for URLhaus client, models, and evidence conversion.

All unit tests strictly mock external HTTP requests via httpx and do NOT
depend on the live URLhaus service.
"""

import json
import pytest
import httpx
from fastapi.testclient import TestClient

from app.main import app
from app.models.incident import Evidence, EvidenceType, Indicator, IndicatorType
from app.models.urlhaus import URLReputationResult, URLhausResponse
from app.services.urlhaus_client import (
    URLhausAuthError,
    URLhausClient,
    URLhausConfigError,
    URLhausConnectionError,
    URLhausRateLimitError,
    URLhausResponseError,
)

MOCK_URLHAUS_OK = {
    "query_status": "ok",
    "id": "271828",
    "urlhaus_reference": "https://urlhaus.abuse.ch/url/271828/",
    "url": "https://threat-test.example.com/malware_loader.bin",
    "url_status": "online",
    "host": "threat-test.example.com",
    "date_added": "2026-09-30 08:00:00 UTC",
    "threat": "malware_download",
    "reporter": "security_researcher_demo",
    "larted": "true",
    "tags": ["payload", "stealer", "bin"],
    "blacklists": {
        "spamhaus_dbl": "not listed",
        "surbl": "listed",
    },
    "payloads": [
        {
            "response_sha256": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            "file_type": "exe",
            "signature": "SimulatedStealer.Gen",
        }
    ],
}

MOCK_URLHAUS_NO_RESULTS = {
    "query_status": "no_results",
}


@pytest.fixture
def mock_urlhaus_client() -> URLhausClient:
    """Client configured with a dummy auth key for testing."""
    return URLhausClient(auth_key="mock_urlhaus_key_xyz987")


def test_missing_api_key():
    """Verify that calling check_url without an auth key raises URLhausConfigError."""
    client = URLhausClient(auth_key="")
    client._auth_key = None
    with pytest.MonkeyPatch.context() as mp:
        mp.setattr("app.core.config.settings.URLHAUS_AUTH_KEY", None)
        with pytest.raises(URLhausConfigError, match="URLhaus authentication key is not configured"):
            client.check_url("https://example.com/test")


def test_invalid_url_syntax(mock_urlhaus_client: URLhausClient):
    """Verify that syntactically invalid URLs are rejected before any network call."""
    invalid_cases = [
        "not-a-url",
        "ftp://example.com/file",
        "http://",
        "",
        "just_a_string",
    ]
    for bad_url in invalid_cases:
        with pytest.raises(ValueError, match="Invalid URL"):
            mock_urlhaus_client.check_url(bad_url)


def test_successful_urlhaus_response(mock_urlhaus_client: URLhausClient):
    """Test successful query and parsing of URLhaus 'ok' response data."""
    def handler(request: httpx.Request) -> httpx.Response:
        assert request.headers.get("Auth-Key") == "mock_urlhaus_key_xyz987"
        assert request.headers.get("Accept") == "application/json"
        body = request.read().decode("utf-8")
        assert "url=https%3A%2F%2Fthreat-test.example.com%2Fmalware_loader.bin" in body or "threat-test.example.com" in body
        return httpx.Response(200, json=MOCK_URLHAUS_OK)

    transport = httpx.MockTransport(handler)
    reputation = mock_urlhaus_client.check_url(
        "https://threat-test.example.com/malware_loader.bin",
        transport=transport,
    )

    assert isinstance(reputation, URLhausResponse)
    assert reputation.query_status == "ok"
    assert reputation.urlhaus_id == "271828"
    assert reputation.url == "https://threat-test.example.com/malware_loader.bin"
    assert reputation.url_status == "online"
    assert reputation.host == "threat-test.example.com"
    assert reputation.threat == "malware_download"
    assert reputation.reporter == "security_researcher_demo"
    assert "stealer" in reputation.tags
    assert len(reputation.payloads) == 1
    assert reputation.blacklists.get("surbl") == "listed"
    assert reputation.source == "URLhaus"


def test_successful_urlhaus_no_results(mock_urlhaus_client: URLhausClient):
    """Test query where URL is not found in URLhaus (query_status: 'no_results')."""
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json=MOCK_URLHAUS_NO_RESULTS)

    transport = httpx.MockTransport(handler)
    reputation = mock_urlhaus_client.check_url(
        "https://clean.example.com/page",
        transport=transport,
    )

    assert isinstance(reputation, URLhausResponse)
    assert reputation.query_status == "no_results"
    assert reputation.url == "https://clean.example.com/page"
    assert reputation.threat is None


def test_authentication_failure(mock_urlhaus_client: URLhausClient):
    """Test handling of HTTP 401/403 authorization failures."""
    def handler_401(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, text="Unauthorized: Invalid Auth-Key")

    transport = httpx.MockTransport(handler_401)
    with pytest.raises(URLhausAuthError, match="authentication failed \\(HTTP 401\\)"):
        mock_urlhaus_client.check_url("https://example.com/test", transport=transport)


def test_rate_limit_response(mock_urlhaus_client: URLhausClient):
    """Test handling of HTTP 429 rate limit exceeded response."""
    def handler_429(request: httpx.Request) -> httpx.Response:
        return httpx.Response(429, text="Rate limit exceeded. Try again later.")

    transport = httpx.MockTransport(handler_429)
    with pytest.raises(URLhausRateLimitError, match="rate limit exceeded"):
        mock_urlhaus_client.check_url("https://example.com/test", transport=transport)


def test_timeout_network_error(mock_urlhaus_client: URLhausClient):
    """Test handling of request timeout and connection errors."""
    def handler_timeout(request: httpx.Request) -> httpx.Response:
        raise httpx.TimeoutException("Read timeout after 10.0 seconds")

    transport = httpx.MockTransport(handler_timeout)
    with pytest.raises(URLhausConnectionError, match="timed out"):
        mock_urlhaus_client.check_url("https://example.com/test", transport=transport)


def test_malformed_response(mock_urlhaus_client: URLhausClient):
    """Test handling of corrupt JSON or missing query_status."""
    def handler_corrupt(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"unexpected_key": "unexpected_val"})

    transport = httpx.MockTransport(handler_corrupt)
    with pytest.raises(URLhausResponseError, match="does not contain expected 'query_status'"):
        mock_urlhaus_client.check_url("https://example.com/test", transport=transport)


def test_indicator_and_evidence_conversion(mock_urlhaus_client: URLhausClient):
    """Verify evidence and indicator conversion adheres strictly to CyberOrchestra schema.

    Crucially, confidence must be None and NOT derived from external URLhaus classification.
    """
    reputation = mock_urlhaus_client._parse_urlhaus_payload(
        "https://threat-test.example.com/malware_loader.bin",
        MOCK_URLHAUS_OK,
    )
    indicator, evidence = mock_urlhaus_client.convert_to_standardized_evidence(reputation)

    # Validate Indicator
    assert isinstance(indicator, Indicator)
    assert indicator.indicator_type == IndicatorType.URL.value
    assert indicator.value == "https://threat-test.example.com/malware_loader.bin"
    assert indicator.source == "URLhaus"
    assert indicator.confidence is None  # CRITICAL: Not mapped to AI confidence!
    assert indicator.metadata["threat"] == "malware_download"
    assert indicator.metadata["url_status"] == "online"
    assert indicator.metadata["urlhaus_id"] == "271828"

    # Validate Evidence
    assert isinstance(evidence, Evidence)
    assert evidence.evidence_id.startswith("EVID-URLHAUS-")
    assert evidence.evidence_type == EvidenceType.URL_REPUTATION.value
    assert evidence.source == "URLhaus"
    assert evidence.confidence is None  # CRITICAL: Not mapped to AI confidence!
    assert "threat=malware_download" in evidence.description
    assert evidence.raw_reference == "https://urlhaus.abuse.ch/url/271828/"
    assert evidence.metadata["reporter"] == "security_researcher_demo"
    assert len(evidence.metadata["payloads"]) == 1


def test_preservation_of_urlhaus_metadata_and_provenance(mock_urlhaus_client: URLhausClient):
    """Verify that specialized external fields and source provenance are preserved."""
    data = dict(MOCK_URLHAUS_OK)
    data["custom_community_rating"] = 99
    data["asn"] = 13335

    reputation = mock_urlhaus_client._parse_urlhaus_payload(
        "https://threat-test.example.com/malware_loader.bin",
        data,
    )
    assert reputation.metadata.get("custom_community_rating") == 99
    assert reputation.metadata.get("asn") == 13335

    indicator, evidence = mock_urlhaus_client.convert_to_standardized_evidence(reputation)
    assert indicator.source == "URLhaus"
    assert evidence.source == "URLhaus"
    assert indicator.metadata.get("custom_community_rating") == 99
    assert evidence.metadata.get("asn") == 13335


def test_api_route_successful_response(monkeypatch):
    """Test the GET /api/v1/intelligence/url route with a mocked client."""
    reputation_obj = URLhausResponse(
        query_status="ok",
        url="https://threat-test.example.com/malware_loader.bin",
        urlhaus_id="271828",
        urlhaus_reference="https://urlhaus.abuse.ch/url/271828/",
        url_status="online",
        host="threat-test.example.com",
        date_added="2026-09-30 08:00:00 UTC",
        threat="malware_download",
        reporter="security_researcher_demo",
        tags=["stealer"],
        source="URLhaus",
        metadata={},
    )
    client_instance = URLhausClient(auth_key="mock_key")
    ind, ev = client_instance.convert_to_standardized_evidence(reputation_obj)
    mock_result = URLReputationResult(
        url="https://threat-test.example.com/malware_loader.bin",
        reputation=reputation_obj,
        indicator=ind,
        evidence=ev,
    )

    monkeypatch.setattr(
        "app.api.v1.intelligence.urlhaus_client.check_and_convert",
        lambda url: mock_result,
    )

    test_client = TestClient(app)
    response = test_client.get(
        "/api/v1/intelligence/url",
        params={"url": "https://threat-test.example.com/malware_loader.bin"},
    )
    assert response.status_code == 200

    data = response.json()
    assert data["url"] == "https://threat-test.example.com/malware_loader.bin"
    assert data["indicator"]["indicator_type"] == "url"
    assert data["indicator"]["source"] == "URLhaus"
    assert data["indicator"]["confidence"] is None
    assert data["evidence"]["evidence_type"] == "url_reputation"
    assert data["evidence"]["confidence"] is None
    assert data["reputation"]["threat"] == "malware_download"


def test_api_route_invalid_url():
    """Test that invalid URL query parameter returns HTTP 400 from the route."""
    test_client = TestClient(app)
    response = test_client.get(
        "/api/v1/intelligence/url",
        params={"url": "not_a_valid_url"},
    )
    assert response.status_code == 400
    assert "Invalid URL parameter" in response.json()["detail"]


def test_api_route_missing_key(monkeypatch):
    """Test that missing URLhaus Auth-Key returns HTTP 503 from the route."""
    def raise_config_err(*args, **kwargs):
        raise URLhausConfigError("Missing key")

    monkeypatch.setattr(
        "app.api.v1.intelligence.urlhaus_client.check_and_convert",
        raise_config_err,
    )

    test_client = TestClient(app)
    response = test_client.get(
        "/api/v1/intelligence/url",
        params={"url": "https://example.com/test"},
    )
    assert response.status_code == 503
    assert "Intelligence source not configured" in response.json()["detail"]
