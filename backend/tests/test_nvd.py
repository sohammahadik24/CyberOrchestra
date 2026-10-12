"""Unit tests for NVD CVE API 2.0 integration.

All HTTP requests are mocked using pytest-mock and httpx mock transports.
These tests NEVER make live NVD API calls and do not require NVD availability.

Tests cover:
- CVE ID validation (valid and invalid formats)
- Successful NVD response parsing
- CVE not found (totalResults = 0)
- NVD rate limit handling (HTTP 403 / 429)
- Timeout and network error handling
- Malformed NVD response handling
- NVD -> Indicator conversion (type, value, source, confidence)
- NVD -> Evidence conversion (type, source, metadata fields)
- CVSS fields preserved correctly in metadata
- CWE fields preserved when present
- Affected product information preserved
- References preserved
- Provenance/source attribution
- Optional API key behavior (with and without key)
- API route successful response
- API route invalid CVE → HTTP 400
- API route CVE not found → HTTP 404
- Explicit verification that Evidence.confidence is NOT populated from CVSS score
"""

from datetime import datetime, timezone
from unittest.mock import MagicMock, patch

import httpx
import pytest
from fastapi.testclient import TestClient

from app.core.config import settings
from app.main import app
from app.models.incident import EvidenceType, IndicatorType
from app.models.nvd import (
    AffectedProduct,
    CVEReference,
    CVSSMetricV2,
    CVSSMetricV3,
    CWEEntry,
    NVDCVEResponse,
)
from app.services.nvd_client import (
    NVDClient,
    NVDConnectionError,
    NVDInvalidCVEError,
    NVDNotFoundError,
    NVDRateLimitError,
    NVDResponseError,
    validate_cve_id,
)

client = TestClient(app)


# ---------------------------------------------------------------------------
# Sample NVD API 2.0 fixture payloads
# ---------------------------------------------------------------------------

SAMPLE_CVE_ID = "CVE-2021-44228"  # Log4Shell — well-known public CVE

SAMPLE_NVD_PAYLOAD = {
    "resultsPerPage": 1,
    "startIndex": 0,
    "totalResults": 1,
    "format": "NVD_CVE",
    "version": "2.0",
    "timestamp": "2024-01-01T00:00:00.000",
    "vulnerabilities": [
        {
            "cve": {
                "id": SAMPLE_CVE_ID,
                "sourceIdentifier": "secalert@redhat.com",
                "published": "2021-12-10T10:15:09.143",
                "lastModified": "2024-01-01T00:00:00.000",
                "vulnStatus": "Analyzed",
                "descriptions": [
                    {
                        "lang": "en",
                        "value": (
                            "Apache Log4j2 2.0-beta9 through 2.15.0 (excluding security releases) "
                            "JNDI features used in configuration, log messages, and parameters do "
                            "not protect against attacker controlled LDAP and other JNDI related "
                            "endpoints."
                        ),
                    },
                    {
                        "lang": "es",
                        "value": "Descripción en español",
                    },
                ],
                "metrics": {
                    "cvssMetricV31": [
                        {
                            "source": "nvd@nist.gov",
                            "type": "Primary",
                            "cvssData": {
                                "version": "3.1",
                                "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
                                "baseScore": 10.0,
                                "baseSeverity": "CRITICAL",
                                "attackVector": "NETWORK",
                                "attackComplexity": "LOW",
                                "privilegesRequired": "NONE",
                                "userInteraction": "NONE",
                                "scope": "CHANGED",
                                "confidentialityImpact": "HIGH",
                                "integrityImpact": "HIGH",
                                "availabilityImpact": "HIGH",
                            },
                            "exploitabilityScore": 3.9,
                            "impactScore": 6.0,
                        }
                    ],
                    "cvssMetricV2": [
                        {
                            "source": "nvd@nist.gov",
                            "type": "Primary",
                            "cvssData": {
                                "version": "2.0",
                                "vectorString": "AV:N/AC:L/Au:N/C:C/I:C/A:C",
                                "baseScore": 10.0,
                            },
                            "baseSeverity": "HIGH",
                            "exploitabilityScore": 10.0,
                            "impactScore": 10.0,
                        }
                    ],
                },
                "weaknesses": [
                    {
                        "source": "nvd@nist.gov",
                        "type": "Primary",
                        "description": [
                            {"lang": "en", "value": "CWE-917"}
                        ],
                    }
                ],
                "configurations": [
                    {
                        "nodes": [
                            {
                                "operator": "OR",
                                "negate": False,
                                "cpeMatch": [
                                    {
                                        "vulnerable": True,
                                        "criteria": "cpe:2.3:a:apache:log4j:2.0:beta9:*:*:*:*:*:*",
                                        "versionStartIncluding": "2.0",
                                        "versionEndExcluding": "2.15.0",
                                    }
                                ],
                            }
                        ]
                    }
                ],
                "references": [
                    {
                        "url": "https://logging.apache.org/log4j/2.x/security.html",
                        "source": "secalert@redhat.com",
                        "tags": ["Vendor Advisory"],
                    },
                    {
                        "url": "https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
                        "source": "nvd@nist.gov",
                        "tags": ["Third Party Advisory", "US Government Resource"],
                    },
                ],
            }
        }
    ],
}

NOT_FOUND_PAYLOAD = {
    "resultsPerPage": 0,
    "startIndex": 0,
    "totalResults": 0,
    "format": "NVD_CVE",
    "version": "2.0",
    "timestamp": "2024-01-01T00:00:00.000",
    "vulnerabilities": [],
}


# ---------------------------------------------------------------------------
# Helper: create a mock transport that returns a given response
# ---------------------------------------------------------------------------

def _mock_transport(status_code: int, json_body: dict | None = None, text: str = "") -> httpx.MockTransport:
    """Build an httpx.MockTransport that returns a fixed HTTP response."""

    def handler(request: httpx.Request) -> httpx.Response:
        if json_body is not None:
            import json
            content = json.dumps(json_body).encode()
            headers = {"Content-Type": "application/json"}
            return httpx.Response(status_code, content=content, headers=headers)
        return httpx.Response(status_code, text=text)

    return httpx.MockTransport(handler)


# ---------------------------------------------------------------------------
# 1 & 2. CVE ID Validation
# ---------------------------------------------------------------------------

class TestCVEValidation:
    """Tests for CVE identifier format validation."""

    @pytest.mark.parametrize("valid_cve", [
        "CVE-2021-44228",
        "CVE-2024-12345",
        "CVE-1999-0001",
        "CVE-2023-999999",
        "cve-2021-44228",  # lower-case should be normalised
        " CVE-2024-1234 ",  # whitespace should be stripped
    ])
    def test_valid_cve_ids(self, valid_cve: str):
        """Valid CVE identifiers should pass validation and be returned upper-cased."""
        result = validate_cve_id(valid_cve)
        assert result.startswith("CVE-")
        assert result == result.strip().upper()

    @pytest.mark.parametrize("invalid_cve", [
        "CVE-2021",           # missing sequence
        "CVE-21-44228",       # year too short
        "CVE2021-44228",      # missing dash after CVE
        "cve-abcd-1234",      # non-numeric year
        "CVE-2021-ABC",       # non-numeric sequence
        "2021-44228",         # missing CVE prefix
        "",                   # empty
        "   ",                # whitespace only
        "CVE-2021-123",       # sequence too short (< 4 digits)
        "NOTACVE",
    ])
    def test_invalid_cve_ids(self, invalid_cve: str):
        """Invalid CVE identifiers should raise NVDInvalidCVEError."""
        with pytest.raises(NVDInvalidCVEError):
            validate_cve_id(invalid_cve)


# ---------------------------------------------------------------------------
# 3. Successful NVD response
# ---------------------------------------------------------------------------

class TestNVDClientSuccess:
    """Tests for successful NVD API responses."""

    def test_get_cve_returns_nvd_response(self):
        """A valid CVE request should return a populated NVDCVEResponse."""
        transport = _mock_transport(200, json_body=SAMPLE_NVD_PAYLOAD)
        nvd = NVDClient()
        result = nvd.get_cve(SAMPLE_CVE_ID, transport=transport)

        assert isinstance(result, NVDCVEResponse)
        assert result.cve_id == SAMPLE_CVE_ID
        assert result.source == "NVD"
        assert result.vuln_status == "Analyzed"
        assert result.source_identifier == "secalert@redhat.com"

    def test_description_extracted_in_english(self):
        """English description should be preferred over other languages."""
        transport = _mock_transport(200, json_body=SAMPLE_NVD_PAYLOAD)
        nvd = NVDClient()
        result = nvd.get_cve(SAMPLE_CVE_ID, transport=transport)
        assert "Apache Log4j2" in (result.description or "")

    def test_published_and_last_modified_parsed(self):
        """Published and last_modified should be timezone-aware UTC datetimes."""
        transport = _mock_transport(200, json_body=SAMPLE_NVD_PAYLOAD)
        nvd = NVDClient()
        result = nvd.get_cve(SAMPLE_CVE_ID, transport=transport)
        assert isinstance(result.published, datetime)
        assert result.published.tzinfo is not None
        assert isinstance(result.last_modified, datetime)
        assert result.last_modified.tzinfo is not None

    def test_nvd_url_set_correctly(self):
        """NVD canonical URL should point to the CVE detail page."""
        transport = _mock_transport(200, json_body=SAMPLE_NVD_PAYLOAD)
        nvd = NVDClient()
        result = nvd.get_cve(SAMPLE_CVE_ID, transport=transport)
        assert result.nvd_url == f"https://nvd.nist.gov/vuln/detail/{SAMPLE_CVE_ID}"


# ---------------------------------------------------------------------------
# 4. CVE not found
# ---------------------------------------------------------------------------

class TestNVDNotFound:
    def test_cve_not_found_raises_error(self):
        """NVD returning totalResults=0 should raise NVDNotFoundError."""
        transport = _mock_transport(200, json_body=NOT_FOUND_PAYLOAD)
        nvd = NVDClient()
        with pytest.raises(NVDNotFoundError):
            nvd.get_cve("CVE-2099-99999", transport=transport)


# ---------------------------------------------------------------------------
# 5. Rate limit
# ---------------------------------------------------------------------------

class TestNVDRateLimit:
    @pytest.mark.parametrize("status_code", [403, 429])
    def test_rate_limit_raises_error(self, status_code: int):
        """HTTP 403 and 429 from NVD should raise NVDRateLimitError."""
        transport = _mock_transport(status_code, text="Rate limit exceeded")
        nvd = NVDClient()
        with pytest.raises(NVDRateLimitError):
            nvd.get_cve(SAMPLE_CVE_ID, transport=transport)


# ---------------------------------------------------------------------------
# 6. Timeout / network error
# ---------------------------------------------------------------------------

class TestNVDConnectionErrors:
    def test_timeout_raises_connection_error(self):
        """httpx.TimeoutException should be wrapped in NVDConnectionError."""

        def timeout_handler(request: httpx.Request) -> httpx.Response:
            raise httpx.TimeoutException("timed out", request=request)

        transport = httpx.MockTransport(timeout_handler)
        nvd = NVDClient()
        with pytest.raises(NVDConnectionError):
            nvd.get_cve(SAMPLE_CVE_ID, transport=transport)

    def test_request_error_raises_connection_error(self):
        """httpx.RequestError should be wrapped in NVDConnectionError."""

        def error_handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("connection refused", request=request)

        transport = httpx.MockTransport(error_handler)
        nvd = NVDClient()
        with pytest.raises(NVDConnectionError):
            nvd.get_cve(SAMPLE_CVE_ID, transport=transport)


# ---------------------------------------------------------------------------
# 7. Malformed NVD response
# ---------------------------------------------------------------------------

class TestNVDMalformedResponse:
    def test_non_json_response_raises_response_error(self):
        """Non-JSON response body should raise NVDResponseError."""
        transport = _mock_transport(200, text="<html>not json</html>")
        nvd = NVDClient()
        with pytest.raises(NVDResponseError):
            nvd.get_cve(SAMPLE_CVE_ID, transport=transport)

    def test_missing_cve_key_raises_response_error(self):
        """Entry missing the 'cve' key should raise NVDResponseError."""
        bad_payload = {
            "totalResults": 1,
            "vulnerabilities": [{"bad_key": "data"}],
        }
        transport = _mock_transport(200, json_body=bad_payload)
        nvd = NVDClient()
        with pytest.raises(NVDResponseError):
            nvd.get_cve(SAMPLE_CVE_ID, transport=transport)

    def test_unexpected_http_status_raises_response_error(self):
        """Unexpected HTTP 500 from NVD should raise NVDResponseError."""
        transport = _mock_transport(500, text="Internal Server Error")
        nvd = NVDClient()
        with pytest.raises(NVDResponseError):
            nvd.get_cve(SAMPLE_CVE_ID, transport=transport)


# ---------------------------------------------------------------------------
# 8 & 9. NVD -> Indicator and Evidence conversion
# ---------------------------------------------------------------------------

class TestNVDConversion:
    """Tests for standardized Indicator and Evidence output from NVD data."""

    @pytest.fixture
    def sample_cve_response(self) -> NVDCVEResponse:
        transport = _mock_transport(200, json_body=SAMPLE_NVD_PAYLOAD)
        nvd = NVDClient()
        return nvd.get_cve(SAMPLE_CVE_ID, transport=transport)

    def test_indicator_type_is_cve(self, sample_cve_response):
        """Indicator.indicator_type must be 'cve'."""
        nvd = NVDClient()
        indicator, _ = nvd.convert_to_standardized_evidence(sample_cve_response)
        assert indicator.indicator_type == IndicatorType.CVE.value

    def test_indicator_value_is_cve_id(self, sample_cve_response):
        """Indicator.value must be the CVE identifier."""
        nvd = NVDClient()
        indicator, _ = nvd.convert_to_standardized_evidence(sample_cve_response)
        assert indicator.value == SAMPLE_CVE_ID

    def test_indicator_source_is_nvd(self, sample_cve_response):
        """Indicator.source must be 'NVD'."""
        nvd = NVDClient()
        indicator, _ = nvd.convert_to_standardized_evidence(sample_cve_response)
        assert indicator.source == "NVD"

    # 10. CRITICAL: confidence must NOT be populated from CVSS score
    def test_indicator_confidence_is_none(self, sample_cve_response):
        """CVSS score must NOT be used as Indicator.confidence — must be None."""
        nvd = NVDClient()
        indicator, _ = nvd.convert_to_standardized_evidence(sample_cve_response)
        assert indicator.confidence is None, (
            "CVSS base score must NOT be mapped to Indicator.confidence. "
            "CVSS is an external vulnerability metric, not an AI confidence value."
        )

    def test_evidence_type_is_vulnerability_intelligence(self, sample_cve_response):
        """Evidence.evidence_type must be 'vulnerability_intelligence'."""
        nvd = NVDClient()
        _, evidence = nvd.convert_to_standardized_evidence(sample_cve_response)
        assert evidence.evidence_type == EvidenceType.VULNERABILITY_INTELLIGENCE.value

    def test_evidence_source_is_nvd(self, sample_cve_response):
        """Evidence.source must be 'NVD'."""
        nvd = NVDClient()
        _, evidence = nvd.convert_to_standardized_evidence(sample_cve_response)
        assert evidence.source == "NVD"

    def test_evidence_id_contains_cve_id(self, sample_cve_response):
        """Evidence.evidence_id should include the CVE identifier."""
        nvd = NVDClient()
        _, evidence = nvd.convert_to_standardized_evidence(sample_cve_response)
        assert SAMPLE_CVE_ID in evidence.evidence_id

    # CRITICAL: Evidence confidence must also NOT be populated from CVSS
    def test_evidence_confidence_is_none(self, sample_cve_response):
        """CVSS score must NOT be used as Evidence.confidence — must be None."""
        nvd = NVDClient()
        _, evidence = nvd.convert_to_standardized_evidence(sample_cve_response)
        assert evidence.confidence is None, (
            "CVSS base score must NOT be mapped to Evidence.confidence. "
            "CVSS is an external vulnerability metric, not an AI confidence value."
        )

    def test_evidence_raw_reference_is_nvd_url(self, sample_cve_response):
        """Evidence.raw_reference should point to the NVD CVE detail page."""
        nvd = NVDClient()
        _, evidence = nvd.convert_to_standardized_evidence(sample_cve_response)
        assert evidence.raw_reference is not None
        assert SAMPLE_CVE_ID in evidence.raw_reference


# ---------------------------------------------------------------------------
# 10 & 11. CVSS fields preserved in metadata
# ---------------------------------------------------------------------------

class TestCVSSPreservation:
    """Verify that CVSS metrics are preserved in metadata, not mapped to confidence."""

    @pytest.fixture
    def nvd_and_response(self):
        transport = _mock_transport(200, json_body=SAMPLE_NVD_PAYLOAD)
        nvd = NVDClient()
        response = nvd.get_cve(SAMPLE_CVE_ID, transport=transport)
        return nvd, response

    def test_cvss_v3_parsed(self, nvd_and_response):
        """CVSS v3.1 should be parsed into CVSSMetricV3."""
        _, response = nvd_and_response
        assert response.cvss_v3 is not None
        assert response.cvss_v3.base_score == 10.0
        assert response.cvss_v3.base_severity == "CRITICAL"
        assert response.cvss_v3.cvss_version == "3.1"
        assert response.cvss_v3.vector_string is not None

    def test_cvss_v3_in_evidence_metadata(self, nvd_and_response):
        """CVSS v3 data should be in Evidence.metadata['cvss_v3']."""
        nvd, response = nvd_and_response
        _, evidence = nvd.convert_to_standardized_evidence(response)
        assert "cvss_v3" in evidence.metadata
        cvss_v3 = evidence.metadata["cvss_v3"]
        assert cvss_v3 is not None
        assert cvss_v3["base_score"] == 10.0
        assert cvss_v3["base_severity"] == "CRITICAL"

    def test_cvss_v2_parsed(self, nvd_and_response):
        """CVSS v2 should be parsed into CVSSMetricV2."""
        _, response = nvd_and_response
        assert response.cvss_v2 is not None
        assert response.cvss_v2.base_score == 10.0

    def test_cvss_v2_in_evidence_metadata(self, nvd_and_response):
        """CVSS v2 data should be preserved in Evidence.metadata['cvss_v2']."""
        nvd, response = nvd_and_response
        _, evidence = nvd.convert_to_standardized_evidence(response)
        assert "cvss_v2" in evidence.metadata
        assert evidence.metadata["cvss_v2"] is not None

    def test_attack_vector_preserved(self, nvd_and_response):
        """CVSS v3 attack vector should be preserved on the model."""
        _, response = nvd_and_response
        assert response.cvss_v3 is not None
        assert response.cvss_v3.attack_vector == "NETWORK"

    def test_note_about_cvss_not_confidence_in_metadata(self, nvd_and_response):
        """Evidence metadata should include an explanatory note about CVSS vs confidence."""
        nvd, response = nvd_and_response
        _, evidence = nvd.convert_to_standardized_evidence(response)
        assert "note" in evidence.metadata
        assert "CVSS" in evidence.metadata["note"]


# ---------------------------------------------------------------------------
# 11. CWE fields preserved
# ---------------------------------------------------------------------------

class TestCWEPreservation:
    def test_cwes_parsed(self):
        """CWE weakness entries should be parsed into CWEEntry list."""
        transport = _mock_transport(200, json_body=SAMPLE_NVD_PAYLOAD)
        nvd = NVDClient()
        response = nvd.get_cve(SAMPLE_CVE_ID, transport=transport)
        assert len(response.cwes) >= 1
        cwe = response.cwes[0]
        assert cwe.cwe_id == "CWE-917"

    def test_cwes_in_evidence_metadata(self):
        """CWE list should be preserved in Evidence.metadata['cwes']."""
        transport = _mock_transport(200, json_body=SAMPLE_NVD_PAYLOAD)
        nvd = NVDClient()
        response = nvd.get_cve(SAMPLE_CVE_ID, transport=transport)
        _, evidence = nvd.convert_to_standardized_evidence(response)
        assert "cwes" in evidence.metadata
        assert len(evidence.metadata["cwes"]) >= 1
        assert evidence.metadata["cwes"][0]["cwe_id"] == "CWE-917"


# ---------------------------------------------------------------------------
# 12. Affected product information
# ---------------------------------------------------------------------------

class TestAffectedProducts:
    def test_affected_products_parsed(self):
        """Affected product / CPE entries should be parsed into AffectedProduct list."""
        transport = _mock_transport(200, json_body=SAMPLE_NVD_PAYLOAD)
        nvd = NVDClient()
        response = nvd.get_cve(SAMPLE_CVE_ID, transport=transport)
        assert len(response.affected_products) >= 1
        p = response.affected_products[0]
        assert isinstance(p, AffectedProduct)
        assert p.cpe_name is not None
        assert p.vendor == "apache"
        assert p.product == "log4j"

    def test_affected_products_in_evidence_metadata(self):
        """Affected products should appear in Evidence.metadata."""
        transport = _mock_transport(200, json_body=SAMPLE_NVD_PAYLOAD)
        nvd = NVDClient()
        response = nvd.get_cve(SAMPLE_CVE_ID, transport=transport)
        _, evidence = nvd.convert_to_standardized_evidence(response)
        assert "affected_products" in evidence.metadata
        assert evidence.metadata["affected_products_count"] >= 1


# ---------------------------------------------------------------------------
# 13. References preserved
# ---------------------------------------------------------------------------

class TestReferencesPreservation:
    def test_references_parsed(self):
        """CVE references should be parsed into CVEReference list."""
        transport = _mock_transport(200, json_body=SAMPLE_NVD_PAYLOAD)
        nvd = NVDClient()
        response = nvd.get_cve(SAMPLE_CVE_ID, transport=transport)
        assert len(response.references) == 2
        urls = [r.url for r in response.references]
        assert any("apache.org" in (u or "") for u in urls)

    def test_references_in_evidence_metadata(self):
        """References should appear in Evidence.metadata['references']."""
        transport = _mock_transport(200, json_body=SAMPLE_NVD_PAYLOAD)
        nvd = NVDClient()
        response = nvd.get_cve(SAMPLE_CVE_ID, transport=transport)
        _, evidence = nvd.convert_to_standardized_evidence(response)
        assert "references" in evidence.metadata
        assert len(evidence.metadata["references"]) == 2


# ---------------------------------------------------------------------------
# 14. Provenance preservation
# ---------------------------------------------------------------------------

class TestProvenance:
    def test_provenance_in_evidence_metadata(self):
        """Evidence.metadata should include 'provenance' pointing to NVD CVE API 2.0."""
        transport = _mock_transport(200, json_body=SAMPLE_NVD_PAYLOAD)
        nvd = NVDClient()
        response = nvd.get_cve(SAMPLE_CVE_ID, transport=transport)
        _, evidence = nvd.convert_to_standardized_evidence(response)
        assert "provenance" in evidence.metadata
        assert "NVD" in evidence.metadata["provenance"]

    def test_source_identifier_preserved(self):
        """CNA source identifier should be preserved on the NVDCVEResponse."""
        transport = _mock_transport(200, json_body=SAMPLE_NVD_PAYLOAD)
        nvd = NVDClient()
        response = nvd.get_cve(SAMPLE_CVE_ID, transport=transport)
        assert response.source_identifier == "secalert@redhat.com"


# ---------------------------------------------------------------------------
# 15. Optional API key behavior
# ---------------------------------------------------------------------------

class TestAPIKeyBehavior:
    def test_request_sent_without_api_key_when_not_configured(self):
        """When no API key is configured, requests should proceed without apiKey header."""
        sent_headers: dict = {}

        def capture_handler(request: httpx.Request) -> httpx.Response:
            sent_headers.update(dict(request.headers))
            import json
            content = json.dumps(SAMPLE_NVD_PAYLOAD).encode()
            return httpx.Response(200, content=content, headers={"Content-Type": "application/json"})

        transport = httpx.MockTransport(capture_handler)
        # Use a client with explicit api_key=None AND patch settings so fallback also returns None
        nvd = NVDClient(api_key=None)
        with patch("app.services.nvd_client.settings") as mock_settings:
            mock_settings.NVD_API_KEY = None
            mock_settings.NVD_API_URL = settings.NVD_API_URL
            mock_settings.NVD_TIMEOUT_SECONDS = settings.NVD_TIMEOUT_SECONDS
            nvd_patched = NVDClient(api_key=None)
            nvd_patched.get_cve(SAMPLE_CVE_ID, transport=transport)

        assert "apikey" not in {k.lower() for k in sent_headers.keys()}


    def test_request_sent_with_api_key_when_configured(self):
        """When API key is configured, apiKey header should be included."""
        sent_headers: dict = {}

        def capture_handler(request: httpx.Request) -> httpx.Response:
            sent_headers.update(dict(request.headers))
            import json
            content = json.dumps(SAMPLE_NVD_PAYLOAD).encode()
            return httpx.Response(200, content=content, headers={"Content-Type": "application/json"})

        transport = httpx.MockTransport(capture_handler)
        nvd = NVDClient(api_key="test-api-key-12345")
        nvd.get_cve(SAMPLE_CVE_ID, transport=transport)

        header_keys_lower = {k.lower() for k in sent_headers.keys()}
        assert "apikey" in header_keys_lower


# ---------------------------------------------------------------------------
# 16, 17, 18. API route tests via FastAPI TestClient
# ---------------------------------------------------------------------------

class TestNVDAPIRoute:
    """Integration tests for GET /api/v1/intelligence/cve/{cve_id} endpoint."""

    def test_route_invalid_cve_returns_400(self):
        """Invalid CVE format should return HTTP 400."""
        response = client.get("/api/v1/intelligence/cve/NOT-A-CVE")
        assert response.status_code == 400
        assert "Invalid CVE" in response.json().get("detail", "")

    def test_route_valid_cve_not_found_returns_404(self):
        """When NVD returns no results, route should return HTTP 404."""
        with patch("app.services.nvd_client.nvd_client.get_cve_and_convert") as mock_fn:
            mock_fn.side_effect = NVDNotFoundError("CVE not in NVD")
            response = client.get(f"/api/v1/intelligence/cve/{SAMPLE_CVE_ID}")
        assert response.status_code == 404

    def test_route_rate_limit_returns_429(self):
        """NVD rate limit should surface as HTTP 429."""
        with patch("app.services.nvd_client.nvd_client.get_cve_and_convert") as mock_fn:
            mock_fn.side_effect = NVDRateLimitError("Rate limited")
            response = client.get(f"/api/v1/intelligence/cve/{SAMPLE_CVE_ID}")
        assert response.status_code == 429

    def test_route_connection_error_returns_503(self):
        """NVD connection failure should surface as HTTP 503."""
        with patch("app.services.nvd_client.nvd_client.get_cve_and_convert") as mock_fn:
            mock_fn.side_effect = NVDConnectionError("timed out")
            response = client.get(f"/api/v1/intelligence/cve/{SAMPLE_CVE_ID}")
        assert response.status_code == 503

    def test_route_response_error_returns_502(self):
        """Upstream NVD malformed response should surface as HTTP 502."""
        with patch("app.services.nvd_client.nvd_client.get_cve_and_convert") as mock_fn:
            mock_fn.side_effect = NVDResponseError("malformed")
            response = client.get(f"/api/v1/intelligence/cve/{SAMPLE_CVE_ID}")
        assert response.status_code == 502

    def test_route_successful_response_structure(self):
        """Successful route response should include cve_id, cve_data, indicator, evidence."""
        transport = _mock_transport(200, json_body=SAMPLE_NVD_PAYLOAD)

        from app.services.nvd_client import NVDClient
        real_client = NVDClient()
        real_result = real_client.get_cve_and_convert(SAMPLE_CVE_ID, transport=transport)

        with patch("app.services.nvd_client.nvd_client.get_cve_and_convert") as mock_fn:
            mock_fn.return_value = real_result
            response = client.get(f"/api/v1/intelligence/cve/{SAMPLE_CVE_ID}")

        assert response.status_code == 200
        body = response.json()
        assert body["cve_id"] == SAMPLE_CVE_ID
        assert "cve_data" in body
        assert "indicator" in body
        assert "evidence" in body
        # Verify confidence is not set from CVSS
        assert body["indicator"]["confidence"] is None
        assert body["evidence"]["confidence"] is None
        # Verify evidence type
        assert body["evidence"]["evidence_type"] == EvidenceType.VULNERABILITY_INTELLIGENCE.value
