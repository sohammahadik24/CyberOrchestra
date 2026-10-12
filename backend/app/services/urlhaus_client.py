"""URLhaus API v1 Client for CyberOrchestra.

Responsible for querying external URL reputation intelligence from the abuse.ch
URLhaus API and standardizing the resulting telemetry into CyberOrchestra's
Indicator and Evidence models.

IMPORTANT:
- This client consumes external evidence ONLY.
- It does not make cybersecurity response decisions (e.g. blocking, quarantine,
  verdict determination).
- URLhaus threat classifications are preserved as external evidence in metadata
  and are NOT mapped to CyberOrchestra's internal AI confidence field.
"""

from datetime import datetime, timezone
import hashlib
from typing import Any, Dict, List, Optional, Tuple
import urllib.parse
import httpx

from app.core.config import settings
from app.models.incident import Evidence, EvidenceType, Indicator, IndicatorType
from app.models.urlhaus import URLReputationResult, URLhausResponse


class URLhausError(Exception):
    """Base exception for all URLhaus client errors."""
    pass


class URLhausConfigError(URLhausError):
    """Raised when URLhaus authentication key or required configuration is missing."""
    pass


class URLhausAuthError(URLhausError):
    """Raised when URLhaus returns HTTP 401 or 403 authorization failures."""
    pass


class URLhausRateLimitError(URLhausError):
    """Raised when URLhaus returns HTTP 429 rate limit exceeded."""
    pass


class URLhausConnectionError(URLhausError):
    """Raised on network timeout, DNS resolution failure, or unreachable host."""
    pass


class URLhausResponseError(URLhausError):
    """Raised when URLhaus returns unexpected HTTP errors or malformed payloads."""
    pass


class URLhausClient:
    """Client for retrieving external URL threat intelligence from URLhaus API v1."""

    def __init__(
        self,
        auth_key: Optional[str] = None,
        base_url: Optional[str] = None,
        timeout: Optional[float] = None,
    ):
        """Initialize the URLhaus client.

        Args:
            auth_key: URLhaus Auth-Key. If omitted, loaded from settings.URLHAUS_AUTH_KEY.
            base_url: Query endpoint URL. Defaults to https://urlhaus-api.abuse.ch/v1/url/.
            timeout: Request timeout in seconds. Defaults to settings.URLHAUS_TIMEOUT_SECONDS.
        """
        self._auth_key = auth_key
        self.base_url = base_url or settings.URLHAUS_API_URL
        self.timeout = timeout if timeout is not None else settings.URLHAUS_TIMEOUT_SECONDS

    @property
    def auth_key(self) -> Optional[str]:
        """Resolve Auth-Key dynamically from explicit argument or application settings."""
        return self._auth_key or settings.URLHAUS_AUTH_KEY

    def check_url(
        self,
        url: str,
        transport: Optional[httpx.BaseTransport] = None,
    ) -> URLhausResponse:
        """Query URLhaus API v1 for threat intelligence regarding a specific URL.

        Args:
            url: Valid HTTP or HTTPS URL string.
            transport: Optional custom httpx transport for testing/mocking.

        Returns:
            URLhausResponse containing parsed external intelligence attributes.

        Raises:
            ValueError: If url is not a syntactically valid HTTP/HTTPS URL.
            URLhausConfigError: If URLHAUS_AUTH_KEY is not configured.
            URLhausAuthError: If authentication with URLhaus fails.
            URLhausRateLimitError: If API rate limits are exceeded.
            URLhausConnectionError: If network connection fails or times out.
            URLhausResponseError: If response payload is malformed or unprocessable.
        """
        # 1. Validate URL syntax
        clean_url = str(url).strip()
        parsed = urllib.parse.urlparse(clean_url)
        if not parsed.scheme or parsed.scheme.lower() not in ("http", "https") or not parsed.netloc:
            raise ValueError(
                f"Invalid URL: '{url}'. Target must be a valid HTTP or HTTPS URL with a network host."
            )

        # 2. Check for configured authentication key
        active_key = self.auth_key
        if not active_key or not active_key.strip("'\" \t\r\n"):
            raise URLhausConfigError(
                "URLhaus authentication key is not configured. Set URLHAUS_AUTH_KEY in the environment or .env file."
            )

        headers = {
            "Auth-Key": active_key.strip("'\" \t\r\n"),
            "Accept": "application/json",
            "User-Agent": "CyberOrchestra-Intelligence/0.1.0",
        }

        form_data = {
            "url": clean_url,
        }

        # 3. Execute HTTP POST request
        try:
            with httpx.Client(timeout=self.timeout, transport=transport) as client:
                response = client.post(self.base_url, headers=headers, data=form_data)
        except httpx.TimeoutException as err:
            raise URLhausConnectionError(
                f"URLhaus request timed out after {self.timeout}s: {err}"
            ) from err
        except httpx.RequestError as err:
            raise URLhausConnectionError(
                f"Network communication failure connecting to URLhaus: {err}"
            ) from err

        # 4. Handle HTTP status codes
        if response.status_code in (401, 403):
            raise URLhausAuthError(
                f"URLhaus authentication failed (HTTP {response.status_code}): {response.text}"
            )
        if response.status_code == 429:
            raise URLhausRateLimitError(
                f"URLhaus rate limit exceeded (HTTP 429): {response.text}"
            )
        if response.status_code != 200:
            raise URLhausResponseError(
                f"URLhaus API returned unexpected status {response.status_code}: {response.text}"
            )

        # 5. Parse response JSON
        try:
            payload = response.json()
        except Exception as err:
            raise URLhausResponseError(
                f"Malformed JSON response received from URLhaus: {err}"
            ) from err

        if not isinstance(payload, dict) or "query_status" not in payload:
            raise URLhausResponseError(
                "URLhaus response does not contain expected 'query_status' field."
            )

        return self._parse_urlhaus_payload(clean_url, payload)

    def convert_to_standardized_evidence(
        self,
        reputation: URLhausResponse,
    ) -> Tuple[Indicator, Evidence]:
        """Convert a URLhaus response into CyberOrchestra Indicator and Evidence models.

        CRITICAL GROUNDING PRINCIPLE:
        URLhaus results represent external intelligence attribution, NOT internal AI confidence.
        Therefore, confidence on both models is set strictly to None, and external metrics
        are preserved within metadata.
        """
        # 1. Standardized Indicator
        indicator_metadata: Dict[str, Any] = {
            "query_status": reputation.query_status,
            "urlhaus_id": reputation.urlhaus_id,
            "url_status": reputation.url_status,
            "host": reputation.host,
            "date_added": reputation.date_added,
            "threat": reputation.threat,
            "reporter": reputation.reporter,
            "tags": reputation.tags,
            "urlhaus_reference": reputation.urlhaus_reference,
        }
        for k, v in reputation.metadata.items():
            if k not in indicator_metadata:
                indicator_metadata[k] = v

        indicator = Indicator(
            indicator_type=IndicatorType.URL.value,
            value=reputation.url,
            source=reputation.source,
            confidence=None,  # Not mapped to AI confidence
            metadata=indicator_metadata,
        )

        # 2. Standardized Evidence
        url_hash_slug = hashlib.sha256(reputation.url.encode("utf-8")).hexdigest()[:12]
        evidence_id = f"EVID-URLHAUS-{url_hash_slug}"

        if reputation.query_status == "ok":
            evidence_desc = (
                f"URLhaus external threat intelligence for {reputation.url}: "
                f"threat={reputation.threat or 'unspecified'}, "
                f"url_status={reputation.url_status or 'unknown'}, "
                f"tags={reputation.tags}"
            )
        elif reputation.query_status == "no_results":
            evidence_desc = (
                f"URLhaus external threat intelligence for {reputation.url}: "
                f"no matching entries found in URLhaus database."
            )
        else:
            evidence_desc = (
                f"URLhaus external threat intelligence query for {reputation.url}: "
                f"status={reputation.query_status}."
            )

        evidence_metadata: Dict[str, Any] = {
            "query_status": reputation.query_status,
            "urlhaus_id": reputation.urlhaus_id,
            "url_status": reputation.url_status,
            "host": reputation.host,
            "date_added": reputation.date_added,
            "threat": reputation.threat,
            "reporter": reputation.reporter,
            "tags": reputation.tags,
            "payloads": reputation.payloads,
            "blacklists": reputation.blacklists,
            "urlhaus_reference": reputation.urlhaus_reference,
        }
        for k, v in reputation.metadata.items():
            if k not in evidence_metadata:
                evidence_metadata[k] = v

        evidence = Evidence(
            evidence_id=evidence_id,
            evidence_type=EvidenceType.URL_REPUTATION.value,
            source=reputation.source,
            description=evidence_desc,
            timestamp=datetime.now(timezone.utc),
            raw_reference=reputation.urlhaus_reference or f"https://urlhaus.abuse.ch/browse/",
            confidence=None,  # Left for future reasoning agents
            metadata=evidence_metadata,
        )

        return indicator, evidence

    def check_and_convert(
        self,
        url: str,
        transport: Optional[httpx.BaseTransport] = None,
    ) -> URLReputationResult:
        """Query URLhaus for a URL and return the standardized result."""
        reputation = self.check_url(url, transport=transport)
        indicator, evidence = self.convert_to_standardized_evidence(reputation)
        return URLReputationResult(
            url=reputation.url,
            reputation=reputation,
            indicator=indicator,
            evidence=evidence,
        )

    def _parse_urlhaus_payload(self, url: str, data: Dict[str, Any]) -> URLhausResponse:
        """Parse raw URLhaus JSON payload into URLhausResponse model."""
        query_status = str(data.get("query_status", "unknown")).strip()

        standard_keys = {
            "query_status", "id", "urlhaus_reference", "url", "url_status",
            "host", "date_added", "threat", "reporter", "tags", "payloads", "blacklists"
        }
        metadata: Dict[str, Any] = {}
        for k, v in data.items():
            if k not in standard_keys:
                metadata[k] = v

        urlhaus_id = str(data["id"]) if data.get("id") is not None else None
        tags = data.get("tags") if isinstance(data.get("tags"), list) else []
        payloads = data.get("payloads") if isinstance(data.get("payloads"), list) else []
        blacklists = data.get("blacklists") if isinstance(data.get("blacklists"), dict) else {}

        return URLhausResponse(
            query_status=query_status,
            url=url,
            urlhaus_id=urlhaus_id,
            urlhaus_reference=data.get("urlhaus_reference"),
            url_status=data.get("url_status"),
            host=data.get("host"),
            date_added=data.get("date_added"),
            threat=data.get("threat"),
            reporter=data.get("reporter"),
            tags=tags,
            payloads=payloads,
            blacklists=blacklists,
            source="URLhaus",
            metadata=metadata,
        )


# Global default client instance
urlhaus_client = URLhausClient()
