"""AbuseIPDB API v2 Client for CyberOrchestra.

Responsible for querying external IP reputation intelligence from the AbuseIPDB
CHECK endpoint and standardizing the resulting telemetry into CyberOrchestra's
Indicator and Evidence models.

IMPORTANT:
- This client consumes external evidence ONLY.
- It does not make cybersecurity response decisions (e.g. blocking, isolation,
  verdict determination).
- AbuseIPDB abuse confidence scores are preserved as external evidence in metadata
  and are NOT mapped to CyberOrchestra's internal AI confidence field.
"""

from datetime import datetime, timezone
import ipaddress
from typing import Any, Dict, Optional, Tuple
import httpx

from app.core.config import settings
from app.models.abuseipdb import AbuseIPDBResponse, IPReputationResult
from app.models.incident import Evidence, EvidenceType, Indicator, IndicatorType


class AbuseIPDBError(Exception):
    """Base exception for all AbuseIPDB client errors."""
    pass


class AbuseIPDBConfigError(AbuseIPDBError):
    """Raised when AbuseIPDB API key or required client configuration is missing."""
    pass


class AbuseIPDBAuthError(AbuseIPDBError):
    """Raised when AbuseIPDB returns HTTP 401 or 403 authorization failures."""
    pass


class AbuseIPDBRateLimitError(AbuseIPDBError):
    """Raised when AbuseIPDB returns HTTP 429 rate limit exceeded."""
    pass


class AbuseIPDBConnectionError(AbuseIPDBError):
    """Raised on network timeout, DNS resolution failure, or unreachable host."""
    pass


class AbuseIPDBResponseError(AbuseIPDBError):
    """Raised when AbuseIPDB returns unexpected HTTP errors or malformed payloads."""
    pass


class AbuseIPDBClient:
    """Client for retrieving external IP reputation telemetry from AbuseIPDB API v2."""

    def __init__(
        self,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        timeout: Optional[float] = None,
    ):
        """Initialize the client.

        Args:
            api_key: AbuseIPDB API key. If omitted, loaded from settings.ABUSEIPDB_API_KEY.
            base_url: Check endpoint URL. Defaults to https://api.abuseipdb.com/api/v2/check.
            timeout: Request timeout in seconds. Defaults to settings.ABUSEIPDB_TIMEOUT_SECONDS.
        """
        self._api_key = api_key
        self.base_url = base_url or settings.ABUSEIPDB_API_URL
        self.timeout = timeout if timeout is not None else settings.ABUSEIPDB_TIMEOUT_SECONDS

    @property
    def api_key(self) -> Optional[str]:
        """Resolve API key dynamically from explicit argument or application settings."""
        return self._api_key or settings.ABUSEIPDB_API_KEY

    def check_ip(
        self,
        ip_address: str,
        max_age_in_days: int = 30,
        transport: Optional[httpx.BaseTransport] = None,
    ) -> AbuseIPDBResponse:
        """Query AbuseIPDB API v2 check endpoint for a given IP address.

        Args:
            ip_address: Valid IPv4 or IPv6 address string.
            max_age_in_days: Maximum report age to include in evaluation (1 - 365).
            transport: Optional custom httpx transport for testing/mocking.

        Returns:
            AbuseIPDBResponse containing normalized external reputation attributes.

        Raises:
            ValueError: If ip_address is not a syntactically valid IP address.
            AbuseIPDBConfigError: If ABUSEIPDB_API_KEY is not configured.
            AbuseIPDBAuthError: If authentication with AbuseIPDB fails.
            AbuseIPDBRateLimitError: If API rate limits are exceeded.
            AbuseIPDBConnectionError: If network connection fails or times out.
            AbuseIPDBResponseError: If response payload is malformed or unprocessable.
        """
        # 1. Validate IP address syntax
        clean_ip = str(ip_address).strip()
        try:
            ipaddress.ip_address(clean_ip)
        except ValueError as err:
            raise ValueError(f"Invalid IP address format: '{ip_address}'") from err

        # 2. Check for configured API key
        active_key = self.api_key
        if not active_key or not active_key.strip():
            raise AbuseIPDBConfigError(
                "AbuseIPDB API key is not configured. Set ABUSEIPDB_API_KEY in the environment or .env file."
            )

        headers = {
            "Key": active_key.strip(),
            "Accept": "application/json",
            "User-Agent": "CyberOrchestra-Intelligence/0.1.0",
        }

        params = {
            "ipAddress": clean_ip,
            "maxAgeInDays": max_age_in_days,
            "verbose": "",
        }

        # 3. Execute HTTP request
        try:
            with httpx.Client(timeout=self.timeout, transport=transport) as client:
                response = client.get(self.base_url, headers=headers, params=params)
        except httpx.TimeoutException as err:
            raise AbuseIPDBConnectionError(
                f"AbuseIPDB request timed out after {self.timeout}s: {err}"
            ) from err
        except httpx.RequestError as err:
            raise AbuseIPDBConnectionError(
                f"Network communication failure connecting to AbuseIPDB: {err}"
            ) from err

        # 4. Handle HTTP status codes
        if response.status_code in (401, 403):
            raise AbuseIPDBAuthError(
                f"AbuseIPDB authentication failed (HTTP {response.status_code}): {response.text}"
            )
        if response.status_code == 429:
            raise AbuseIPDBRateLimitError(
                f"AbuseIPDB rate limit exceeded (HTTP 429): {response.text}"
            )
        if response.status_code != 200:
            raise AbuseIPDBResponseError(
                f"AbuseIPDB API returned unexpected status {response.status_code}: {response.text}"
            )

        # 5. Parse response JSON
        try:
            payload = response.json()
        except Exception as err:
            raise AbuseIPDBResponseError(
                f"Malformed JSON response received from AbuseIPDB: {err}"
            ) from err

        if not isinstance(payload, dict) or "data" not in payload or not isinstance(payload["data"], dict):
            raise AbuseIPDBResponseError(
                "AbuseIPDB response does not contain expected 'data' object dictionary."
            )

        data = payload["data"]
        return self._parse_abuseipdb_data(data)

    def convert_to_standardized_evidence(
        self,
        reputation: AbuseIPDBResponse,
    ) -> Tuple[Indicator, Evidence]:
        """Convert an AbuseIPDB response into CyberOrchestra Indicator and Evidence models.

        CRITICAL GROUNDING PRINCIPLE:
        AbuseIPDB's abuseConfidenceScore is external telemetry, NOT internal AI confidence.
        Therefore, confidence on both models is set to None, and external metrics are preserved
        strictly within metadata.
        """
        # 1. Standardized Indicator
        indicator_metadata: Dict[str, Any] = {
            "abuse_confidence_score": reputation.abuse_confidence_score,
            "total_reports": reputation.total_reports,
            "country_code": reputation.country_code,
            "usage_type": reputation.usage_type,
            "is_whitelisted": reputation.is_whitelisted,
            "ip_version": reputation.ip_version,
            "last_reported_at": reputation.last_reported_at.isoformat() if reputation.last_reported_at else None,
        }
        # Include additional preserved metadata
        for k, v in reputation.metadata.items():
            if k not in indicator_metadata:
                indicator_metadata[k] = v

        indicator = Indicator(
            indicator_type=IndicatorType.IP.value,
            value=reputation.ip_address,
            source=reputation.source,
            confidence=None,  # Preserved as None; external score is in metadata
            metadata=indicator_metadata,
        )

        # 2. Standardized Evidence
        clean_id_suffix = reputation.ip_address.replace(":", "_").replace(".", "_")
        evidence_id = f"EVID-ABUSEIPDB-{clean_id_suffix}"

        evidence_description = (
            f"AbuseIPDB external reputation check for {reputation.ip_address}: "
            f"{reputation.total_reports} abuse reports, "
            f"abuse confidence score {reputation.abuse_confidence_score}%"
        )
        if reputation.is_whitelisted is not None:
            evidence_description += f", whitelisted: {reputation.is_whitelisted}"
        if reputation.usage_type:
            evidence_description += f", usage: {reputation.usage_type}"

        evidence_metadata: Dict[str, Any] = {
            "abuse_confidence_score": reputation.abuse_confidence_score,
            "total_reports": reputation.total_reports,
            "country_code": reputation.country_code,
            "usage_type": reputation.usage_type,
            "is_whitelisted": reputation.is_whitelisted,
            "ip_version": reputation.ip_version,
            "last_reported_at": reputation.last_reported_at.isoformat() if reputation.last_reported_at else None,
        }
        for k, v in reputation.metadata.items():
            if k not in evidence_metadata:
                evidence_metadata[k] = v

        evidence = Evidence(
            evidence_id=evidence_id,
            evidence_type=EvidenceType.NETWORK_REPUTATION.value,
            source=reputation.source,
            description=evidence_description,
            timestamp=datetime.now(timezone.utc),
            raw_reference=f"https://www.abuseipdb.com/check/{reputation.ip_address}",
            confidence=None,  # AI confidence left for future detection agents
            metadata=evidence_metadata,
        )

        return indicator, evidence

    def check_and_convert(
        self,
        ip_address: str,
        max_age_in_days: int = 30,
        transport: Optional[httpx.BaseTransport] = None,
    ) -> IPReputationResult:
        """Convenience method to query reputation and return standardized result."""
        reputation = self.check_ip(ip_address, max_age_in_days=max_age_in_days, transport=transport)
        indicator, evidence = self.convert_to_standardized_evidence(reputation)
        return IPReputationResult(
            ip_address=reputation.ip_address,
            reputation=reputation,
            indicator=indicator,
            evidence=evidence,
        )

    def _parse_abuseipdb_data(self, data: Dict[str, Any]) -> AbuseIPDBResponse:
        """Parse raw AbuseIPDB 'data' dictionary into AbuseIPDBResponse model."""
        ip_addr = str(data.get("ipAddress", "")).strip()

        # Parse timestamp safely
        last_reported_raw = data.get("lastReportedAt")
        last_reported_dt: Optional[datetime] = None
        if last_reported_raw:
            try:
                # Handle ISO timestamps with Z or offset
                val_str = str(last_reported_raw).strip()
                if val_str.endswith("Z"):
                    val_str = val_str[:-1] + "+00:00"
                last_reported_dt = datetime.fromisoformat(val_str)
                if last_reported_dt.tzinfo is None:
                    last_reported_dt = last_reported_dt.replace(tzinfo=timezone.utc)
            except Exception:
                last_reported_dt = None

        # Build preserved metadata from supplementary fields
        standard_keys = {
            "ipAddress", "ipVersion", "abuseConfidenceScore", "totalReports",
            "lastReportedAt", "countryCode", "usageType", "isWhitelisted"
        }
        metadata: Dict[str, Any] = {}
        for k, v in data.items():
            if k not in standard_keys:
                metadata[k] = v

        return AbuseIPDBResponse(
            ip_address=ip_addr,
            ip_version=data.get("ipVersion"),
            abuse_confidence_score=int(data.get("abuseConfidenceScore", 0)),
            total_reports=int(data.get("totalReports", 0)),
            last_reported_at=last_reported_dt,
            country_code=data.get("countryCode"),
            usage_type=data.get("usageType"),
            is_whitelisted=data.get("isWhitelisted"),
            source="AbuseIPDB",
            metadata=metadata,
        )


# Global default client instance
abuseipdb_client = AbuseIPDBClient()
