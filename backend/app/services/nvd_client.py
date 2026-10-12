"""NVD CVE API 2.0 Client for CyberOrchestra.

Responsible for querying external vulnerability intelligence from the NIST National
Vulnerability Database (NVD) CVE API 2.0 and converting the relevant response into
CyberOrchestra's standardized Indicator and Evidence models.

IMPORTANT DESIGN PRINCIPLES:
- This client retrieves external vulnerability evidence ONLY.
- It does NOT determine whether any specific observed asset is exploitable.
- It does NOT classify a CVE as "exploited" or "confirmed in this incident".
- CVSS scores are vulnerability metadata — NOT internal AI confidence scores.
- NVD provides vulnerability intelligence; exploitation determination belongs to
  the future Vulnerability Assessment Agent after correlation with incident evidence.

Architecture position:
    NVD CVE API 2.0
        ↓
    NVD Client (this module)
        ↓
    External Vulnerability Evidence
        ↓
    CyberOrchestra Indicator / Evidence
        ↓
    Future Vulnerability Assessment Agent
"""

import re
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

import httpx

from app.core.config import settings
from app.models.incident import Evidence, EvidenceType, Indicator, IndicatorType
from app.models.nvd import (
    AffectedProduct,
    CVEIntelligenceResult,
    CVEReference,
    CWEEntry,
    CVSSMetricV2,
    CVSSMetricV3,
    CVSSMetricV4,
    NVDCVEResponse,
)


# ---------------------------------------------------------------------------
# Exception hierarchy
# ---------------------------------------------------------------------------

class NVDError(Exception):
    """Base exception for all NVD client errors."""
    pass


class NVDInvalidCVEError(NVDError):
    """Raised when the provided CVE identifier does not match expected format."""
    pass


class NVDNotFoundError(NVDError):
    """Raised when the CVE does not exist in NVD or returns no results."""
    pass


class NVDRateLimitError(NVDError):
    """Raised when NVD returns HTTP 403 or 429 (rate limit / API key required)."""
    pass


class NVDConnectionError(NVDError):
    """Raised on network timeout, DNS failure, or unreachable NVD host."""
    pass


class NVDResponseError(NVDError):
    """Raised when NVD returns unexpected HTTP errors or a malformed payload."""
    pass


# ---------------------------------------------------------------------------
# CVE ID validation
# ---------------------------------------------------------------------------

# Official CVE ID format: CVE-YEAR-SEQUENCE (year ≥ 1999, sequence ≥ 4 digits)
_CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)


def validate_cve_id(cve_id: str) -> str:
    """Validate and normalise a CVE identifier string.

    Args:
        cve_id: Raw CVE identifier provided by the caller.

    Returns:
        Upper-cased, stripped CVE identifier.

    Raises:
        NVDInvalidCVEError: If the identifier does not match CVE-YYYY-NNNN+ format.
    """
    cleaned = str(cve_id).strip().upper()
    if not _CVE_PATTERN.match(cleaned):
        raise NVDInvalidCVEError(
            f"Invalid CVE identifier: '{cve_id}'. "
            "Expected format: CVE-YYYY-NNNN (e.g., CVE-2024-12345)."
        )
    return cleaned


# ---------------------------------------------------------------------------
# NVD Client
# ---------------------------------------------------------------------------

class NVDClient:
    """Client for retrieving external vulnerability intelligence from NVD CVE API 2.0.

    The NVD API key is optional: without a key the API works but with a lower rate
    limit (~5 requests per 30 seconds). With a key the limit is ~50 per 30 seconds.

    See: https://nvd.nist.gov/developers/vulnerabilities
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        base_url: Optional[str] = None,
        timeout: Optional[float] = None,
    ):
        """Initialise the NVD client.

        Args:
            api_key: NVD API key. Optional — if omitted, loaded from settings.NVD_API_KEY.
                     If still absent the request proceeds without authentication.
            base_url: NVD CVE API 2.0 endpoint URL. Defaults to settings.NVD_API_URL.
            timeout: Request timeout in seconds. Defaults to settings.NVD_TIMEOUT_SECONDS.
        """
        self._api_key = api_key
        self.base_url = base_url or settings.NVD_API_URL
        self.timeout = timeout if timeout is not None else settings.NVD_TIMEOUT_SECONDS

    @property
    def api_key(self) -> Optional[str]:
        """Resolve API key dynamically from constructor argument or application settings."""
        return self._api_key or settings.NVD_API_KEY

    def get_cve(
        self,
        cve_id: str,
        transport: Optional[httpx.BaseTransport] = None,
    ) -> NVDCVEResponse:
        """Query NVD CVE API 2.0 for vulnerability intelligence on a specific CVE.

        Args:
            cve_id: CVE identifier string (e.g., 'CVE-2024-12345').
            transport: Optional custom httpx transport for testing/mocking.

        Returns:
            NVDCVEResponse with structured vulnerability fields.

        Raises:
            NVDInvalidCVEError: If cve_id does not match the expected CVE format.
            NVDNotFoundError: If NVD returns no matching CVE records.
            NVDRateLimitError: If NVD returns HTTP 403 or 429 (rate limit).
            NVDConnectionError: If network/timeout failure occurs.
            NVDResponseError: If NVD returns an unexpected status or malformed JSON.
        """
        # 1. Validate CVE format
        clean_cve_id = validate_cve_id(cve_id)

        # 2. Construct headers — include API key only when configured
        headers: Dict[str, str] = {
            "Accept": "application/json",
            "User-Agent": "CyberOrchestra-Intelligence/0.1.0",
        }
        active_key = self.api_key
        if active_key and active_key.strip():
            headers["apiKey"] = active_key.strip()

        # 3. Query parameters
        params: Dict[str, str] = {"cveId": clean_cve_id}

        # 4. Execute HTTP GET request
        try:
            with httpx.Client(timeout=self.timeout, transport=transport) as client:
                response = client.get(self.base_url, headers=headers, params=params)
        except httpx.TimeoutException as err:
            raise NVDConnectionError(
                f"NVD request timed out after {self.timeout}s: {err}"
            ) from err
        except httpx.RequestError as err:
            raise NVDConnectionError(
                f"Network communication failure connecting to NVD: {err}"
            ) from err

        # 5. Handle HTTP status codes
        if response.status_code in (403, 429):
            raise NVDRateLimitError(
                f"NVD rate limit or API key required (HTTP {response.status_code}). "
                "Consider setting NVD_API_KEY for higher request limits."
            )
        if response.status_code != 200:
            raise NVDResponseError(
                f"NVD API returned unexpected status {response.status_code}: {response.text[:200]}"
            )

        # 6. Parse response JSON
        try:
            payload = response.json()
        except Exception as err:
            raise NVDResponseError(
                f"Malformed JSON received from NVD: {err}"
            ) from err

        if not isinstance(payload, dict):
            raise NVDResponseError("NVD response is not a JSON object.")

        # 7. Check that NVD returned results
        vulnerabilities = payload.get("vulnerabilities", [])
        if not isinstance(vulnerabilities, list) or len(vulnerabilities) == 0:
            total_results = payload.get("totalResults", 0)
            if total_results == 0:
                raise NVDNotFoundError(
                    f"CVE '{clean_cve_id}' was not found in NVD. "
                    "Note: synthetic CVE IDs used in CyberOrchestra simulation scenarios "
                    "may not exist in NVD."
                )
            raise NVDResponseError(
                f"NVD returned totalResults={total_results} but no vulnerability entries."
            )

        # 8. Parse the first (and only) CVE entry
        return self._parse_nvd_entry(clean_cve_id, vulnerabilities[0])

    def convert_to_standardized_evidence(
        self,
        cve_data: NVDCVEResponse,
    ) -> Tuple[Indicator, Evidence]:
        """Convert an NVDCVEResponse into CyberOrchestra Indicator and Evidence models.

        CRITICAL GROUNDING PRINCIPLES:
        1. confidence is set to None on both models — CVSS scores are NOT AI confidence.
        2. CVSS information is preserved inside metadata for downstream agents.
        3. This evidence represents vulnerability INTELLIGENCE, not exploitation confirmation.
        4. Exploitation determination is delegated to the future Vulnerability Assessment Agent.

        Args:
            cve_data: Parsed NVD CVE response.

        Returns:
            Tuple of (Indicator, Evidence) in CyberOrchestra standard format.
        """
        # 1. Build Indicator
        indicator_metadata: Dict[str, Any] = {
            "description": cve_data.description,
            "published": cve_data.published.isoformat() if cve_data.published else None,
            "last_modified": cve_data.last_modified.isoformat() if cve_data.last_modified else None,
            "vuln_status": cve_data.vuln_status,
            "cvss_v3_base_score": cve_data.cvss_v3.base_score if cve_data.cvss_v3 else None,
            "cvss_v3_severity": cve_data.cvss_v3.base_severity if cve_data.cvss_v3 else None,
            "cvss_v2_base_score": cve_data.cvss_v2.base_score if cve_data.cvss_v2 else None,
            "cwe_ids": [c.cwe_id for c in cve_data.cwes if c.cwe_id],
            "source_identifier": cve_data.source_identifier,
        }

        indicator = Indicator(
            indicator_type=IndicatorType.CVE.value,
            value=cve_data.cve_id,
            source=cve_data.source,
            confidence=None,  # CVSS is NOT an AI confidence score
            metadata=indicator_metadata,
        )

        # 2. Build Evidence
        evidence_id = f"EVID-NVD-{cve_data.cve_id}"

        # Build human-readable description
        cvss_part = ""
        if cve_data.cvss_v3:
            cvss_part = (
                f"CVSS v3 base score={cve_data.cvss_v3.base_score}, "
                f"severity={cve_data.cvss_v3.base_severity}"
            )
        elif cve_data.cvss_v2:
            cvss_part = (
                f"CVSS v2 base score={cve_data.cvss_v2.base_score}, "
                f"severity={cve_data.cvss_v2.base_severity}"
            )
        elif cve_data.cvss_v4:
            cvss_part = (
                f"CVSS v4 base score={cve_data.cvss_v4.base_score}, "
                f"severity={cve_data.cvss_v4.base_severity}"
            )
        else:
            cvss_part = "no CVSS metric available"

        cwe_part = ""
        if cve_data.cwes:
            cwe_ids = [c.cwe_id for c in cve_data.cwes if c.cwe_id]
            cwe_part = f", CWE={cwe_ids}" if cwe_ids else ""

        truncated_desc = (cve_data.description or "No description available")[:200]

        evidence_desc = (
            f"NVD vulnerability intelligence for {cve_data.cve_id}: "
            f"{truncated_desc}. "
            f"{cvss_part}{cwe_part}. "
            f"Status: {cve_data.vuln_status or 'unknown'}."
        )

        evidence_metadata: Dict[str, Any] = {
            "cve_id": cve_data.cve_id,
            "description": cve_data.description,
            "published": cve_data.published.isoformat() if cve_data.published else None,
            "last_modified": cve_data.last_modified.isoformat() if cve_data.last_modified else None,
            "vuln_status": cve_data.vuln_status,
            "source_identifier": cve_data.source_identifier,
            # CVSS fields preserved as metadata — NOT used as confidence
            "cvss_v2": cve_data.cvss_v2.model_dump() if cve_data.cvss_v2 else None,
            "cvss_v3": cve_data.cvss_v3.model_dump() if cve_data.cvss_v3 else None,
            "cvss_v4": cve_data.cvss_v4.model_dump() if cve_data.cvss_v4 else None,
            "cwes": [c.model_dump() for c in cve_data.cwes],
            "references": [r.model_dump() for r in cve_data.references],
            "affected_products_count": len(cve_data.affected_products),
            "affected_products": [p.model_dump() for p in cve_data.affected_products[:20]],
            "nvd_url": cve_data.nvd_url,
            "provenance": "NVD CVE API 2.0",
            "note": (
                "CVSS scores are vulnerability severity metrics, NOT CyberOrchestra AI confidence. "
                "Exploitation determination requires correlation with incident/asset evidence "
                "by the Vulnerability Assessment Agent."
            ),
        }
        for k, v in cve_data.metadata.items():
            if k not in evidence_metadata:
                evidence_metadata[k] = v

        evidence = Evidence(
            evidence_id=evidence_id,
            evidence_type=EvidenceType.VULNERABILITY_INTELLIGENCE.value,
            source=cve_data.source,
            description=evidence_desc,
            timestamp=cve_data.last_modified or cve_data.published or datetime.now(timezone.utc),
            raw_reference=cve_data.nvd_url or f"https://nvd.nist.gov/vuln/detail/{cve_data.cve_id}",
            confidence=None,  # Not populated from CVSS — left for reasoning agents
            metadata=evidence_metadata,
        )

        return indicator, evidence

    def get_cve_and_convert(
        self,
        cve_id: str,
        transport: Optional[httpx.BaseTransport] = None,
    ) -> CVEIntelligenceResult:
        """Query NVD for a CVE and return the full standardized intelligence result.

        Args:
            cve_id: CVE identifier string.
            transport: Optional httpx transport (for testing/mocking).

        Returns:
            CVEIntelligenceResult containing NVD data and standardized Indicator/Evidence.
        """
        cve_data = self.get_cve(cve_id, transport=transport)
        indicator, evidence = self.convert_to_standardized_evidence(cve_data)
        return CVEIntelligenceResult(
            cve_id=cve_data.cve_id,
            cve_data=cve_data,
            indicator=indicator,
            evidence=evidence,
        )

    # -----------------------------------------------------------------------
    # Private NVD response parsing helpers
    # -----------------------------------------------------------------------

    def _parse_nvd_entry(self, cve_id: str, entry: Dict[str, Any]) -> NVDCVEResponse:
        """Parse a single NVD 'vulnerabilities' list item into NVDCVEResponse."""
        if not isinstance(entry, dict) or "cve" not in entry:
            raise NVDResponseError(
                f"NVD entry for {cve_id} is missing expected 'cve' key."
            )

        cve = entry["cve"]
        if not isinstance(cve, dict):
            raise NVDResponseError(
                f"NVD 'cve' field for {cve_id} is not a dictionary."
            )

        # Description (prefer English)
        description = self._extract_description(cve.get("descriptions", []))

        # Timestamps
        published = self._parse_nvd_datetime(cve.get("published"))
        last_modified = self._parse_nvd_datetime(cve.get("lastModified"))

        # CVSS metrics
        cvss_v2 = self._parse_cvss_v2(cve.get("metrics", {}).get("cvssMetricV2", []))
        cvss_v3 = self._parse_cvss_v3x(cve.get("metrics", {}).get("cvssMetricV31", []))
        if cvss_v3 is None:
            cvss_v3 = self._parse_cvss_v3x(cve.get("metrics", {}).get("cvssMetricV30", []))
        cvss_v4 = self._parse_cvss_v4(cve.get("metrics", {}).get("cvssMetricV40", []))

        # CWE entries
        cwes = self._parse_cwes(cve.get("weaknesses", []))

        # References
        references = self._parse_references(cve.get("references", []))

        # Affected products (simplified from configurations)
        affected_products = self._parse_affected_products(cve.get("configurations", []))

        # NVD canonical URL
        nvd_url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"

        # Preserve unhandled top-level keys as metadata
        known_keys = {
            "id", "sourceIdentifier", "published", "lastModified", "vulnStatus",
            "descriptions", "metrics", "weaknesses", "configurations", "references",
            "cveTags", "evaluatorComment", "evaluatorSolution", "evaluatorImpact",
        }
        metadata: Dict[str, Any] = {}
        for k, v in cve.items():
            if k not in known_keys:
                metadata[k] = v

        return NVDCVEResponse(
            cve_id=cve_id,
            source_identifier=cve.get("sourceIdentifier"),
            published=published,
            last_modified=last_modified,
            vuln_status=cve.get("vulnStatus"),
            description=description,
            cvss_v2=cvss_v2,
            cvss_v3=cvss_v3,
            cvss_v4=cvss_v4,
            cwes=cwes,
            references=references,
            affected_products=affected_products,
            source="NVD",
            nvd_url=nvd_url,
            metadata=metadata,
        )

    @staticmethod
    def _extract_description(descriptions: List[Any]) -> Optional[str]:
        """Extract English description text from NVD descriptions array."""
        if not isinstance(descriptions, list):
            return None
        for item in descriptions:
            if isinstance(item, dict) and item.get("lang") == "en":
                return item.get("value") or None
        # Fall back to first description if no English found
        if descriptions and isinstance(descriptions[0], dict):
            return descriptions[0].get("value") or None
        return None

    @staticmethod
    def _parse_nvd_datetime(val: Any) -> Optional[datetime]:
        """Parse NVD ISO 8601 timestamp strings into timezone-aware datetimes."""
        if not val or not isinstance(val, str):
            return None
        try:
            val_str = val.strip()
            if val_str.endswith("Z"):
                val_str = val_str[:-1] + "+00:00"
            dt = datetime.fromisoformat(val_str)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt.astimezone(timezone.utc)
        except Exception:
            return None

    @staticmethod
    def _parse_cvss_v2(metrics: List[Any]) -> Optional[CVSSMetricV2]:
        """Parse the primary CVSS v2 metric from NVD cvssMetricV2 list."""
        if not isinstance(metrics, list) or not metrics:
            return None
        # Prefer 'Primary' type if multiple entries
        primary = next(
            (m for m in metrics if isinstance(m, dict) and m.get("type") == "Primary"),
            metrics[0] if isinstance(metrics[0], dict) else None,
        )
        if not primary or not isinstance(primary, dict):
            return None
        cvss_data = primary.get("cvssData", {}) or {}
        return CVSSMetricV2(
            source=primary.get("source"),
            type=primary.get("type"),
            cvss_version="2.0",
            base_score=cvss_data.get("baseScore"),
            base_severity=primary.get("baseSeverity"),
            vector_string=cvss_data.get("vectorString"),
            exploitability_score=primary.get("exploitabilityScore"),
            impact_score=primary.get("impactScore"),
        )

    @staticmethod
    def _parse_cvss_v3x(metrics: List[Any]) -> Optional[CVSSMetricV3]:
        """Parse the primary CVSS v3.x metric from NVD cvssMetricV31 or V30 list."""
        if not isinstance(metrics, list) or not metrics:
            return None
        primary = next(
            (m for m in metrics if isinstance(m, dict) and m.get("type") == "Primary"),
            metrics[0] if isinstance(metrics[0], dict) else None,
        )
        if not primary or not isinstance(primary, dict):
            return None
        cvss_data = primary.get("cvssData", {}) or {}
        return CVSSMetricV3(
            source=primary.get("source"),
            type=primary.get("type"),
            cvss_version=cvss_data.get("version"),
            base_score=cvss_data.get("baseScore"),
            base_severity=cvss_data.get("baseSeverity"),
            vector_string=cvss_data.get("vectorString"),
            exploitability_score=primary.get("exploitabilityScore"),
            impact_score=primary.get("impactScore"),
            attack_vector=cvss_data.get("attackVector"),
            attack_complexity=cvss_data.get("attackComplexity"),
            privileges_required=cvss_data.get("privilegesRequired"),
            user_interaction=cvss_data.get("userInteraction"),
            scope=cvss_data.get("scope"),
            confidentiality_impact=cvss_data.get("confidentialityImpact"),
            integrity_impact=cvss_data.get("integrityImpact"),
            availability_impact=cvss_data.get("availabilityImpact"),
        )

    @staticmethod
    def _parse_cvss_v4(metrics: List[Any]) -> Optional[CVSSMetricV4]:
        """Parse the primary CVSS v4.0 metric from NVD cvssMetricV40 list."""
        if not isinstance(metrics, list) or not metrics:
            return None
        primary = next(
            (m for m in metrics if isinstance(m, dict) and m.get("type") == "Primary"),
            metrics[0] if isinstance(metrics[0], dict) else None,
        )
        if not primary or not isinstance(primary, dict):
            return None
        cvss_data = primary.get("cvssData", {}) or {}
        return CVSSMetricV4(
            source=primary.get("source"),
            type=primary.get("type"),
            cvss_version=cvss_data.get("version"),
            base_score=cvss_data.get("baseScore"),
            base_severity=cvss_data.get("baseSeverity"),
            vector_string=cvss_data.get("vectorString"),
        )

    @staticmethod
    def _parse_cwes(weaknesses: List[Any]) -> List[CWEEntry]:
        """Parse CWE weakness entries from NVD weaknesses array."""
        result: List[CWEEntry] = []
        if not isinstance(weaknesses, list):
            return result
        for weakness in weaknesses:
            if not isinstance(weakness, dict):
                continue
            source = weakness.get("source")
            for desc in weakness.get("description", []):
                if isinstance(desc, dict) and desc.get("lang") == "en":
                    value = desc.get("value", "")
                    result.append(CWEEntry(
                        cwe_id=value if value.startswith("CWE-") else None,
                        description=value,
                        source=source,
                    ))
        return result

    @staticmethod
    def _parse_references(references: List[Any]) -> List[CVEReference]:
        """Parse NVD references array into CVEReference list."""
        result: List[CVEReference] = []
        if not isinstance(references, list):
            return result
        for ref in references:
            if not isinstance(ref, dict):
                continue
            tags = ref.get("tags", [])
            result.append(CVEReference(
                url=ref.get("url"),
                source=ref.get("source"),
                tags=tags if isinstance(tags, list) else [],
            ))
        return result

    @staticmethod
    def _parse_affected_products(configurations: List[Any]) -> List[AffectedProduct]:
        """Parse NVD configurations (CPE matches) into simplified AffectedProduct list."""
        result: List[AffectedProduct] = []
        if not isinstance(configurations, list):
            return result

        def _walk_nodes(nodes: List[Any]) -> None:
            for node in nodes:
                if not isinstance(node, dict):
                    continue
                # Recurse into nested nodes
                _walk_nodes(node.get("nodes", []))
                # Process cpeMatch entries
                for cpe_match in node.get("cpeMatch", []):
                    if not isinstance(cpe_match, dict):
                        continue
                    cpe_name = cpe_match.get("criteria", "")
                    # Parse vendor/product from CPE 2.3 uri (cpe:2.3:a:vendor:product:...)
                    vendor = product = None
                    parts = cpe_name.split(":") if cpe_name else []
                    if len(parts) >= 5:
                        vendor = parts[3] if parts[3] != "*" else None
                        product = parts[4] if parts[4] != "*" else None
                    result.append(AffectedProduct(
                        cpe_name=cpe_name or None,
                        vendor=vendor,
                        product=product,
                        version_start_including=cpe_match.get("versionStartIncluding"),
                        version_end_including=cpe_match.get("versionEndIncluding"),
                        version_start_excluding=cpe_match.get("versionStartExcluding"),
                        version_end_excluding=cpe_match.get("versionEndExcluding"),
                        vulnerable=cpe_match.get("vulnerable"),
                    ))

        _walk_nodes(configurations)
        return result


# ---------------------------------------------------------------------------
# Global default client instance
# ---------------------------------------------------------------------------

nvd_client = NVDClient()
