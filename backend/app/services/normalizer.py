"""Data Normalizer Service for CyberOrchestra.

Transforms heterogeneous raw telemetry, threat feeds, and simulated logs into
a standardized Incident representation adhering to the common schema.

Key responsibilities:
- Receives heterogeneous raw incident and evidence dictionaries.
- Validates required fields and rejects malformed inputs deterministically.
- Standardizes indicator types (e.g. IP, URL, domain, hash, CVE, MITRE ATT&CK).
- Preserves source attribution, evidence provenance, and unmapped metadata.
- Safely handles optional fields without hallucination or arbitrary extrapolation.

NOTE: The Data Normalizer does not determine whether an incident is malicious
and does not make response decisions.
"""

from datetime import datetime, timezone
import re
from typing import Any, Dict, List, Optional, Union
from uuid import uuid4

from app.models.incident import (
    Evidence,
    EvidenceType,
    Incident,
    Indicator,
    IndicatorType,
)


class NormalizationError(ValueError):
    """Raised when raw incident or evidence data cannot be normalized."""
    pass


class DataNormalizer:
    """Service that validates and standardizes raw incident payloads into Incident models."""

    # Canonical indicator type synonyms mapping to IndicatorType enum values
    INDICATOR_TYPE_MAP: Dict[str, str] = {
        # IP mappings
        "ip": IndicatorType.IP.value,
        "ipv4": IndicatorType.IP.value,
        "ipv6": IndicatorType.IP.value,
        "ip_address": IndicatorType.IP.value,
        "ip-address": IndicatorType.IP.value,
        "ip address": IndicatorType.IP.value,
        # URL mappings
        "url": IndicatorType.URL.value,
        "uri": IndicatorType.URL.value,
        "link": IndicatorType.URL.value,
        "web_address": IndicatorType.URL.value,
        # Domain mappings
        "domain": IndicatorType.DOMAIN.value,
        "hostname": IndicatorType.DOMAIN.value,
        "fqdn": IndicatorType.DOMAIN.value,
        "domain_name": IndicatorType.DOMAIN.value,
        # File hash mappings
        "hash": IndicatorType.FILE_HASH.value,
        "file_hash": IndicatorType.FILE_HASH.value,
        "filehash": IndicatorType.FILE_HASH.value,
        "sha256": IndicatorType.FILE_HASH.value,
        "sha-256": IndicatorType.FILE_HASH.value,
        "sha1": IndicatorType.FILE_HASH.value,
        "sha-1": IndicatorType.FILE_HASH.value,
        "md5": IndicatorType.FILE_HASH.value,
        # CVE mappings
        "cve": IndicatorType.CVE.value,
        "cve_id": IndicatorType.CVE.value,
        "vulnerability": IndicatorType.CVE.value,
        # MITRE ATT&CK mappings
        "mitre": IndicatorType.MITRE_ATTACK.value,
        "mitre_attack": IndicatorType.MITRE_ATTACK.value,
        "mitre_technique": IndicatorType.MITRE_ATTACK.value,
        "technique": IndicatorType.MITRE_ATTACK.value,
        "attack_technique": IndicatorType.MITRE_ATTACK.value,
        # Log event mappings
        "log": IndicatorType.LOG_EVENT.value,
        "log_event": IndicatorType.LOG_EVENT.value,
        "log_entry": IndicatorType.LOG_EVENT.value,
        "event": IndicatorType.LOG_EVENT.value,
        # Malware mappings
        "malware": IndicatorType.MALWARE.value,
        "malware_family": IndicatorType.MALWARE.value,
        "malware_sample": IndicatorType.MALWARE.value,
        "malware_indicator": IndicatorType.MALWARE.value,
    }

    # Evidence type mapping
    EVIDENCE_TYPE_MAP: Dict[str, str] = {
        "network": EvidenceType.NETWORK_LOG.value,
        "network_log": EvidenceType.NETWORK_LOG.value,
        "firewall": EvidenceType.NETWORK_LOG.value,
        "pcap": EvidenceType.NETWORK_LOG.value,
        "system": EvidenceType.SYSTEM_LOG.value,
        "system_log": EvidenceType.SYSTEM_LOG.value,
        "syslog": EvidenceType.SYSTEM_LOG.value,
        "auth": EvidenceType.AUTHENTICATION_LOG.value,
        "authentication": EvidenceType.AUTHENTICATION_LOG.value,
        "auth_log": EvidenceType.AUTHENTICATION_LOG.value,
        "file": EvidenceType.FILE_SAMPLE.value,
        "file_sample": EvidenceType.FILE_SAMPLE.value,
        "intel": EvidenceType.THREAT_INTEL_FEED.value,
        "threat_intel": EvidenceType.THREAT_INTEL_FEED.value,
        "threat_intel_feed": EvidenceType.THREAT_INTEL_FEED.value,
        "cve": EvidenceType.VULNERABILITY_REPORT.value,
        "vulnerability": EvidenceType.VULNERABILITY_REPORT.value,
        "vulnerability_report": EvidenceType.VULNERABILITY_REPORT.value,
        "observation": EvidenceType.OBSERVATION.value,
        "network_reputation": EvidenceType.NETWORK_REPUTATION.value,
        "reputation": EvidenceType.NETWORK_REPUTATION.value,
        "abuseipdb": EvidenceType.NETWORK_REPUTATION.value,
        "url_reputation": EvidenceType.URL_REPUTATION.value,
        "urlhaus": EvidenceType.URL_REPUTATION.value,
        "vulnerability_intelligence": EvidenceType.VULNERABILITY_INTELLIGENCE.value,
        "nvd": EvidenceType.VULNERABILITY_INTELLIGENCE.value,
        "nvd_cve": EvidenceType.VULNERABILITY_INTELLIGENCE.value,
        "cve_intelligence": EvidenceType.VULNERABILITY_INTELLIGENCE.value,
    }

    def normalize(self, raw_data: Any) -> Incident:
        """Normalize a raw incident dictionary into a standardized Incident object.

        Args:
            raw_data: Raw input dictionary containing incident details.

        Returns:
            Standardized Incident Pydantic model instance.

        Raises:
            NormalizationError: If required fields are missing or data is malformed.
        """
        if not isinstance(raw_data, dict):
            raise NormalizationError("Raw incident payload must be a JSON object / Python dictionary.")

        # 1. Validate and extract incident ID
        incident_id = self._extract_string(raw_data, ["incident_id", "id"])
        if not incident_id:
            raise NormalizationError("Missing required field: 'incident_id'")

        # 2. Validate and extract incident type
        incident_type = self._extract_string(raw_data, ["incident_type", "type", "category"])
        if not incident_type:
            raise NormalizationError("Missing required field: 'incident_type'")

        # 3. Validate and extract description
        description = self._extract_string(raw_data, ["description", "summary", "message"])
        if not description:
            raise NormalizationError("Missing required field: 'description'")

        # 4. Resolve source provenance
        source = self._extract_string(raw_data, ["source", "origin", "sensor", "feed"])
        if not source:
            # Fallback to source from first indicator or evidence if present, or mark as 'unspecified'
            inferred_source = self._infer_source_from_children(raw_data)
            source = inferred_source or "unspecified"

        # 5. Extract timestamp (safely parse or generate current UTC)
        timestamp = self._parse_timestamp(raw_data.get("timestamp") or raw_data.get("created_at") or raw_data.get("time"))

        # 6. Extract severity if supplied (do not calculate severity)
        raw_severity = raw_data.get("severity")
        severity = str(raw_severity).strip().lower() if raw_severity is not None and str(raw_severity).strip() else None

        # 7. Normalize indicators
        raw_indicators = raw_data.get("indicators")
        normalized_indicators: List[Indicator] = []
        if raw_indicators is not None:
            if not isinstance(raw_indicators, list):
                raise NormalizationError("Field 'indicators' must be a list if provided.")
            for idx, raw_ind in enumerate(raw_indicators):
                normalized_indicators.append(
                    self._normalize_indicator(raw_ind, default_source=source, index=idx)
                )

        # 8. Normalize evidence
        raw_evidence = raw_data.get("evidence")
        normalized_evidence: List[Evidence] = []
        if raw_evidence is not None:
            if not isinstance(raw_evidence, list):
                raise NormalizationError("Field 'evidence' must be a list if provided.")
            for idx, raw_ev in enumerate(raw_evidence):
                normalized_evidence.append(
                    self._normalize_evidence(raw_ev, default_source=source, incident_id=incident_id, index=idx)
                )

        # Construct and validate the Incident model
        try:
            return Incident(
                incident_id=incident_id,
                timestamp=timestamp,
                incident_type=incident_type,
                description=description,
                severity=severity,
                source=source,
                indicators=normalized_indicators,
                evidence=normalized_evidence,
            )
        except Exception as e:
            raise NormalizationError(f"Incident schema validation error: {e}") from e

    def _normalize_indicator(self, raw_ind: Any, default_source: str, index: int) -> Indicator:
        """Normalize a single raw indicator dictionary."""
        if not isinstance(raw_ind, dict):
            raise NormalizationError(f"Indicator at index {index} must be a dictionary.")

        raw_type = self._extract_string(raw_ind, ["type", "indicator_type", "kind"]) or "other"
        normalized_type = self._normalize_indicator_type(raw_type)

        value = self._extract_string(raw_ind, ["value", "val", "indicator"])
        if not value:
            raise NormalizationError(f"Indicator at index {index} is missing a required 'value'.")

        source = self._extract_string(raw_ind, ["source", "origin"]) or default_source

        confidence = self._parse_confidence(raw_ind.get("confidence"))

        # Preserve unmapped fields in metadata
        reserved_keys = {"type", "indicator_type", "kind", "value", "val", "indicator", "source", "origin", "confidence", "metadata"}
        metadata = dict(raw_ind.get("metadata", {})) if isinstance(raw_ind.get("metadata"), dict) else {}
        for k, v in raw_ind.items():
            if k not in reserved_keys:
                metadata[k] = v

        return Indicator(
            indicator_type=normalized_type,
            value=value,
            source=source,
            confidence=confidence,
            metadata=metadata,
        )

    def _normalize_evidence(self, raw_ev: Any, default_source: str, incident_id: str, index: int) -> Evidence:
        """Normalize a single raw evidence dictionary."""
        if not isinstance(raw_ev, dict):
            raise NormalizationError(f"Evidence at index {index} must be a dictionary.")

        evidence_id = self._extract_string(raw_ev, ["evidence_id", "id"])
        if not evidence_id:
            evidence_id = f"{incident_id}-EVID-{index + 1}"

        raw_type = self._extract_string(raw_ev, ["evidence_type", "type", "category"]) or "observation"
        normalized_type = self._normalize_evidence_type(raw_type)

        source = self._extract_string(raw_ev, ["source", "sensor", "origin"]) or default_source

        description = self._extract_string(raw_ev, ["description", "summary", "details", "message"])
        if not description:
            description = f"Supporting evidence {evidence_id} of type {normalized_type}"

        timestamp = self._parse_timestamp(raw_ev.get("timestamp") or raw_ev.get("time")) if ("timestamp" in raw_ev or "time" in raw_ev) else None

        raw_reference = self._extract_string(raw_ev, ["raw_reference", "reference", "ref", "url", "log_id"])

        confidence = self._parse_confidence(raw_ev.get("confidence"))

        reserved_keys = {
            "evidence_id", "id", "evidence_type", "type", "category",
            "source", "sensor", "origin", "description", "summary", "details", "message",
            "timestamp", "time", "raw_reference", "reference", "ref", "url", "log_id",
            "confidence", "metadata"
        }
        metadata = dict(raw_ev.get("metadata", {})) if isinstance(raw_ev.get("metadata"), dict) else {}
        for k, v in raw_ev.items():
            if k not in reserved_keys:
                metadata[k] = v

        return Evidence(
            evidence_id=evidence_id,
            evidence_type=normalized_type,
            source=source,
            description=description,
            timestamp=timestamp,
            raw_reference=raw_reference,
            confidence=confidence,
            metadata=metadata,
        )

    def _normalize_indicator_type(self, raw_type: str) -> str:
        """Map heterogeneous indicator type names to standardized IndicatorType values."""
        cleaned = raw_type.strip().lower()
        cleaned = re.sub(r"[\s\-_]+", "_", cleaned)
        return self.INDICATOR_TYPE_MAP.get(cleaned, cleaned or IndicatorType.OTHER.value)

    def _normalize_evidence_type(self, raw_type: str) -> str:
        """Map heterogeneous evidence type names to standardized EvidenceType values."""
        cleaned = raw_type.strip().lower()
        cleaned = re.sub(r"[\s\-_]+", "_", cleaned)
        return self.EVIDENCE_TYPE_MAP.get(cleaned, cleaned or EvidenceType.OTHER.value)

    @staticmethod
    def _extract_string(data: Dict[str, Any], candidates: List[str]) -> Optional[str]:
        """Extract the first non-empty string value from a list of candidate keys."""
        for key in candidates:
            if key in data and data[key] is not None:
                val = str(data[key]).strip()
                if val:
                    return val
        return None

    @staticmethod
    def _parse_timestamp(val: Any) -> datetime:
        """Parse varied timestamp representations into timezone-aware UTC datetime."""
        if val is None:
            return datetime.now(timezone.utc)
        if isinstance(val, datetime):
            if val.tzinfo is None:
                return val.replace(tzinfo=timezone.utc)
            return val.astimezone(timezone.utc)
        if isinstance(val, (int, float)):
            try:
                return datetime.fromtimestamp(val, tz=timezone.utc)
            except Exception:
                return datetime.now(timezone.utc)
        if isinstance(val, str):
            val_str = val.strip()
            # Handle ISO formats
            try:
                # Replace trailing 'Z' if needed for fromisoformat in older pythons
                if val_str.endswith("Z"):
                    val_str = val_str[:-1] + "+00:00"
                dt = datetime.fromisoformat(val_str)
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                return dt.astimezone(timezone.utc)
            except Exception:
                pass
        return datetime.now(timezone.utc)

    @staticmethod
    def _parse_confidence(val: Any) -> Optional[float]:
        """Safely parse and bound confidence values between 0.0 and 1.0."""
        if val is None:
            return None
        try:
            num = float(val)
            # If percentage scale (e.g. 85 or 100), rescale to [0.0, 1.0]
            if num > 1.0 and num <= 100.0:
                num = num / 100.0
            if num < 0.0:
                num = 0.0
            elif num > 1.0:
                num = 1.0
            return round(num, 4)
        except (ValueError, TypeError):
            return None

    @staticmethod
    def _infer_source_from_children(data: Dict[str, Any]) -> Optional[str]:
        """Infer source from indicators or evidence if root source is omitted."""
        indicators = data.get("indicators")
        if isinstance(indicators, list) and len(indicators) > 0 and isinstance(indicators[0], dict):
            src = indicators[0].get("source") or indicators[0].get("origin")
            if src:
                return str(src).strip()
        evidence = data.get("evidence")
        if isinstance(evidence, list) and len(evidence) > 0 and isinstance(evidence[0], dict):
            src = evidence[0].get("source") or evidence[0].get("sensor")
            if src:
                return str(src).strip()
        return None


# Module-level default instance
default_normalizer = DataNormalizer()


def normalize_incident(raw_data: Any) -> Incident:
    """Convenience helper to normalize a raw incident payload."""
    return default_normalizer.normalize(raw_data)
