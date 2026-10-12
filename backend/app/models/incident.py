"""Standardized incident and evidence models for CyberOrchestra.

These models define the common internal representation produced by the Data Normalizer
and consumed by downstream AI agents.
"""

from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field


class IndicatorType(str, Enum):
    """Standardized indicator types supported across threat telemetry."""

    IP = "ip"
    URL = "url"
    DOMAIN = "domain"
    FILE_HASH = "file_hash"
    CVE = "cve"
    MITRE_ATTACK = "mitre_attack"
    LOG_EVENT = "log_event"
    MALWARE = "malware"
    OTHER = "other"


class EvidenceType(str, Enum):
    """Standardized categories of forensic evidence."""

    NETWORK_LOG = "network_log"
    SYSTEM_LOG = "system_log"
    AUTHENTICATION_LOG = "authentication_log"
    FILE_SAMPLE = "file_sample"
    THREAT_INTEL_FEED = "threat_intel_feed"
    NETWORK_REPUTATION = "network_reputation"
    URL_REPUTATION = "url_reputation"
    VULNERABILITY_REPORT = "vulnerability_report"
    VULNERABILITY_INTELLIGENCE = "vulnerability_intelligence"
    OBSERVATION = "observation"
    OTHER = "other"


class Indicator(BaseModel):
    """Normalized atomic indicator of compromise or interest.

    Attributes:
        indicator_type: Normalized indicator category (e.g., 'ip', 'domain', 'file_hash').
        value: The indicator value (e.g., IP address, URL, hash string).
        source: Provenance source of the indicator (e.g., 'simulated', 'AbuseIPDB').
        confidence: Optional confidence score between 0.0 and 1.0.
        metadata: Arbitrary contextual metadata preserved from raw telemetry.
    """

    indicator_type: str = Field(
        ...,
        description="Standardized type of indicator (e.g. ip, url, domain, file_hash, cve, mitre_attack)",
    )
    value: str = Field(..., description="Observable indicator value")
    source: str = Field(..., description="Origin source of this indicator")
    confidence: Optional[float] = Field(
        default=None,
        ge=0.0,
        le=1.0,
        description="Confidence score in the range [0.0, 1.0]",
    )
    metadata: Dict[str, Any] = Field(
        default_factory=dict,
        description="Additional context or unmapped fields from raw telemetry",
    )

    model_config = ConfigDict(extra="ignore")


class Evidence(BaseModel):
    """Normalized forensic evidence item supporting an incident.

    Attributes:
        evidence_id: Unique identifier for this evidence item.
        evidence_type: Classification of evidence (e.g., 'network_log', 'system_log').
        source: Telemetry source or logging agent that recorded the evidence.
        description: Human-readable narrative or summary of the evidence.
        timestamp: Optional capture/event timestamp.
        raw_reference: Optional external URI, log pointer, or raw artifact reference.
        confidence: Optional confidence score between 0.0 and 1.0.
        metadata: Preserved raw key-value attributes and provenance context.
    """

    evidence_id: str = Field(..., description="Unique identifier for the evidence entry")
    evidence_type: str = Field(..., description="Classification category of the evidence")
    source: str = Field(..., description="Originating source system or feed")
    description: str = Field(..., description="Summary or observation details")
    timestamp: Optional[datetime] = Field(
        default=None,
        description="Event observation timestamp in UTC",
    )
    raw_reference: Optional[str] = Field(
        default=None,
        description="Pointer or reference ID to raw artifact or source log",
    )
    confidence: Optional[float] = Field(
        default=None,
        ge=0.0,
        le=1.0,
        description="Confidence score in the range [0.0, 1.0]",
    )
    metadata: Dict[str, Any] = Field(
        default_factory=dict,
        description="Preserved raw metadata and key-value properties",
    )

    model_config = ConfigDict(extra="ignore")


class Incident(BaseModel):
    """Standardized representation of a security incident.

    This common schema is the output of the Data Normalizer and serves as the input
    contract for all downstream AI analysis agents.

    Attributes:
        incident_id: Unique identifier for the incident.
        timestamp: Event or creation timestamp in UTC.
        incident_type: High-level classification of the incident.
        description: Textual summary of the observed activity.
        severity: Initial input severity if supplied by source; not calculated by normalizer.
        source: Primary originating feed, telemetry sensor, or simulation source.
        indicators: List of atomic normalized indicators (IPs, hashes, CVEs, etc.).
        evidence: List of supporting forensic evidence artifacts.
    """

    incident_id: str = Field(..., description="Unique incident identifier")
    timestamp: datetime = Field(
        default_factory=lambda: datetime.now(timezone.utc),
        description="Timestamp of the incident in UTC",
    )
    incident_type: str = Field(
        ...,
        description="Type/category of the incident (e.g., suspicious_network_activity)",
    )
    description: str = Field(..., description="Human-readable incident summary")
    severity: Optional[str] = Field(
        default=None,
        description="Initial severity if provided by source; normalizer does not calculate this",
    )
    source: str = Field(
        ...,
        description="Originating source or ingest feed provenance",
    )
    indicators: List[Indicator] = Field(
        default_factory=list,
        description="Collection of normalized indicators associated with the incident",
    )
    evidence: List[Evidence] = Field(
        default_factory=list,
        description="Collection of forensic evidence records associated with the incident",
    )

    model_config = ConfigDict(extra="ignore")
