"""AbuseIPDB reputation models and intelligence response schemas."""

from datetime import datetime
from typing import Any, Dict, Optional
from pydantic import BaseModel, ConfigDict, Field

from app.models.incident import Evidence, Indicator


class AbuseIPDBResponse(BaseModel):
    """Normalized internal representation of AbuseIPDB IP check response data.

    Only captures security-relevant attributes required by CyberOrchestra, preserving
    secondary details in metadata.
    """

    ip_address: str = Field(..., description="Observed IP address")
    ip_version: Optional[int] = Field(default=None, description="IP version (4 or 6)")
    abuse_confidence_score: int = Field(
        ...,
        ge=0,
        le=100,
        description="External reputation score from AbuseIPDB (0-100 scale)",
    )
    total_reports: int = Field(
        ...,
        ge=0,
        description="Total distinct abuse complaints recorded against this IP",
    )
    last_reported_at: Optional[datetime] = Field(
        default=None,
        description="Timestamp of most recent abuse report in UTC",
    )
    country_code: Optional[str] = Field(
        default=None,
        description="Two-letter ISO country code associated with the IP",
    )
    usage_type: Optional[str] = Field(
        default=None,
        description="Classified infrastructure role (e.g., Data Center, Commercial, ISP)",
    )
    is_whitelisted: Optional[bool] = Field(
        default=None,
        description="Whether the IP address is recognized on the AbuseIPDB whitelist",
    )
    source: str = Field(
        default="AbuseIPDB",
        description="External intelligence source name",
    )
    metadata: Dict[str, Any] = Field(
        default_factory=dict,
        description="Preserved contextual metadata (e.g. ISP, hostnames, domain, is_tor)",
    )

    model_config = ConfigDict(extra="ignore")


class IPReputationResult(BaseModel):
    """Standardized intelligence result encapsulating converted Indicator and Evidence."""

    ip_address: str = Field(..., description="Target IP address queried")
    reputation: AbuseIPDBResponse = Field(..., description="Extracted AbuseIPDB response fields")
    indicator: Indicator = Field(..., description="Standardized Indicator model")
    evidence: Evidence = Field(..., description="Standardized Evidence model")

    model_config = ConfigDict(extra="ignore")
