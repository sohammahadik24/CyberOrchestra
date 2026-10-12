"""URLhaus reputation models and intelligence response schemas."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field

from app.models.incident import Evidence, Indicator


class URLhausResponse(BaseModel):
    """Normalized internal representation of URLhaus API v1 query response data.

    Captures security-relevant attributes from URLhaus (e.g. query_status, threat,
    url_status, host, reporter, tags, payload references, and identifiers).
    """

    query_status: str = Field(
        ...,
        description="URLhaus query status code (e.g., 'ok', 'no_results', 'invalid_url')",
    )
    url: str = Field(..., description="The queried URL string")
    urlhaus_id: Optional[str] = Field(
        default=None,
        description="Unique URLhaus internal database identifier",
    )
    urlhaus_reference: Optional[str] = Field(
        default=None,
        description="Web portal reference URI for the URLhaus entry",
    )
    url_status: Optional[str] = Field(
        default=None,
        description="Online availability of the URL (e.g., 'online', 'offline')",
    )
    host: Optional[str] = Field(
        default=None,
        description="Host or domain associated with the URL",
    )
    date_added: Optional[str] = Field(
        default=None,
        description="Timestamp string when the entry was first added to URLhaus (UTC)",
    )
    threat: Optional[str] = Field(
        default=None,
        description="Classified threat category (e.g., 'malware_download')",
    )
    reporter: Optional[str] = Field(
        default=None,
        description="Community reporter or source attribution",
    )
    tags: List[str] = Field(
        default_factory=list,
        description="Associated threat tags, malware families, or file extensions",
    )
    payloads: List[Dict[str, Any]] = Field(
        default_factory=list,
        description="Payload signatures and file hash references if returned",
    )
    blacklists: Dict[str, Any] = Field(
        default_factory=dict,
        description="Third-party blacklist status (e.g. Spamhaus DBL, SURBL)",
    )
    source: str = Field(
        default="URLhaus",
        description="External intelligence source name",
    )
    metadata: Dict[str, Any] = Field(
        default_factory=dict,
        description="Preserved raw contextual metadata and unmapped attributes",
    )

    model_config = ConfigDict(extra="ignore")


class URLReputationResult(BaseModel):
    """Standardized intelligence result encapsulating converted Indicator and Evidence."""

    url: str = Field(..., description="Target URL queried")
    reputation: URLhausResponse = Field(..., description="Extracted URLhaus response fields")
    indicator: Indicator = Field(..., description="Standardized Indicator model")
    evidence: Evidence = Field(..., description="Standardized Evidence model")

    model_config = ConfigDict(extra="ignore")
