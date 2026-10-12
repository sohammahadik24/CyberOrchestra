"""NVD CVE vulnerability intelligence models for CyberOrchestra.

Typed Pydantic models representing structured data from the NVD CVE API 2.0.
These models preserve all relevant NVD fields without inventing missing values.

IMPORTANT: NVD data is external vulnerability intelligence.
It does NOT determine whether a specific observed asset is exploitable.
That determination belongs to the future Vulnerability Assessment Agent.
"""

from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, ConfigDict, Field

from app.models.incident import Evidence, Indicator


# ---------------------------------------------------------------------------
# CVSS Metric Models
# ---------------------------------------------------------------------------

class CVSSMetricV2(BaseModel):
    """CVSS v2 base score and vector information from NVD."""

    source: Optional[str] = Field(default=None, description="NVD or vendor source of this metric")
    type: Optional[str] = Field(default=None, description="Primary or Secondary metric type")
    cvss_version: str = Field(default="2.0", description="CVSS version (always '2.0' here)")
    base_score: Optional[float] = Field(default=None, description="CVSS v2 base score (0.0–10.0)")
    base_severity: Optional[str] = Field(default=None, description="Severity label derived from base score")
    vector_string: Optional[str] = Field(default=None, description="CVSS v2 vector string (AV:N/AC:L/...)")
    exploitability_score: Optional[float] = Field(default=None, description="CVSS v2 exploitability sub-score")
    impact_score: Optional[float] = Field(default=None, description="CVSS v2 impact sub-score")

    model_config = ConfigDict(extra="ignore")


class CVSSMetricV3(BaseModel):
    """CVSS v3.x base score and vector information from NVD."""

    source: Optional[str] = Field(default=None, description="NVD or vendor source of this metric")
    type: Optional[str] = Field(default=None, description="Primary or Secondary metric type")
    cvss_version: Optional[str] = Field(default=None, description="CVSS version (e.g. '3.1' or '3.0')")
    base_score: Optional[float] = Field(default=None, description="CVSS v3 base score (0.0–10.0)")
    base_severity: Optional[str] = Field(default=None, description="Severity label (LOW/MEDIUM/HIGH/CRITICAL)")
    vector_string: Optional[str] = Field(default=None, description="CVSS v3 vector string (CVSS:3.1/AV:N/...)")
    exploitability_score: Optional[float] = Field(default=None, description="CVSS v3 exploitability sub-score")
    impact_score: Optional[float] = Field(default=None, description="CVSS v3 impact sub-score")
    attack_vector: Optional[str] = Field(default=None, description="Attack vector (NETWORK, ADJACENT, LOCAL, PHYSICAL)")
    attack_complexity: Optional[str] = Field(default=None, description="Attack complexity (LOW, HIGH)")
    privileges_required: Optional[str] = Field(default=None, description="Privileges required (NONE, LOW, HIGH)")
    user_interaction: Optional[str] = Field(default=None, description="User interaction required (NONE, REQUIRED)")
    scope: Optional[str] = Field(default=None, description="Scope changed or unchanged")
    confidentiality_impact: Optional[str] = Field(default=None, description="Confidentiality impact")
    integrity_impact: Optional[str] = Field(default=None, description="Integrity impact")
    availability_impact: Optional[str] = Field(default=None, description="Availability impact")

    model_config = ConfigDict(extra="ignore")


class CVSSMetricV4(BaseModel):
    """CVSS v4.0 base score and vector information from NVD."""

    source: Optional[str] = Field(default=None, description="NVD or vendor source of this metric")
    type: Optional[str] = Field(default=None, description="Primary or Secondary metric type")
    cvss_version: Optional[str] = Field(default=None, description="CVSS version (e.g. '4.0')")
    base_score: Optional[float] = Field(default=None, description="CVSS v4 base score (0.0–10.0)")
    base_severity: Optional[str] = Field(default=None, description="Severity label")
    vector_string: Optional[str] = Field(default=None, description="CVSS v4 vector string")

    model_config = ConfigDict(extra="ignore")


# ---------------------------------------------------------------------------
# CWE Model
# ---------------------------------------------------------------------------

class CWEEntry(BaseModel):
    """A single CWE (Common Weakness Enumeration) entry associated with a CVE."""

    cwe_id: Optional[str] = Field(default=None, description="CWE identifier (e.g., 'CWE-79')")
    description: Optional[str] = Field(default=None, description="Human-readable weakness description")
    source: Optional[str] = Field(default=None, description="Attribution source for the CWE mapping")

    model_config = ConfigDict(extra="ignore")


# ---------------------------------------------------------------------------
# Reference Model
# ---------------------------------------------------------------------------

class CVEReference(BaseModel):
    """An external reference or advisory link associated with a CVE."""

    url: Optional[str] = Field(default=None, description="Reference URL")
    source: Optional[str] = Field(default=None, description="Organization providing the reference")
    tags: List[str] = Field(default_factory=list, description="Reference classification tags")

    model_config = ConfigDict(extra="ignore")


# ---------------------------------------------------------------------------
# Affected Product / CPE Configuration
# ---------------------------------------------------------------------------

class AffectedProduct(BaseModel):
    """Simplified representation of an affected product/configuration entry."""

    cpe_name: Optional[str] = Field(default=None, description="CPE 2.3 formatted name")
    vendor: Optional[str] = Field(default=None, description="Vendor name")
    product: Optional[str] = Field(default=None, description="Product name")
    version_start_including: Optional[str] = Field(default=None, description="Inclusive start version")
    version_end_including: Optional[str] = Field(default=None, description="Inclusive end version")
    version_start_excluding: Optional[str] = Field(default=None, description="Exclusive start version")
    version_end_excluding: Optional[str] = Field(default=None, description="Exclusive end version")
    vulnerable: Optional[bool] = Field(default=None, description="Whether this CPE match is vulnerable")

    model_config = ConfigDict(extra="ignore")


# ---------------------------------------------------------------------------
# Core NVD CVE Response Model
# ---------------------------------------------------------------------------

class NVDCVEResponse(BaseModel):
    """Normalized internal representation of an NVD CVE API 2.0 response for a single CVE.

    Preserves all security-relevant fields including CVSS metrics (v2, v3, v4),
    CWE information, affected product configurations, references, and timestamps.

    IMPORTANT: This model does NOT include exploitability determinations.
    Whether a specific asset is affected by this CVE is determined by the
    future Vulnerability Assessment Agent through correlation with incident evidence.
    """

    cve_id: str = Field(..., description="CVE identifier (e.g., 'CVE-2024-12345')")
    source_identifier: Optional[str] = Field(
        default=None,
        description="Authoritative CNA (CVE Numbering Authority) that assigned the CVE",
    )
    published: Optional[datetime] = Field(
        default=None,
        description="Date the CVE was published to NVD (UTC)",
    )
    last_modified: Optional[datetime] = Field(
        default=None,
        description="Date the CVE record was last modified in NVD (UTC)",
    )
    vuln_status: Optional[str] = Field(
        default=None,
        description="NVD analysis status (e.g., 'Analyzed', 'Awaiting Analysis', 'Modified')",
    )
    description: Optional[str] = Field(
        default=None,
        description="Primary English language CVE vulnerability description from NVD",
    )
    cvss_v2: Optional[CVSSMetricV2] = Field(
        default=None,
        description="CVSS v2 base metric (primary NVD metric if present)",
    )
    cvss_v3: Optional[CVSSMetricV3] = Field(
        default=None,
        description="CVSS v3.x base metric (primary NVD metric if present)",
    )
    cvss_v4: Optional[CVSSMetricV4] = Field(
        default=None,
        description="CVSS v4.0 base metric (primary NVD metric if present)",
    )
    cwes: List[CWEEntry] = Field(
        default_factory=list,
        description="Associated CWE weakness entries",
    )
    references: List[CVEReference] = Field(
        default_factory=list,
        description="External references, advisories, and patches associated with the CVE",
    )
    affected_products: List[AffectedProduct] = Field(
        default_factory=list,
        description="Simplified list of vulnerable CPE entries from NVD configuration data",
    )
    source: str = Field(
        default="NVD",
        description="External intelligence source name (always 'NVD')",
    )
    nvd_url: Optional[str] = Field(
        default=None,
        description="Canonical NVD web page URL for the CVE",
    )
    metadata: Dict[str, Any] = Field(
        default_factory=dict,
        description="Preserved raw NVD fields not mapped to structured attributes",
    )

    model_config = ConfigDict(extra="ignore")


# ---------------------------------------------------------------------------
# Result Wrapper
# ---------------------------------------------------------------------------

class CVEIntelligenceResult(BaseModel):
    """Standardized CyberOrchestra intelligence result for an NVD CVE lookup.

    Wraps the raw NVD response with standardized CyberOrchestra Indicator and Evidence.
    """

    cve_id: str = Field(..., description="Queried CVE identifier")
    cve_data: NVDCVEResponse = Field(..., description="Structured NVD CVE response data")
    indicator: Indicator = Field(..., description="Standardized CyberOrchestra Indicator model")
    evidence: Evidence = Field(..., description="Standardized CyberOrchestra Evidence model")

    model_config = ConfigDict(extra="ignore")
