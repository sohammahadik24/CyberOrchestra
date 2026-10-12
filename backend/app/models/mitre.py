"""Structured results from the official MITRE ATT&CK STIX data."""

from typing import Any, Dict, List, Optional

from pydantic import BaseModel, ConfigDict, Field

from app.models.incident import Evidence, Indicator


class MITREReference(BaseModel):
    source_name: Optional[str] = None
    url: Optional[str] = None
    external_id: Optional[str] = None
    description: Optional[str] = None
    model_config = ConfigDict(extra="allow")


class MITRETechnique(BaseModel):
    technique_id: str
    name: str
    description: str = ""
    tactics: List[str] = Field(default_factory=list)
    platforms: List[str] = Field(default_factory=list)
    is_subtechnique: bool = False
    parent_technique_id: Optional[str] = None
    references: List[MITREReference] = Field(default_factory=list)
    source: str = "MITRE ATT&CK"
    provenance: str = "MITRE ATT&CK STIX 2.1"
    raw: Dict[str, Any] = Field(default_factory=dict)
    model_config = ConfigDict(extra="allow")


class MITREIntelligenceResult(BaseModel):
    technique: MITRETechnique
    indicator: Indicator
    evidence: Evidence
