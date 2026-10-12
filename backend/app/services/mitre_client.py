"""Read-only client for the official MITRE ATT&CK Enterprise STIX 2.1 bundle."""

import re
from typing import Any, Dict, List, Optional, Tuple

import httpx

from app.models.incident import Evidence, EvidenceType, Indicator, IndicatorType
from app.models.mitre import MITREIntelligenceResult, MITREReference, MITRETechnique

MITRE_STIX_URL = "https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json"
_TECHNIQUE_ID = re.compile(r"^T\d{4}(?:\.\d{3})?$")


class MITREError(Exception):
    """Base error for MITRE ATT&CK lookup failures."""


class MITREInvalidTechniqueIDError(MITREError):
    pass


class MITRENotFoundError(MITREError):
    pass


class MITREConnectionError(MITREError):
    pass


class MITREResponseError(MITREError):
    pass


def validate_technique_id(technique_id: str) -> str:
    cleaned = str(technique_id).strip().upper()
    if not _TECHNIQUE_ID.fullmatch(cleaned):
        raise MITREInvalidTechniqueIDError(
            f"Invalid ATT&CK technique ID {technique_id!r}; expected T#### or T####.###."
        )
    return cleaned


class MITREClient:
    """Fetch and standardize ATT&CK technique objects from official MITRE STIX."""

    def __init__(self, base_url: str = MITRE_STIX_URL, timeout: float = 20.0):
        self.base_url = base_url
        self.timeout = timeout

    def _load_bundle(self, transport: Optional[httpx.BaseTransport] = None) -> Dict[str, Any]:
        try:
            with httpx.Client(timeout=self.timeout, transport=transport) as client:
                response = client.get(self.base_url, headers={"Accept": "application/json"})
        except httpx.RequestError as err:
            raise MITREConnectionError(f"Unable to retrieve MITRE ATT&CK STIX data: {err}") from err
        if response.status_code != 200:
            raise MITREResponseError(f"MITRE ATT&CK source returned HTTP {response.status_code}.")
        try:
            bundle = response.json()
        except Exception as err:
            raise MITREResponseError(f"Malformed JSON from MITRE ATT&CK source: {err}") from err
        if not isinstance(bundle, dict) or not isinstance(bundle.get("objects"), list):
            raise MITREResponseError("MITRE ATT&CK response must be a STIX bundle with an objects list.")
        return bundle

    def get_technique(
        self, technique_id: str, transport: Optional[httpx.BaseTransport] = None
    ) -> MITRETechnique:
        requested = validate_technique_id(technique_id)
        bundle = self._load_bundle(transport)
        objects = bundle["objects"]
        if not all(isinstance(obj, dict) for obj in objects):
            raise MITREResponseError("MITRE ATT&CK STIX objects list contains malformed entries.")

        match = None
        for obj in objects:
            if obj.get("type") != "attack-pattern" or obj.get("revoked") or obj.get("x_mitre_deprecated"):
                continue
            ids = [ref.get("external_id", "").upper() for ref in obj.get("external_references", []) if isinstance(ref, dict)]
            if requested in ids:
                match = obj
                break
        if match is None:
            raise MITRENotFoundError(f"ATT&CK technique {requested} was not found.")
        refs = match.get("external_references", [])
        if not isinstance(refs, list):
            raise MITREResponseError("Technique external_references is malformed.")
        refs = [r for r in refs if isinstance(r, dict)]
        attck_ref = next((r for r in refs if r.get("external_id", "").upper() == requested), {})
        tactics = [phase["phase_name"] for phase in match.get("kill_chain_phases", [])
                   if isinstance(phase, dict) and phase.get("kill_chain_name") == "mitre-attack" and phase.get("phase_name")]
        is_sub = bool(match.get("x_mitre_is_subtechnique", False))
        parent_id = requested.split(".", 1)[0] if is_sub else None
        return MITRETechnique(
            technique_id=requested,
            name=match.get("name", ""),
            description=match.get("description", ""),
            tactics=tactics,
            platforms=match.get("x_mitre_platforms", []) or [],
            is_subtechnique=is_sub,
            parent_technique_id=parent_id,
            references=[MITREReference(**r) for r in refs],
            raw=match,
            metadata_source_id=match.get("id"),
            url=attck_ref.get("url"),
        )

    def convert_to_standardized_evidence(self, technique: MITRETechnique) -> Tuple[Indicator, Evidence]:
        metadata = {
            "technique_id": technique.technique_id,
            "technique_name": technique.name,
            "description": technique.description,
            "tactics": technique.tactics,
            "platforms": technique.platforms,
            "is_subtechnique": technique.is_subtechnique,
            "parent_technique_id": technique.parent_technique_id,
            "references": [ref.model_dump(exclude_none=True) for ref in technique.references],
            "provenance": technique.provenance,
            "raw": technique.raw,
        }
        indicator = Indicator(indicator_type=IndicatorType.MITRE_ATTACK.value,
                              value=technique.technique_id, source=technique.source,
                              confidence=None, metadata=metadata)
        evidence = Evidence(
            evidence_id=f"EVID-MITRE-{technique.technique_id}",
            evidence_type=EvidenceType.THREAT_INTEL_FEED.value,
            source=technique.source,
            description=f"MITRE ATT&CK technique intelligence for {technique.technique_id} ({technique.name}): {technique.description}",
            raw_reference=next((r.url for r in technique.references if r.external_id == technique.technique_id), None),
            confidence=None,
            metadata={**metadata, "source": technique.source},
        )
        return indicator, evidence

    def get_technique_and_convert(self, technique_id: str, transport: Optional[httpx.BaseTransport] = None) -> MITREIntelligenceResult:
        technique = self.get_technique(technique_id, transport=transport)
        indicator, evidence = self.convert_to_standardized_evidence(technique)
        return MITREIntelligenceResult(technique=technique, indicator=indicator, evidence=evidence)


mitre_client = MITREClient()
