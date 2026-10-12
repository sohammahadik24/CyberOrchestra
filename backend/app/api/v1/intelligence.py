"""Threat intelligence endpoints for external reputation lookups."""

from fastapi import APIRouter, HTTPException, Query, status

from app.models.abuseipdb import IPReputationResult
from app.models.nvd import CVEIntelligenceResult
from app.models.mitre import MITREIntelligenceResult
from app.models.urlhaus import URLReputationResult
from app.services.abuseipdb_client import (
    AbuseIPDBAuthError,
    AbuseIPDBConfigError,
    AbuseIPDBConnectionError,
    AbuseIPDBError,
    AbuseIPDBRateLimitError,
    AbuseIPDBResponseError,
    abuseipdb_client,
)
from app.services.nvd_client import (
    NVDConnectionError,
    NVDError,
    NVDInvalidCVEError,
    NVDNotFoundError,
    NVDRateLimitError,
    NVDResponseError,
    nvd_client,
)
from app.services.mitre_client import (
    MITREConnectionError, MITREError, MITREInvalidTechniqueIDError,
    MITRENotFoundError, MITREResponseError, mitre_client,
)
from app.services.urlhaus_client import (
    URLhausAuthError,
    URLhausClient,
    URLhausConfigError,
    URLhausConnectionError,
    URLhausError,
    URLhausRateLimitError,
    URLhausResponseError,
    urlhaus_client,
)

router = APIRouter(prefix="/intelligence", tags=["Threat Intelligence"])


@router.get(
    "/ip/{ip_address}",
    response_model=IPReputationResult,
    status_code=status.HTTP_200_OK,
    summary="Query IP reputation intelligence from AbuseIPDB",
    description=(
        "Queries AbuseIPDB API v2 check endpoint for external reputation evidence, "
        "returning both the extracted reputation metrics and standardized CyberOrchestra "
        "Indicator and Evidence models. Does NOT make response or triage decisions."
    ),
)
def get_ip_reputation(
    ip_address: str,
    max_age_in_days: int = Query(
        default=30,
        ge=1,
        le=365,
        description="Maximum age in days of abuse reports to retrieve from AbuseIPDB",
    ),
) -> IPReputationResult:
    """Thin endpoint: Route -> AbuseIPDB Client -> Evidence Conversion -> Response."""
    try:
        result = abuseipdb_client.check_and_convert(
            ip_address=ip_address,
            max_age_in_days=max_age_in_days,
        )
        return result
    except ValueError as err:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid IP address parameter: {err}",
        ) from err
    except AbuseIPDBConfigError as err:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Intelligence source not configured: {err}",
        ) from err
    except AbuseIPDBAuthError as err:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Upstream AbuseIPDB authentication failed: {err}",
        ) from err
    except AbuseIPDBRateLimitError as err:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Upstream AbuseIPDB rate limit reached: {err}",
        ) from err
    except AbuseIPDBConnectionError as err:
        raise HTTPException(
            status_code=status.HTTP_504_GATEWAY_TIMEOUT,
            detail=f"Upstream AbuseIPDB connection failed: {err}",
        ) from err
    except AbuseIPDBResponseError as err:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Upstream AbuseIPDB error: {err}",
        ) from err
    except AbuseIPDBError as err:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Intelligence retrieval failure: {err}",
        ) from err


@router.get(
    "/url",
    response_model=URLReputationResult,
    status_code=status.HTTP_200_OK,
    summary="Query URL threat intelligence from URLhaus",
    description=(
        "Queries abuse.ch URLhaus API v1 for external URL threat intelligence, "
        "returning parsed URLhaus attributes and standardized CyberOrchestra "
        "Indicator and Evidence models. Does NOT make response or triage decisions."
    ),
)
def get_url_reputation(
    url: str = Query(
        ...,
        description="Target HTTP or HTTPS URL to check against URLhaus",
    ),
) -> URLReputationResult:
    """Thin endpoint: Route -> URLhaus Client -> Evidence Conversion -> Response."""
    try:
        result = urlhaus_client.check_and_convert(url=url)
        return result
    except ValueError as err:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid URL parameter: {err}",
        ) from err
    except URLhausConfigError as err:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Intelligence source not configured: {err}",
        ) from err
    except URLhausAuthError as err:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Upstream URLhaus authentication failed: {err}",
        ) from err
    except URLhausRateLimitError as err:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Upstream URLhaus rate limit reached: {err}",
        ) from err
    except URLhausConnectionError as err:
        raise HTTPException(
            status_code=status.HTTP_504_GATEWAY_TIMEOUT,
            detail=f"Upstream URLhaus connection failed: {err}",
        ) from err
    except URLhausResponseError as err:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Upstream URLhaus error: {err}",
        ) from err
    except URLhausError as err:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Intelligence retrieval failure: {err}",
        ) from err


@router.get(
    "/cve/{cve_id}",
    response_model=CVEIntelligenceResult,
    status_code=status.HTTP_200_OK,
    summary="Query CVE vulnerability intelligence from NVD CVE API 2.0",
    description=(
        "Queries the NIST National Vulnerability Database (NVD) CVE API 2.0 for external "
        "vulnerability intelligence on a specific CVE identifier, returning structured CVSS, "
        "CWE, affected product, and reference data alongside standardized CyberOrchestra "
        "Indicator and Evidence models. "
        "Does NOT determine whether any asset in an observed incident is exploitable. "
        "That determination is delegated to the future Vulnerability Assessment Agent."
    ),
)
def get_cve_intelligence(
    cve_id: str,
) -> CVEIntelligenceResult:
    """Thin endpoint: Route -> NVD Client -> Evidence Conversion -> Response."""
    try:
        result = nvd_client.get_cve_and_convert(cve_id=cve_id)
        return result
    except NVDInvalidCVEError as err:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid CVE identifier: {err}",
        ) from err
    except NVDNotFoundError as err:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"CVE not found in NVD: {err}",
        ) from err
    except NVDRateLimitError as err:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"NVD rate limit reached: {err}",
        ) from err
    except NVDConnectionError as err:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"NVD connection failed: {err}",
        ) from err
    except NVDResponseError as err:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Upstream NVD error: {err}",
        ) from err
    except NVDError as err:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"CVE intelligence retrieval failure: {err}",
        ) from err


@router.get(
    "/mitre/{technique_id}",
    response_model=MITREIntelligenceResult,
    status_code=status.HTTP_200_OK,
    summary="Query MITRE ATT&CK technique intelligence",
    description=(
        "Retrieves official MITRE ATT&CK STIX technique metadata as read-only external "
        "intelligence. A technique description is not evidence that an attack occurred."
    ),
)
def get_mitre_technique(technique_id: str) -> MITREIntelligenceResult:
    try:
        return mitre_client.get_technique_and_convert(technique_id)
    except MITREInvalidTechniqueIDError as err:
        raise HTTPException(status_code=400, detail=str(err)) from err
    except MITRENotFoundError as err:
        raise HTTPException(status_code=404, detail=str(err)) from err
    except MITREConnectionError as err:
        raise HTTPException(status_code=503, detail=str(err)) from err
    except MITREResponseError as err:
        raise HTTPException(status_code=502, detail=str(err)) from err
    except MITREError as err:
        raise HTTPException(status_code=500, detail=str(err)) from err


@router.get(
    "/feed",
    status_code=status.HTTP_200_OK,
    summary="Get aggregated live threat indicators collected from real incidents and lookups",
)
def get_threat_feed():
    from app.services.incident_repository import incident_repository
    records = incident_repository.get_all()

    items = []
    seen = set()

    for rec in records:
        for ind in rec.incident.indicators:
            key = f"{ind.indicator_type}:{ind.value}"
            if key in seen:
                continue
            seen.add(key)

            sev_map = {
                "critical": "Critical",
                "high": "High",
                "medium": "Medium",
                "low": "Low",
            }
            mapped_sev = sev_map.get((rec.incident.severity or "medium").lower(), "Medium")

            type_map = {
                "ip": "IP",
                "ipv4": "IP",
                "url": "URL",
                "cve": "CVE",
                "mitre": "MITRE",
                "mitre_attack": "MITRE",
                "file_hash": "Hash",
            }
            display_type = type_map.get(ind.indicator_type.lower(), "Other")

            confidence_pct = int(ind.confidence * 100) if ind.confidence is not None else 85

            items.append({
                "id": f"tf-{len(items) + 1:03d}",
                "indicator": ind.value,
                "type": display_type,
                "source": ind.source,
                "severity": mapped_sev,
                "confidence": confidence_pct,
                "firstSeen": rec.created_at.isoformat(),
                "tags": [rec.incident.incident_id, ind.indicator_type],
            })

    return items


@router.get(
    "/sources",
    status_code=status.HTTP_200_OK,
    summary="Get status and metadata for all integrated threat intelligence feeds",
)
def get_threat_sources():
    from app.core.config import settings

    has_abuse_key = bool(settings.ABUSEIPDB_API_KEY)
    has_urlhaus_key = bool(settings.URLHAUS_AUTH_KEY)
    has_nvd_key = bool(settings.NVD_API_KEY)

    return [
        {
            "name": "AbuseIPDB",
            "type": "IP Reputation",
            "status": "Live" if has_abuse_key else "Missing API Key",
            "operational": has_abuse_key,
            "endpoint": settings.ABUSEIPDB_API_URL,
            "rateLimit": "~1,000 req/day (Free tier)",
            "authRequired": True,
        },
        {
            "name": "URLhaus",
            "type": "URL Threat Intelligence",
            "status": "Live" if has_urlhaus_key else "Missing Auth Key",
            "operational": has_urlhaus_key,
            "endpoint": settings.URLHAUS_API_URL,
            "rateLimit": "Standard abuse.ch rate limit",
            "authRequired": True,
        },
        {
            "name": "NVD CVE API 2.0",
            "type": "Vulnerability Database",
            "status": "Live (Authenticated)" if has_nvd_key else "Live (Public Rate Limit)",
            "operational": True,
            "endpoint": settings.NVD_API_URL,
            "rateLimit": "~50 req/30s" if has_nvd_key else "~5 req/30s",
            "authRequired": False,
        },
        {
            "name": "MITRE ATT&CK",
            "type": "Technique Library",
            "status": "Live",
            "operational": True,
            "endpoint": "STIX 2.1 Knowledge Base",
            "rateLimit": "Local STIX (unlimited)",
            "authRequired": False,
        },
    ]

