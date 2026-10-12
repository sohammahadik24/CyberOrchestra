"""Aggregate read-only external intelligence for indicators in a normalized incident."""

from dataclasses import dataclass, field
from typing import Dict, List, Mapping, Tuple

from app.models.incident import Evidence, Incident, Indicator, IndicatorType
from app.services.abuseipdb_client import abuseipdb_client
from app.services.mitre_client import mitre_client
from app.services.nvd_client import nvd_client
from app.services.urlhaus_client import urlhaus_client


@dataclass
class ThreatIntelligenceCollection:
    """Successful standardized results and per-indicator retrieval errors."""

    indicators: List[Indicator] = field(default_factory=list)
    evidence: List[Evidence] = field(default_factory=list)
    failures: List[Dict[str, str]] = field(default_factory=list)


class ThreatIntelligenceService:
    """Route incident indicators to their corresponding intelligence providers.

    This service gathers source data only. It does not classify indicators or
    incidents as malicious or benign and does not invoke AI/LLM services.
    """

    def __init__(self, abuseipdb=None, urlhaus=None, nvd=None, mitre=None):
        self.clients = {
            IndicatorType.IP.value: abuseipdb or abuseipdb_client,
            IndicatorType.URL.value: urlhaus or urlhaus_client,
            IndicatorType.CVE.value: nvd or nvd_client,
            IndicatorType.MITRE_ATTACK.value: mitre or mitre_client,
        }
        self._lookup_methods = {
            IndicatorType.IP.value: "check_and_convert",
            IndicatorType.URL.value: "check_and_convert",
            IndicatorType.CVE.value: "get_cve_and_convert",
            IndicatorType.MITRE_ATTACK.value: "get_technique_and_convert",
        }

    def collect(self, incident: Incident) -> ThreatIntelligenceCollection:
        """Query available sources for supported incident indicators independently."""
        result = ThreatIntelligenceCollection()
        for source_type, client in self.clients.items():
            matching = [i for i in incident.indicators if i.indicator_type.lower() == source_type]
            # No request is made for a source absent from this incident.
            for indicator in matching:
                try:
                    method = getattr(client, self._lookup_methods[source_type])
                    if source_type == IndicatorType.IP.value:
                        lookup_result = method(indicator.value)
                    else:
                        lookup_result = method(indicator.value)
                    result.indicators.append(lookup_result.indicator)
                    result.evidence.append(lookup_result.evidence)
                except Exception as err:
                    result.failures.append({
                        "indicator_type": source_type,
                        "indicator": indicator.value,
                        "source": self._source_name(source_type),
                        "error": str(err),
                    })
        return result

    @staticmethod
    def _source_name(indicator_type: str) -> str:
        return {
            IndicatorType.IP.value: "AbuseIPDB",
            IndicatorType.URL.value: "URLhaus",
            IndicatorType.CVE.value: "NVD",
            IndicatorType.MITRE_ATTACK.value: "MITRE ATT&CK",
        }[indicator_type]


threat_intelligence_service = ThreatIntelligenceService()
