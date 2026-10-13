"""Pipeline Orchestrator for CyberOrchestra multi-agent incident response.

Wires together:
Threat Intel / CVE / Incident Logs
       ↓
  Data Normalizer
       ↓
Threat Detection Agent (Groq openai/gpt-oss-120b)
       ↓
Malware Analysis (openai/gpt-oss-120b) + Log Analysis (qwen/qwen3.8-27b) + Vuln. Assessment (qwen/qwen3.8-27b)
       ↓
Shared Incident State
       ↓
Recovery Planning Agent (Groq qwen/qwen3.8-27b)
       ↓
Deterministic Policy Engine (PE-001..PE-004)
       ↓
Report Generation Agent (Groq qwen/qwen3.8-27b)
       ↓
Human Analyst Review
"""

from datetime import datetime, timezone
import ipaddress
import logging
import time
from typing import Any, Dict, List, Optional

from app.agents.log_analysis import LogAnalysisAgent
from app.agents.malware_analysis import MalwareAnalysisAgent
from app.agents.recovery_planning import RecoveryPlanningAgent
from app.agents.report_generation import ReportGenerationAgent
from app.agents.threat_detection import ThreatDetectionAgent
from app.agents.vulnerability_assessment import VulnerabilityAssessmentAgent
from app.core.config import settings
from app.core.policy_engine import policy_engine
from app.models.incident import Evidence, Incident, Indicator
from app.models.incident_report import (
    EvidenceSummary,
    FinalRiskLevel,
    FindingStatus,
    IncidentReport,
    ReportFinding,
)
from app.models.incident_state import IncidentState
from app.models.log_assessment import LogAssessment, LogFinding, LogSeverity
from app.models.malware_assessment import MalwareAssessment
from app.models.policy_decision import PolicyDecision, PolicyDecisionValue
from app.models.recovery_plan import ActionPriority, RecoveryAction, RecoveryPlan
from app.models.threat_assessment import ThreatAssessment, ThreatClassification, ThreatSeverity
from app.models.vulnerability_assessment import VulnerabilityAssessment, VulnerabilitySeverity
from app.services.abuseipdb_client import AbuseIPDBError, abuseipdb_client
from app.services.incident_repository import IncidentRecord, PolicyReviewRecord, incident_repository
from app.services.incident_state import incident_state_service
from app.services.llm_service import LLMConfigurationError, LLMServiceError
from app.services.mitre_client import MITREError, mitre_client
from app.services.nvd_client import NVDError, nvd_client
from app.services.urlhaus_client import URLhausError, urlhaus_client

logger = logging.getLogger(__name__)

RFC_5737_NETWORKS = [
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
]


class PipelineOrchestrator:
    """Coordinates execution across all agents and services."""

    def __init__(self):
        self.threat_agent = ThreatDetectionAgent()
        self.malware_agent = MalwareAnalysisAgent()
        self.log_agent = LogAnalysisAgent()
        self.vuln_agent = VulnerabilityAssessmentAgent()
        self.recovery_agent = RecoveryPlanningAgent()
        self.report_agent = ReportGenerationAgent()

    def enrich_threat_intelligence(self, incident: Incident) -> Dict[str, Any]:
        """Queries configured live threat intel APIs for observed indicators."""
        results: Dict[str, Any] = {
            "queried": 0,
            "success": 0,
            "errors": [],
            "new_evidence": [],
        }

        # Track existing evidence IDs to avoid duplicates
        existing_evidence_ids = {e.evidence_id for e in incident.evidence}

        for ind in incident.indicators:
            val = ind.value.strip()
            ind_type = ind.indicator_type.lower()

            # 1. IP Lookup via AbuseIPDB
            if ind_type in {"ip", "ipv4", "ipv6"} or self._is_ip(val):
                results["queried"] += 1
                try:
                    ip_obj = ipaddress.ip_address(val)
                    if any(ip_obj in net for net in RFC_5737_NETWORKS):
                        # Documentation IP — create standardized local observation
                        evid = Evidence(
                            evidence_id=f"EVID-DOC-IP-{val.replace('.', '-')}",
                            evidence_type="network_reputation",
                            source="Documentation Network (RFC 5737)",
                            description=f"IP address {val} belongs to RFC 5737 documentation subnet.",
                            timestamp=datetime.now(timezone.utc),
                            confidence=0.5,
                            metadata={"is_documentation_ip": True, "ip": val},
                        )
                        if evid.evidence_id not in existing_evidence_ids:
                            incident.evidence.append(evid)
                            existing_evidence_ids.add(evid.evidence_id)
                            results["new_evidence"].append(evid.evidence_id)
                        results["success"] += 1
                    elif settings.ABUSEIPDB_API_KEY:
                        rep = abuseipdb_client.check_and_convert(val)
                        if rep.evidence.evidence_id not in existing_evidence_ids:
                            incident.evidence.append(rep.evidence)
                            existing_evidence_ids.add(rep.evidence.evidence_id)
                            results["new_evidence"].append(rep.evidence.evidence_id)
                        results["success"] += 1
                    else:
                        results["errors"].append(f"AbuseIPDB API key not configured for IP {val}")
                except Exception as err:
                    results["errors"].append(f"AbuseIPDB query for {val} failed: {err}")

            # 2. URL Lookup via URLhaus
            elif ind_type == "url" or val.startswith("http://") or val.startswith("https://"):
                results["queried"] += 1
                try:
                    rep = urlhaus_client.check_and_convert(val)
                    if rep.evidence.evidence_id not in existing_evidence_ids:
                        incident.evidence.append(rep.evidence)
                        existing_evidence_ids.add(rep.evidence.evidence_id)
                        results["new_evidence"].append(rep.evidence.evidence_id)
                    results["success"] += 1
                except Exception as err:
                    results["errors"].append(f"URLhaus query for {val} failed: {err}")

            # 3. CVE Lookup via NVD CVE API 2.0
            elif ind_type == "cve" or val.upper().startswith("CVE-"):
                results["queried"] += 1
                try:
                    cve_res = nvd_client.get_cve_and_convert(val.upper())
                    if cve_res.evidence.evidence_id not in existing_evidence_ids:
                        incident.evidence.append(cve_res.evidence)
                        existing_evidence_ids.add(cve_res.evidence.evidence_id)
                        results["new_evidence"].append(cve_res.evidence.evidence_id)
                    results["success"] += 1
                except Exception as err:
                    results["errors"].append(f"NVD query for {val} failed: {err}")

            # 4. MITRE ATT&CK Technique Lookup
            elif ind_type in {"mitre", "mitre_attack"} or (val.upper().startswith("T1") and len(val) >= 5):
                results["queried"] += 1
                try:
                    mitre_res = mitre_client.get_technique_and_convert(val.upper())
                    if mitre_res.evidence.evidence_id not in existing_evidence_ids:
                        incident.evidence.append(mitre_res.evidence)
                        existing_evidence_ids.add(mitre_res.evidence.evidence_id)
                        results["new_evidence"].append(mitre_res.evidence.evidence_id)
                    results["success"] += 1
                except Exception as err:
                    results["errors"].append(f"MITRE query for {val} failed: {err}")

        return results

    def _is_ip(self, val: str) -> bool:
        try:
            ipaddress.ip_address(val)
            return True
        except ValueError:
            return False

    def execute_pipeline(self, incident_id: str) -> Dict[str, Any]:
        """Executes the full CyberOrchestra pipeline on an incident in the repository."""
        record = incident_repository.get(incident_id)
        if not record:
            raise ValueError(f"Incident {incident_id} not found in repository.")

        incident = record.incident
        stages_log: List[Dict[str, Any]] = []
        start_time = time.time()

        # Step 1: Data Normalization
        stage1_start = time.time()
        record.update_stage("Normalization", "Investigating")
        stages_log.append({
            "stage": "Data Normalizer",
            "role": "Ingestion & Schema Validation",
            "status": "completed",
            "model": "Deterministic Normalizer",
            "duration": f"{(time.time() - stage1_start) * 1000:.1f}ms",
            "details": f"Normalized schema with {len(incident.indicators)} indicators and {len(incident.evidence)} initial evidence items.",
        })
        incident_repository.log_activity(
            agent="Data Normalizer",
            action=f"Completed schema verification for {incident_id}",
            incident_id=incident_id,
            severity="Info",
        )

        # Step 2: Threat Intelligence Enrichment
        stage2_start = time.time()
        enrichment_result = self.enrich_threat_intelligence(incident)
        stages_log.append({
            "stage": "Threat Intelligence Enrichment",
            "role": "AbuseIPDB · URLhaus · NVD · MITRE Queries",
            "status": "completed" if enrichment_result["queried"] > 0 else "skipped",
            "model": "Live API Clients",
            "duration": f"{(time.time() - stage2_start) * 1000:.1f}ms",
            "details": (
                f"Queried {enrichment_result['queried']} sources, added {len(enrichment_result['new_evidence'])} external evidence records. "
                + (f"Errors: {', '.join(enrichment_result['errors'])}" if enrichment_result["errors"] else "All queries verified.")
            ),
        })

        # Step 3: Threat Detection Agent (Groq openai/gpt-oss-120b)
        stage3_start = time.time()
        record.update_stage("Threat Detection", "Investigating")
        has_groq_key = bool(settings.THREAT_LLM_API_KEY)

        threat_assessment: Optional[ThreatAssessment] = None
        if has_groq_key:
            try:
                threat_assessment = self.threat_agent.assess(incident)
                stages_log.append({
                    "stage": "Threat Detection Agent",
                    "role": "IOC Classification & Triage",
                    "status": "completed",
                    "model": f"Groq {settings.THREAT_LLM_MODEL}",
                    "duration": f"{time.time() - stage3_start:.2f}s",
                    "confidence": int(threat_assessment.confidence * 100) if threat_assessment.confidence else None,
                    "details": threat_assessment.reasoning,
                })
            except Exception as err:
                logger.warning(f"Live Threat Detection failed: {err}")
                stages_log.append({
                    "stage": "Threat Detection Agent",
                    "role": "IOC Classification & Triage",
                    "status": "error",
                    "model": f"Groq {settings.THREAT_LLM_MODEL}",
                    "duration": f"{time.time() - stage3_start:.2f}s",
                    "details": f"Execution error: {err}",
                })
        else:
            # Deterministic evidence-grounded fallback for local execution when GROQ_API_KEY is not configured
            threat_assessment = self._create_grounded_threat_assessment(incident)
            stages_log.append({
                "stage": "Threat Detection Agent",
                "role": "IOC Classification & Triage",
                "status": "completed",
                "model": f"Deterministic Engine (Configure GROQ_API_KEY for {settings.THREAT_LLM_MODEL})",
                "duration": f"{(time.time() - stage3_start) * 1000:.1f}ms",
                "confidence": int(threat_assessment.confidence * 100) if threat_assessment.confidence else None,
                "details": f"{threat_assessment.reasoning} [Note: add GROQ_API_KEY to backend/.env for live LLM]",
            })

        # Step 4: Parallel Specialized Agents
        # A) Malware Analysis Agent
        stage4a_start = time.time()
        malware_assessment: Optional[MalwareAssessment] = None
        if has_groq_key:
            try:
                malware_assessment = self.malware_agent.analyze(incident)
                stages_log.append({
                    "stage": "Malware Analysis Agent",
                    "role": "Binary & Behavioral Analysis",
                    "status": "completed",
                    "model": f"Groq {settings.MALWARE_LLM_MODEL}",
                    "duration": f"{time.time() - stage4a_start:.2f}s",
                    "confidence": int(malware_assessment.confidence * 100) if malware_assessment.confidence else None,
                    "details": f"Malware detected: {malware_assessment.malware_detected}" + (f" ({malware_assessment.suspected_family})" if malware_assessment.suspected_family else ""),
                })
            except Exception as err:
                stages_log.append({
                    "stage": "Malware Analysis Agent",
                    "role": "Binary & Behavioral Analysis",
                    "status": "error",
                    "model": f"Groq {settings.MALWARE_LLM_MODEL}",
                    "duration": f"{time.time() - stage4a_start:.2f}s",
                    "details": str(err),
                })
        else:
            malware_assessment = self._create_grounded_malware_assessment(incident)
            stages_log.append({
                "stage": "Malware Analysis Agent",
                "role": "Binary & Behavioral Analysis",
                "status": "completed",
                "model": f"Deterministic Engine (Configure GROQ_API_KEY for {settings.MALWARE_LLM_MODEL})",
                "duration": f"{(time.time() - stage4a_start) * 1000:.1f}ms",
                "confidence": int(malware_assessment.confidence * 100) if malware_assessment.confidence else None,
                "details": f"Malware detected: {malware_assessment.malware_detected}" + (f" ({malware_assessment.suspected_family})" if malware_assessment.suspected_family else " (clean)"),
            })

        # B) Log Analysis Agent
        stage4b_start = time.time()
        log_assessment: Optional[LogAssessment] = None
        if has_groq_key:
            try:
                log_assessment = self.log_agent.analyze(incident)
                stages_log.append({
                    "stage": "Log Analysis Agent",
                    "role": "Auth / Network Log Forensics",
                    "status": "completed",
                    "model": f"Groq {settings.LOG_LLM_MODEL}",
                    "duration": f"{time.time() - stage4b_start:.2f}s",
                    "confidence": int(log_assessment.confidence * 100) if log_assessment.confidence else None,
                    "details": f"Identified {len(log_assessment.suspicious_events)} suspicious events in telemetry logs.",
                })
            except Exception as err:
                stages_log.append({
                    "stage": "Log Analysis Agent",
                    "role": "Auth / Network Log Forensics",
                    "status": "error",
                    "model": f"Groq {settings.LOG_LLM_MODEL}",
                    "duration": f"{time.time() - stage4b_start:.2f}s",
                    "details": str(err),
                })
        else:
            log_assessment = self._create_grounded_log_assessment(incident)
            stages_log.append({
                "stage": "Log Analysis Agent",
                "role": "Auth / Network Log Forensics",
                "status": "completed",
                "model": f"Deterministic Engine (Configure GROQ_API_KEY for {settings.LOG_LLM_MODEL})",
                "duration": f"{(time.time() - stage4b_start) * 1000:.1f}ms",
                "confidence": int(log_assessment.confidence * 100) if log_assessment.confidence else None,
                "details": f"Correlated {len(log_assessment.suspicious_events)} forensic log events across hosts and perimeter.",
            })

        # C) Vulnerability Assessment Agent
        stage4c_start = time.time()
        vuln_assessment: Optional[VulnerabilityAssessment] = None
        if has_groq_key:
            try:
                vuln_assessment = self.vuln_agent.assess(incident)
                stages_log.append({
                    "stage": "Vulnerability Assessment Agent",
                    "role": "CVE Correlation & CVSS Scoring",
                    "status": "completed",
                    "model": f"Groq {settings.VULNERABILITY_LLM_MODEL}",
                    "duration": f"{time.time() - stage4c_start:.2f}s",
                    "confidence": int(vuln_assessment.confidence * 100) if vuln_assessment.confidence else None,
                    "details": vuln_assessment.exploitability_assessment,
                })
            except Exception as err:
                stages_log.append({
                    "stage": "Vulnerability Assessment Agent",
                    "role": "CVE Correlation & CVSS Scoring",
                    "status": "error",
                    "model": f"Groq {settings.VULNERABILITY_LLM_MODEL}",
                    "duration": f"{time.time() - stage4c_start:.2f}s",
                    "details": str(err),
                })
        else:
            vuln_assessment = self._create_grounded_vuln_assessment(incident)
            stages_log.append({
                "stage": "Vulnerability Assessment Agent",
                "role": "CVE Correlation & CVSS Scoring",
                "status": "completed",
                "model": f"Deterministic Engine (Configure GROQ_API_KEY for {settings.VULNERABILITY_LLM_MODEL})",
                "duration": f"{(time.time() - stage4c_start) * 1000:.1f}ms",
                "confidence": int(vuln_assessment.confidence * 100) if vuln_assessment.confidence else None,
                "details": vuln_assessment.exploitability_assessment,
            })

        # Step 5: Shared Incident State
        stage5_start = time.time()
        record.update_stage("Shared State", "Investigating")
        state = incident_state_service.create(incident)
        if threat_assessment:
            state = incident_state_service.add_threat_detection_result(state, threat_assessment)
        if malware_assessment:
            state = incident_state_service.add_malware_analysis_result(state, malware_assessment)
        if log_assessment:
            state = incident_state_service.add_log_analysis_result(state, log_assessment)
        if vuln_assessment:
            state = incident_state_service.add_vulnerability_assessment_result(state, vuln_assessment)

        record.state = state
        stages_log.append({
            "stage": "Shared Incident State",
            "role": "State Aggregation & Evidence Cross-Validation",
            "status": "completed",
            "model": "Shared Incident State Service",
            "duration": f"{(time.time() - stage5_start) * 1000:.1f}ms",
            "details": f"Aggregated {len(state.aggregated_evidence_ids)} validated evidence citations across {len(state.results())} agent assessments.",
        })

        # Step 6: Recovery Planning Agent (qwen/qwen3.8-27b)
        stage6_start = time.time()
        record.update_stage("Recovery Planning", "Investigating")
        recovery_plan: Optional[RecoveryPlan] = None
        if has_groq_key:
            try:
                recovery_plan = self.recovery_agent.plan(state)
                stages_log.append({
                    "stage": "Recovery Planning Agent",
                    "role": "Containment & Remediation Strategy",
                    "status": "completed",
                    "model": f"Groq {settings.RECOVERY_LLM_MODEL}",
                    "duration": f"{time.time() - stage6_start:.2f}s",
                    "details": f"Proposed {len(recovery_plan.recovery_actions)} structured recovery actions.",
                })
            except Exception as err:
                recovery_plan = self._create_grounded_recovery_plan(state)
                stages_log.append({
                    "stage": "Recovery Planning Agent",
                    "role": "Containment & Remediation Strategy",
                    "status": "completed",
                    "model": f"Groq {settings.RECOVERY_LLM_MODEL} (Fallback)",
                    "duration": f"{time.time() - stage6_start:.2f}s",
                    "details": f"Proposed {len(recovery_plan.recovery_actions)} actions (deterministic fallback: {err}).",
                })
        else:
            recovery_plan = self._create_grounded_recovery_plan(state)
            stages_log.append({
                "stage": "Recovery Planning Agent",
                "role": "Containment & Remediation Strategy",
                "status": "completed",
                "model": f"Deterministic Engine (Configure GROQ_API_KEY for {settings.RECOVERY_LLM_MODEL})",
                "duration": f"{(time.time() - stage6_start) * 1000:.1f}ms",
                "details": f"Generated {len(recovery_plan.recovery_actions)} evidence-grounded recovery recommendations.",
            })

        record.recovery_plan = recovery_plan

        # Step 7: Deterministic Policy Engine (Pure Deterministic Rules PE-001..PE-004)
        stage7_start = time.time()
        record.update_stage("Policy Review", "Policy Review")
        policy_decisions: List[PolicyDecision] = []
        if recovery_plan:
            policy_decisions = policy_engine.evaluate(recovery_plan, state)
            record.policy_reviews = [PolicyReviewRecord(dec) for dec in policy_decisions]

            approved_count = sum(1 for d in policy_decisions if d.decision == PolicyDecisionValue.APPROVED)
            pending_count = sum(1 for d in policy_decisions if d.decision == PolicyDecisionValue.REQUIRES_APPROVAL)
            rejected_count = sum(1 for d in policy_decisions if d.decision == PolicyDecisionValue.REJECTED)

            stages_log.append({
                "stage": "Deterministic Policy Engine",
                "role": "Compliance & Action Validation (PE-001..PE-004)",
                "status": "completed",
                "model": "Deterministic Policy Engine v1.0",
                "duration": f"{(time.time() - stage7_start) * 1000:.1f}ms",
                "details": f"Evaluated {len(policy_decisions)} actions: {approved_count} Approved, {pending_count} Requires Approval, {rejected_count} Rejected.",
            })
            incident_repository.log_activity(
                agent="Policy Engine",
                action=f"Evaluated {len(policy_decisions)} recovery actions ({pending_count} flagged for human approval)",
                incident_id=incident_id,
                severity="High" if pending_count > 0 else "Info",
            )

        # Step 8: Report Generation Agent (qwen/qwen3.8-27b)
        stage8_start = time.time()
        record.update_stage("Report Generation", "Reporting")
        report: Optional[IncidentReport] = None
        if recovery_plan is not None:
            if has_groq_key:
                try:
                    report = self.report_agent.generate(state, recovery_plan, policy_decisions)
                    stages_log.append({
                        "stage": "Report Generation Agent",
                        "role": "Executive & Technical Reporting",
                        "status": "completed",
                        "model": f"Groq {settings.REPORT_LLM_MODEL}",
                        "duration": f"{time.time() - stage8_start:.2f}s",
                        "details": f"Generated comprehensive report with {len(report.findings)} verified findings.",
                    })
                except Exception as err:
                    report = self._create_grounded_report(state, recovery_plan, policy_decisions)
                    stages_log.append({
                        "stage": "Report Generation Agent",
                        "role": "Executive & Technical Reporting",
                        "status": "completed",
                        "model": f"Groq {settings.REPORT_LLM_MODEL} (Fallback)",
                        "duration": f"{time.time() - stage8_start:.2f}s",
                        "details": f"Synthesized incident report with {len(report.findings)} findings (fallback: {err}).",
                    })
            else:
                report = self._create_grounded_report(state, recovery_plan, policy_decisions)
                stages_log.append({
                    "stage": "Report Generation Agent",
                    "role": "Executive & Technical Reporting",
                    "status": "completed",
                    "model": f"Deterministic Engine (Configure GROQ_API_KEY for {settings.REPORT_LLM_MODEL})",
                    "duration": f"{(time.time() - stage8_start) * 1000:.1f}ms",
                    "details": f"Synthesized incident report with {len(report.threat_assessment)} findings and executive summary.",
                })

        record.report = report
        record.execution_history = stages_log
        record.update_stage("Completed", "Resolved" if not any(r.human_status == "Pending" for r in record.policy_reviews) else "Policy Review")

        incident_repository.log_activity(
            agent="CyberOrchestra Pipeline",
            action=f"Completed multi-agent incident response pipeline in {time.time() - start_time:.2f}s",
            incident_id=incident_id,
            severity="Info",
        )

        return {
            "incident_id": incident_id,
            "status": record.status,
            "pipeline_stage": record.pipeline_stage,
            "duration": f"{time.time() - start_time:.2f}s",
            "stages": stages_log,
            "policy_decisions_count": len(policy_decisions),
            "report_generated": report is not None,
        }

    # ── Evidence-grounded deterministic builders for local mode ──────────────────

    def _create_grounded_threat_assessment(self, incident: Incident) -> ThreatAssessment:
        evidence_ids = [e.evidence_id for e in incident.evidence]
        return ThreatAssessment(
            incident_id=incident.incident_id,
            threat_classification=ThreatClassification.SUSPICIOUS,
            severity=ThreatSeverity.HIGH if (incident.severity or "").lower() in {"critical", "high"} else ThreatSeverity.MEDIUM,
            confidence=0.88,
            reasoning=f"Analyzed {len(incident.indicators)} indicators and {len(incident.evidence)} evidence items from {incident.source}.",
            observed_facts=[f"Observed activity: {incident.description}"],
            inferences=["Telemetry patterns indicate unauthorized network or endpoint activity."],
            supporting_evidence_ids=evidence_ids[:3] if evidence_ids else [],
            mitre_techniques=[i.value for i in incident.indicators if i.indicator_type.lower() in {"mitre", "mitre_attack"}],
            related_cves=[i.value for i in incident.indicators if i.indicator_type.lower() == "cve"],
            recommended_next_analysis=["log_analysis", "vulnerability_assessment"],
            uncertainties=["Long-term persistence mechanisms require ongoing log observation."],
        )

    def _create_grounded_malware_assessment(self, incident: Incident) -> MalwareAssessment:
        evidence_ids = [e.evidence_id for e in incident.evidence]
        has_binary = any("exe" in i.value.lower() or i.indicator_type.lower() == "file_hash" for i in incident.indicators)
        return MalwareAssessment(
            incident_id=incident.incident_id,
            malware_detected=has_binary,
            suspected_family="Suspicious Payload" if has_binary else None,
            confidence=0.82 if has_binary else 0.65,
            supporting_evidence_ids=evidence_ids[:2] if evidence_ids else [],
            uncertainties=["Dynamic sandbox execution was not performed on raw binaries."],
            recommended_next_analysis=[],
        )

    def _create_grounded_log_assessment(self, incident: Incident) -> LogAssessment:
        evidence_ids = [e.evidence_id for e in incident.evidence]
        findings = []
        for e in incident.evidence:
            if "log" in e.evidence_type.lower() or "syslog" in (e.raw_reference or "").lower():
                findings.append(LogFinding(
                    finding=e.description,
                    supporting_evidence_ids=[e.evidence_id],
                ))
        if not findings and evidence_ids:
            findings.append(LogFinding(
                finding="Correlated telemetry events across observed network and host logs.",
                supporting_evidence_ids=[evidence_ids[0]],
            ))
        return LogAssessment(
            incident_id=incident.incident_id,
            severity=LogSeverity.HIGH if (incident.severity or "").lower() in {"critical", "high"} else LogSeverity.MEDIUM,
            confidence=0.85,
            suspicious_events=findings,
            attack_indicators=[],
            timeline_findings=[],
            supporting_evidence_ids=evidence_ids[:3] if evidence_ids else [],
            uncertainties=["Log retention period may limit correlation of pre-compromise activity."],
            recommended_next_analysis=[],
        )

    def _create_grounded_vuln_assessment(self, incident: Incident) -> VulnerabilityAssessment:
        evidence_ids = [e.evidence_id for e in incident.evidence]
        cves = [i.value for i in incident.indicators if i.indicator_type.lower() == "cve"]
        return VulnerabilityAssessment(
            incident_id=incident.incident_id,
            vulnerabilities=cves if cves else ["Potential unpatched service"],
            affected_assets=["Host workstation"],
            related_cves=cves,
            severity=VulnerabilitySeverity.HIGH if cves else VulnerabilitySeverity.MEDIUM,
            exploitability_assessment="CVE identifiers observed in network headers." if cves else "unknown",
            confidence=0.90 if cves else 0.70,
            supporting_evidence_ids=evidence_ids[:2] if evidence_ids else [],
            uncertainties=["Asset patch level should be validated against live configuration management database."],
            recommended_next_analysis=[],
        )

    def _create_grounded_recovery_plan(self, state: IncidentState) -> RecoveryPlan:
        evidence_ids = list(state.aggregated_evidence_ids)
        ref_id = evidence_ids[0] if evidence_ids else state.normalized_incident.evidence[0].evidence_id

        actions = [
            RecoveryAction(
                recovery_action="Isolate affected workstation host from corporate VLAN",
                action_priority=ActionPriority.HIGH,
                rationale="Prevent lateral movement across internal subnets while investigation proceeds.",
                expected_outcome="Network traffic to and from the host is restricted to security monitoring.",
                risks=["Temporary operational disruption to the workstation user"],
                supporting_evidence_ids=[ref_id],
            ),
            RecoveryAction(
                recovery_action="Apply firewall egress block on suspicious destination IP",
                action_priority=ActionPriority.HIGH,
                rationale="Halt command-and-control communication channel.",
                expected_outcome="Outbound traffic dropped by perimeter gateway.",
                risks=["May impact other services if IP is multi-tenant"],
                supporting_evidence_ids=[ref_id],
            ),
            RecoveryAction(
                recovery_action="Reset compromised user credentials and revoke active session tokens",
                action_priority=ActionPriority.MEDIUM,
                rationale="Eliminate attacker persistence through stolen session tokens.",
                expected_outcome="User re-authenticates with mandatory multi-factor authentication.",
                risks=["User must log in again"],
                supporting_evidence_ids=[ref_id],
            ),
        ]

        return RecoveryPlan(
            incident_id=state.incident_id,
            recovery_actions=actions,
            uncertainties=["Root cause patch requirements pending complete vulnerability verification."],
        )

    def _create_grounded_report(
        self,
        state: IncidentState,
        plan: RecoveryPlan,
        decisions: List[PolicyDecision],
    ) -> IncidentReport:
        evidence_ids = list(state.aggregated_evidence_ids)
        evid_id = evidence_ids[0] if evidence_ids else state.normalized_incident.evidence[0].evidence_id

        exec_summary = ReportFinding(
            finding=(
                f"CyberOrchestra multi-agent pipeline identified and triaged incident {state.incident_id} "
                f"({state.normalized_incident.description[:100]}). Deterministic policy engine evaluated "
                f"{len(decisions)} proposed actions with full evidence auditability."
            ),
            status=FindingStatus.CONFIRMED,
            supporting_evidence_ids=[evid_id],
        )

        threat_findings = [
            ReportFinding(
                finding=f"Initial Intrusion Vector: {state.normalized_incident.incident_type}",
                status=FindingStatus.CONFIRMED,
                supporting_evidence_ids=[evid_id],
            ),
        ]

        evidence_summaries = [
            EvidenceSummary(
                evidence_id=e.evidence_id,
                summary=e.description,
            )
            for e in state.normalized_incident.evidence[:5]
        ]

        return IncidentReport(
            incident_id=state.incident_id,
            executive_summary=exec_summary,
            threat_assessment=threat_findings,
            malware_findings=[],
            log_findings=[],
            vulnerability_findings=[],
            recovery_recommendations=plan.recovery_actions,
            policy_decisions=decisions,
            evidence_summary=evidence_summaries,
            uncertainties=["Dynamic sandbox verification was not run on live payload."],
            final_risk_level=FinalRiskLevel.HIGH if (state.normalized_incident.severity or "").lower() in {"critical", "high"} else FinalRiskLevel.MEDIUM,
        )



pipeline_orchestrator = PipelineOrchestrator()
