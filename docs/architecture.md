# CyberOrchestra System Architecture

> [!IMPORTANT]
> **LOCKED ARCHITECTURE**:
> The architecture documented below is the locked design for the CyberOrchestra research system. This architecture must not be changed unless explicitly decided and approved in a later phase.

---

## Architecture Diagram

```text
Threat Intel / CVE / Incident Logs
↓
Data Normalizer
↓
Threat Detection Agent
↓
┌──────────┼──────────┐
↓          ↓          ↓
Malware     Log      Vulnerability
Analysis   Analysis    Assessment
└──────────┼──────────┘
↓
Shared Incident State
↓
Recovery Planning
↓
Deterministic Policy Engine
↓
Report Generation
↓
Final Report
↓
Human Analyst
```

---

## Architectural Stages

1. **Ingestion & Normalization**:
   - Ingestion of heterogeneous security telemetry, including external threat intelligence feeds, CVE repositories, and raw incident logs.
   - **Data Normalizer**: Transforms telemetry into standardized schemas for uniform agent consumption.

### Data Normalizer Role & Responsibilities

The **Data Normalizer** acts as the deterministic front door to the CyberOrchestra pipeline:
* **Receives Heterogeneous Raw Evidence**: Ingests raw incident alerts, external threat feeds (e.g., AbuseIPDB, URLhaus, NVD/CVE), MITRE ATT&CK techniques, and simulated telemetry logs.
* **Validates and Standardizes**: Enforces schema integrity, validates required identifiers and fields, normalizes indicator types (e.g., IP addresses, domains, URLs, file hashes, CVEs, MITRE techniques), and rejects malformed inputs.
* **Preserves Provenance**: Retains telemetry origin sources, confidence ratings, raw references, and unmapped metadata without destructive truncation.
* **Produces a Common Representation**: Translates varied external inputs into canonical `Incident`, `Indicator`, and `Evidence` Pydantic models for reliable consumption by downstream AI agents.

### External Threat Intelligence Ingestion (AbuseIPDB)

```text
External Threat Intelligence (AbuseIPDB API v2)
↓
AbuseIPDB Client
↓
Raw Reputation Evidence
↓
Data Normalizer
↓
Standardized Evidence (Indicator & Evidence models)
↓
Future Threat Detection Agent
```

* **Role of AbuseIPDB**: Serves as a specialized external reputation evidence provider. Queries the AbuseIPDB API v2 check endpoint to retrieve observable historical report counts, external abuse confidence ratings, ISP, country code, and usage classifications.
* **Separation of Evidence and Decision**: AbuseIPDB is an external evidence provider and does **not** itself determine CyberOrchestra's final incident classification or make response/containment decisions. External abuse confidence scores are strictly preserved as contextual evidence within metadata and are never equated to CyberOrchestra's internal AI reasoning confidence.

### External Threat Intelligence Ingestion (URLhaus)

```text
URLhaus (abuse.ch API v1)
   ↓
URLhaus Client
   ↓
External URL Intelligence
   ↓
CyberOrchestra Indicator/Evidence (IndicatorType.URL & EvidenceType.URL_REPUTATION)
   ↓
Future Threat Detection Agent
```

* **Role of URLhaus**: Serves as an external URL threat intelligence provider. Queries the abuse.ch URLhaus API v1 endpoint to retrieve community-reported malware distribution links, payload hashes, threat classifications, online status, and tags.
* **Separation of Evidence and Decision**: URLhaus provides external intelligence and does **not** make CyberOrchestra's final incident response or classification decisions. CyberOrchestra does not treat URLhaus's classification as an internally generated AI decision. The external threat verdict and tags are strictly attributed to URLhaus and preserved as external evidence, with `confidence` explicitly left unmapped (`None`) for downstream AI reasoning agents.

### External Vulnerability Intelligence Ingestion (NVD/CVE)

```text
NVD CVE API 2.0 (NIST National Vulnerability Database)
   ↓
NVD Client  (CVE validation → authenticated/unauthenticated GET → response parsing)
   ↓
External Vulnerability Evidence
   (NVDCVEResponse: CVE ID, description, CVSS v2/v3/v4, CWE, CPE, references, timestamps)
   ↓
CyberOrchestra Indicator/Evidence
   (IndicatorType.CVE & EvidenceType.VULNERABILITY_INTELLIGENCE)
   ↓
Future Vulnerability Assessment Agent
   (correlates CVE data with incident/asset evidence to assess actual exposure)
```

* **Role of NVD**: Serves as the authoritative external source for published CVE vulnerability intelligence. Queries the **NVD CVE API 2.0** endpoint to retrieve structured vulnerability data including CVSS metrics (v2, v3, v4), CWE weakness mappings, affected product CPE configurations, advisory references, publication timestamps, and vulnerability analysis status.

* **API Key Configuration**: The `NVD_API_KEY` environment variable is **optional**. The NVD API functions without authentication at a lower rate limit (~5 requests per 30 seconds). When an API key is configured it is sent via the `apiKey` HTTP header, allowing a higher rate limit (~50 requests per 30 seconds). Keys are never hard-coded, logged, or exposed in responses.

* **Provenance Preservation**: All NVD-sourced evidence carries `source="NVD"`, the originating CNA (CVE Numbering Authority) `source_identifier`, and a `provenance` field set to `"NVD CVE API 2.0"`. The canonical NVD URL is preserved in `evidence.raw_reference`.

* **CVSS ≠ AI Confidence — Critical Boundary**:
  CVSS base scores are external vulnerability severity metrics established by NIST/CVE community scoring. They are explicitly **NOT** mapped to CyberOrchestra's internal `confidence` field on either `Indicator` or `Evidence` models. Both are left as `None` pending determination by downstream AI reasoning agents. CVSS data is preserved in `evidence.metadata`.

* **Vulnerability Intelligence ≠ Exploitation Determination**:
  The NVD client retrieves that a vulnerability *exists and is documented*. It does **not** determine whether any specific asset observed in a CyberOrchestra incident is actually affected by or exposed to this CVE. That correlation requires:
  ```
  NVD Evidence   +   Incident Asset Evidence
        ↓
  Vulnerability Assessment Agent  (future)
        ↓
  Exploitation Exposure Assessment
  ```

* **Synthetic CVE Separation**: CyberOrchestra simulation scenarios may use fictional CVE identifiers (e.g., `CVE-2026-10001`) for reproducible benchmarking. These are independent from live NVD data. The NVD client will correctly return `NVDNotFoundError` for identifiers that do not exist in the real NVD database, which is the expected behavior for synthetic scenario CVEs.

### Combined Threat Intelligence Collection

```text
Normalized Incident
→ Combined Threat Intelligence Service
→ AbuseIPDB (IP) / URLhaus (URL) / NVD (CVE) / MITRE ATT&CK (technique)
→ standardized Indicators and Evidence
```

The combined service queries only sources for indicator types present in the incident. It returns successful standardized results and records per-indicator retrieval failures so one unavailable source does not prevent other lookups. This layer gathers external intelligence only; it makes no malicious/benign decision and does not invoke an LLM. Its standardized evidence is available to the Threat Detection Agent.

### Threat Detection Agent

```text
Normalized Incident + standardized external Evidence
→ Threat Detection Agent
→ Structured Threat Assessment
```

The Threat Detection Agent receives the incident and collected evidence, then uses the configured cloud LLM through the reusable LLM service. Its prompt limits analysis to supplied data, separates observed facts from inferences, treats external scores as contextual evidence, and requires uncertainty reporting. Output confidence is the agent's assessment confidence and remains separate from external provider scores. The agent does not invent evidence or execute security actions; cited evidence IDs are validated against the supplied records. Later analysis agents and action or reporting stages remain outside this step.

### Malware Analysis Agent

```text
Incident + malware-relevant indicators and Evidence
→ Malware Analysis Agent (shared LLM service)
→ Structured Malware Assessment
```

The Malware Analysis Agent focuses on file hashes, malware labels, file samples, and malware-related behavioral evidence. It keeps evidence identifiers, distinguishes observed from suspected behavior, treats a hash as an indicator rather than proof, and validates cited evidence against the supplied records. Family attribution and agent confidence remain uncertain unless supported by the input. The agent does not generate or execute malware and does not perform offensive or autonomous actions.

### External MITRE ATT&CK Intelligence

```text
MITRE ATT&CK official STIX 2.1 data
→ MITRE Client
→ standardized Evidence
→ future Threat Detection Agent
```

The MITRE client retrieves technique descriptions and metadata as read-only external intelligence and preserves source provenance, references, tactics, platforms, and STIX fields. Technique information is descriptive context; it is not an AI confidence score and does not establish that a technique occurred in an incident.

2. **Triage & Detection**:
   - **Threat Detection Agent**: Inspects normalized input to classify attack vectors, identify initial indicators of compromise (IOCs), and trigger specialized investigation pipelines.

3. **Specialized Parallel Investigation**:
   - **Malware Analysis Agent**: Evaluates malicious code fragments, strings, and behavioral signatures.
   - **Log Analysis Agent**: Traces temporal sequences across system, network, and identity access logs.
   - **Vulnerability Assessment Agent**: Correlates targets against known software defects, exploits, and severity rankings (CVSS).

4. **Synthesis & Coordination**:
   - **Shared Incident State**: Serves as the central repository and synchronization blackboard for facts, evidence, confidence scores, and forensic artifacts established by upstream agents.

5. **Action Formulation & Governance**:
   - **Recovery Planning Agent**: Formulates step-by-step containment, eradication, and remediation action plans based on the shared incident state.
   - **Deterministic Policy Engine**: Enforces strict policy compliance, preventing hallucinations or unauthorized system actions through rule-based validation prior to execution.

6. **Reporting & Analyst Handoff**:
   - **Report Generation Agent**: Formulates clear, evidence-grounded incident reports and audit records.
   - **Final Report**: Delivered to the **Human Analyst** for final review, approval, and execution of recovery actions.
