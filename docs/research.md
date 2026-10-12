# Research Direction & Methodology

## Overview

CyberOrchestra investigates whether a structured, multi-agent prompt-engineering framework outperforms monolithic, general-purpose LLMs in conducting end-to-end cybersecurity incident response while adhering to strict operational and organizational policies.

## Core Research Pillars

1. **Specialized Agents**:
   - Rather than relying on a single prompt or model instance to perform all IR functions, CyberOrchestra partitions tasks into narrow domains of expertise (Threat Detection, Malware Analysis, Log Analysis, Vulnerability Assessment, Recovery Planning, and Report Generation).

2. **Structured Cross-Agent Hand-offs**:
   - Agent communication relies on strict schema-validated message passing and structured hand-offs, minimizing context bloat and preventing drift across execution stages.

3. **Shared Incident State**:
   - An immutable and observable incident state blackboard coordinates findings, hypotheses, and forensic evidence across investigative agents.

4. **Evidence Grounding**:
   - Every inference, IOC extraction, and remediation proposal must trace directly back to concrete evidence identified in the ingested telemetry or threat intelligence sources.

5. **Deterministic Policy Verification**:
   - LLM-generated containment and recovery actions are intercepted by a deterministic, non-probabilistic policy engine to guarantee compliance with authorization hierarchies, regulatory frameworks, and enterprise safety rules.

6. **Dedicated Report Generation**:
   - Separation of technical investigation from communication ensures that technical depth is preserved while generating compliant, structured executive summaries and post-incident reviews.

## Evaluation Strategy

- **Baseline Comparison**:
  - The multi-agent CyberOrchestra framework will be quantitatively and qualitatively benchmarked against a single, general-purpose LLM baseline given equivalent incident telemetry in one-shot and chain-of-thought configurations.

- **End-to-End Evaluation**:
  - Evaluation will measure:
    - **Detection accuracy & precision**: Correct identification of threat actors, TTPs (MITRE ATT&CK), and affected assets.
    - **Policy compliance rate**: Adherence of recovery actions to enterprise incident response playbooks and security constraints.
    - **Hallucination & grounding score**: Rate of ungrounded assertions or phantom IOCs.
    - **Response latency & token efficiency**: Resource overhead across collaborative agents compared to single-agent approaches.

## Role of Reproducible Simulated Incidents

Evaluating a multi-agent incident response system in a scientific, rigorous manner presents distinct empirical challenges:
* **Controlled Ground Truth**: Live production telemetry is noisy, non-deterministic, and frequently lacks complete or unambiguous ground truth. Synthetic, reproducible incident scenarios provide known signal provenance, enabling precise calculation of precision, recall, and grounding metrics.
* **Deterministic Benchmark Comparison**: Fixed scenarios allow direct, controlled head-to-head comparisons between monolithic LLMs (e.g. standard zero-shot / chain-of-thought) and specialized multi-agent architectures on identical inputs.
* **Cross-Agent Consistency Testing**: Multi-signal scenarios (correlating network logs, endpoint events, vulnerability states, and external references) stress-test agent consensus, blackboard synchronization in the Shared Incident State, and cross-signal reasoning without introducing external network instability.
* **Safety & Compliance**: Safe documentation indicators (RFC 5737 IP ranges, RFC 2606 domain names, harmless documentation hashes) eliminate security and ethical hazards associated with handling active malware infrastructure or sensitive operational telemetry during research and automated testing.

