// ============================================================
// CyberOrchestra — Shared Domain & API Types
// ============================================================

export type Severity = 'Critical' | 'High' | 'Medium' | 'Low' | 'Info';

export type IncidentStatus =
  | 'New'
  | 'Investigating'
  | 'Containment'
  | 'Eradication'
  | 'Recovery'
  | 'Policy Review'
  | 'Reporting'
  | 'Resolved'
  | 'Error';

export type AgentStatus = 'idle' | 'running' | 'completed' | 'error' | 'waiting';

// ── Incident Types ──────────────────────────────────────────
export interface Incident {
  id: string;
  title: string;
  description: string;
  severity: Severity;
  status: IncidentStatus;
  assignee: string;
  source: string;
  affectedAssets: number;
  createdAt: string;
  updatedAt: string;
  pipelineStage: string;
  iocs: string[];
  tags: string[];
  indicatorCount?: number;
  evidenceCount?: number;
  hasRecoveryPlan?: boolean;
  hasPolicyReviews?: boolean;
  hasReport?: boolean;
}

export interface IncidentIndicator {
  indicator_type: string;
  value: string;
  source: string;
  confidence?: number | null;
  metadata?: Record<string, any>;
}

export interface IncidentEvidence {
  evidence_id: string;
  evidence_type: string;
  source: string;
  description: string;
  timestamp?: string | null;
  raw_reference?: string | null;
  confidence?: number | null;
  metadata?: Record<string, any>;
}

export interface PipelineStageExecution {
  stage: string;
  role: string;
  status: 'completed' | 'error' | 'skipped' | 'running';
  model?: string;
  duration?: string;
  confidence?: number | null;
  details?: string;
}

export interface IncidentDetail {
  summary: Incident;
  incident: {
    incident_id: string;
    incident_type: string;
    description: string;
    severity?: string | null;
    source: string;
    timestamp: string;
    indicators: IncidentIndicator[];
    evidence: IncidentEvidence[];
  };
  raw_payload?: Record<string, any>;
  pipeline_stage: string;
  status: string;
  execution_history: PipelineStageExecution[];
  state?: Record<string, any> | null;
  recovery_plan?: Record<string, any> | null;
  policy_reviews: PolicyReview[];
  report?: Record<string, any> | null;
}

// ── Agent Pipeline Stage ────────────────────────────────────
export interface AgentStage {
  id: string;
  name: string;
  role: string;
  model: string;
  status: AgentStatus;
  progress: number;
  incidentId: string | null;
  lastAction: string;
  processingTime: string;
  confidence: number | null;
  tokensUsed: number | null;
}

// ── System Health ───────────────────────────────────────────
export interface SystemHealthItem {
  component: string;
  status: 'operational' | 'degraded' | 'down';
  latency: string;
  uptime: string;
  details?: string;
}

export interface SystemHealthResponse {
  status: string;
  timestamp: string;
  components: SystemHealthItem[];
}

// ── Threat Intelligence ─────────────────────────────────────
export interface ThreatFeedItem {
  id: string;
  indicator: string;
  type: 'IP' | 'URL' | 'Hash' | 'CVE' | 'MITRE' | 'Other';
  source: string;
  severity: Severity;
  confidence: number;
  firstSeen: string;
  tags: string[];
}

export interface ThreatSource {
  name: string;
  type: string;
  status: string;
  operational: boolean;
  endpoint: string;
  rateLimit: string;
  authRequired: boolean;
}

// ── Dashboard Statistics ────────────────────────────────────
export interface DashboardKPIs {
  totalIncidents: number;
  criticalIncidents: number;
  activeInvestigations: number;
  policyReviews: number;
  resolvedLast24h: number;
  meanTimeToDetect: string;
  meanTimeToContain: string;
  agentsActive: number;
}

export interface SeverityDistributionItem {
  name: string;
  value: number;
  fill: string;
}

export interface PipelineThroughputItem {
  stage: string;
  count: number;
}

export interface IncidentTrendItem {
  day: string;
  incidents: number;
  resolved: number;
}

export interface ActivityLogEntry {
  id: string;
  timestamp: string;
  agent: string;
  action: string;
  incidentId: string | null;
  severity: Severity | 'System';
}

export interface DashboardStats {
  kpis: DashboardKPIs;
  severityDistribution: SeverityDistributionItem[];
  pipelineThroughput: PipelineThroughputItem[];
  incidentTrend: IncidentTrendItem[];
  recentIncidents: Incident[];
  recentActivity: ActivityLogEntry[];
}

// ── Policy Review ───────────────────────────────────────────
export interface PolicyReview {
  id: string;
  incident: string;
  action: string;
  decision: 'APPROVED' | 'REQUIRES_APPROVAL' | 'REJECTED' | 'approved' | 'requires_approval' | 'rejected';
  status: 'Pending' | 'Approved' | 'Rejected';
  policy_rule_id: string;
  reason: string;
  supporting_evidence_ids: string[];
  analyst_notes?: string | null;
  created_at: string;
  decided_at?: string | null;
}

// ── Reports ─────────────────────────────────────────────────
export interface ReportSummary {
  id: string;
  incident: string;
  title: string;
  status: string;
  analyst: string;
  generatedAt: string;
  riskLevel: string;
  executiveSummary: string;
  findingsCount: number;
  recommendationsCount: number;
}

export interface ReportFindingItem {
  finding: string;
  status: 'confirmed' | 'inferred' | 'uncertain';
  supporting_evidence_ids: string[];
}

export interface ReportEvidenceSummaryItem {
  evidence_id: string;
  summary: string;
}

export interface RecoveryActionItem {
  recovery_action: string;
  action_priority: string;
  rationale: string;
  expected_outcome: string;
  risks: string[];
  supporting_evidence_ids: string[];
}

export interface PolicyDecisionItem {
  incident_id: string;
  action: string;
  decision: string;
  reason: string;
  supporting_evidence_ids: string[];
  policy_rule_id: string;
}

export interface ReportDetail {
  id: string;
  incident: string;
  title: string;
  status: string;
  analyst: string;
  generatedAt: string;
  riskLevel: string;
  executiveSummary: string;
  threatAssessment: ReportFindingItem[];
  malwareFindings: ReportFindingItem[];
  logFindings: ReportFindingItem[];
  vulnerabilityFindings: ReportFindingItem[];
  recoveryRecommendations: RecoveryActionItem[];
  policyDecisions: PolicyDecisionItem[];
  evidenceSummary: ReportEvidenceSummaryItem[];
  uncertainties: string[];
}

// ── Evaluation ──────────────────────────────────────────────
export interface MetricDetail {
  name: string;
  value: number | null;
  display: string;
  numerator: number;
  denominator: number;
  status: string;
  definition: string;
}

export interface SystemMetricsGroup {
  system_name: string;
  metrics: Record<string, MetricDetail>;
  invalid_predictions: string[];
}

export interface EvaluationResponse {
  status: string;
  benchmark_dataset: string;
  scenarios_available: number;
  tested: boolean;
  message?: string;
  incident_ids?: string[];
  multi_agent?: SystemMetricsGroup;
  single_llm_baseline?: SystemMetricsGroup;
}

// ── Benchmark Scenario ──────────────────────────────────────
export interface ScenarioItem {
  filename: string;
  incident_id: string;
  incident_type: string;
  description: string;
  severity: string;
  source: string;
  indicatorsCount: number;
  evidenceCount: number;
  rawData: Record<string, any>;
}
