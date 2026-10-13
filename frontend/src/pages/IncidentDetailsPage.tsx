import React, { useCallback, useEffect, useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import {
  Activity, AlertTriangle, ArrowLeft, CheckCircle2, ChevronDown, ChevronUp,
  Circle, Clock, Download, FileText, LoaderCircle, RefreshCw,
  Shield, ShieldAlert, ShieldCheck, ShieldX, Sparkles, UserCheck, XCircle,
} from 'lucide-react';
import { Header } from '../components/layout/Header';
import { SeverityBadge, StatusBadge } from '../components/ui/Badges';
import { api, ApiError } from '../services/api';
import type { IncidentDetail } from '../types';

type PipelineTab = 'agents' | 'state' | 'recovery' | 'policy' | 'report';
type AnyRecord = Record<string, any>;

// ── Helpers ───────────────────────────────────────────────────────────────────
const asList = (v: unknown): any[] => Array.isArray(v) ? v : [];
const prettyStatus = (v: unknown) =>
  typeof v === 'string' ? v.replaceAll('_', ' ').replace(/^./, (c) => c.toUpperCase()) : 'Not available';
const asText = (v: unknown): string => (typeof v === 'string' && v.trim() ? v : '');
const pct = (v: unknown) =>
  typeof v === 'number' ? `${Math.round(v > 1 ? v : v * 100)}%` : '—';

// ── Evidence Reference Pills ─────────────────────────────────────────────────
const EvidenceRefs: React.FC<{ ids: unknown }> = ({ ids }) => {
  const list = asList(ids).map(String).filter(Boolean);
  if (!list.length) return <span className="detail-muted">No evidence cited.</span>;
  return (
    <div className="evidence-ref-list">
      {list.map((id) => <span className="evidence-ref" key={id}>{id}</span>)}
    </div>
  );
};

// ── Finding List ──────────────────────────────────────────────────────────────
const FindingList: React.FC<{ items: unknown; empty: string }> = ({ items, empty }) => {
  const list = asList(items);
  if (!list.length) return <p className="detail-muted">{empty}</p>;
  return (
    <ul className="detail-bullets">
      {list.map((item, i) => (
        <li key={i}>
          {typeof item === 'string' ? item : (
            <>
              {item.finding ?? item.event ?? JSON.stringify(item)}
              {item.status && <span className="finding-status"> · {prettyStatus(item.status)}</span>}
            </>
          )}
          {item?.supporting_evidence_ids && <EvidenceRefs ids={item.supporting_evidence_ids} />}
        </li>
      ))}
    </ul>
  );
};

// ── Collapsible Raw JSON ──────────────────────────────────────────────────────
const RawDataToggle: React.FC<{ data: unknown; label?: string }> = ({ data, label = 'Raw data' }) => {
  const [open, setOpen] = useState(false);
  return (
    <div className="raw-toggle">
      <button className="raw-toggle-btn" onClick={() => setOpen((o) => !o)}>
        {open ? <ChevronUp size={13} /> : <ChevronDown size={13} />}
        {open ? 'Hide' : 'Show'} {label}
      </button>
      {open && (
        <pre className="raw-pre">{JSON.stringify(data, null, 2)}</pre>
      )}
    </div>
  );
};

// ── Pipeline Stepper ──────────────────────────────────────────────────────────
interface StepperProps {
  currentTab: PipelineTab;
  onTabChange: (tab: PipelineTab) => void;
  detail: IncidentDetail;
}

const STEPS: { id: PipelineTab; label: string; icon: React.FC<any> }[] = [
  { id: 'agents',   label: 'Analytical Agents',  icon: ShieldAlert },
  { id: 'state',    label: 'Shared State',        icon: Activity },
  { id: 'recovery', label: 'Recovery Plan',       icon: RefreshCw },
  { id: 'policy',   label: 'Policy & Approval',   icon: ShieldCheck },
  { id: 'report',   label: 'Final Report',        icon: FileText },
];

const STAGE_COMPLETE_ORDER: Record<PipelineTab, string[]> = {
  agents:   ['Threat Detection Agent', 'Malware Analysis Agent', 'Log Analysis Agent', 'Vulnerability Assessment Agent'],
  state:    ['Shared Incident State'],
  recovery: ['Recovery Planning Agent'],
  policy:   ['Deterministic Policy Engine'],
  report:   ['Report Generation Agent'],
};

function stepStatus(tab: PipelineTab, detail: IncidentDetail): 'completed' | 'error' | 'running' | 'pending' {
  const history = detail.execution_history ?? [];
  const stages = STAGE_COMPLETE_ORDER[tab];
  const matches = history.filter((h) => stages.includes(h.stage));
  if (matches.some((m) => m.status === 'error')) return 'error';
  if (matches.some((m) => m.status === 'running')) return 'running';
  if (matches.length && matches.every((m) => m.status === 'completed' || m.status === 'skipped')) return 'completed';
  if (detail.pipeline_stage === 'Completed') {
    if (tab === 'report' && detail.report) return 'completed';
    if (tab === 'policy' && detail.policy_reviews?.length) return 'completed';
    if (tab === 'recovery' && detail.recovery_plan) return 'completed';
    if (tab === 'state' && detail.state) return 'completed';
  }
  return 'pending';
}

const PipelineStepper: React.FC<StepperProps> = ({ currentTab, onTabChange, detail }) => (
  <div className="pipeline-stepper">
    {STEPS.map((step, i) => {
      const status = stepStatus(step.id, detail);
      const Icon = step.icon;
      return (
        <React.Fragment key={step.id}>
          <button
            className={`stepper-step step-${status} ${currentTab === step.id ? 'step-active' : ''}`}
            onClick={() => onTabChange(step.id)}
          >
            <span className="stepper-icon">
              {status === 'completed' ? <CheckCircle2 size={16} /> :
               status === 'error' ? <XCircle size={16} /> :
               status === 'running' ? <LoaderCircle size={16} className="spin-icon" /> :
               <Icon size={16} />}
            </span>
            <span className="stepper-label">{step.label}</span>
            {status === 'running' && <span className="stepper-live-dot" />}
          </button>
          {i < STEPS.length - 1 && (
            <div className={`stepper-connector ${status === 'completed' ? 'connector-done' : ''}`} />
          )}
        </React.Fragment>
      );
    })}
  </div>
);

// ── Agent Cards ───────────────────────────────────────────────────────────────
const AGENT_DEFS = [
  {
    key: 'threat_detection_result',
    title: 'Threat Detection Agent',
    stage: 'Threat Detection Agent',
    purpose: 'Classifies the incident, assesses severity, and explains the evidence behind the assessment.',
    icon: ShieldAlert,
    color: 'cyan',
  },
  {
    key: 'malware_analysis_result',
    title: 'Malware Analysis Agent',
    stage: 'Malware Analysis Agent',
    purpose: 'Reviews malware indicators and behavioral findings associated with this incident.',
    icon: Shield,
    color: 'red',
  },
  {
    key: 'log_analysis_result',
    title: 'Log Analysis Agent',
    stage: 'Log Analysis Agent',
    purpose: 'Correlates suspicious events and timelines from available log evidence.',
    icon: FileText,
    color: 'amber',
  },
  {
    key: 'vulnerability_assessment_result',
    title: 'Vulnerability Assessment Agent',
    stage: 'Vulnerability Assessment Agent',
    purpose: 'Reviews vulnerability information and related CVEs for affected assets.',
    icon: AlertTriangle,
    color: 'purple',
  },
] as const;

function AgentResultBody({ kind, result }: { kind: string; result: AnyRecord }) {
  if (kind === 'threat_detection_result') {
    return (
      <>
        <div className="agent-callout">
          <strong>{prettyStatus(result.threat_classification)}</strong>
          <span>Severity: {prettyStatus(result.severity)} · Confidence: {pct(result.confidence)}</span>
        </div>
        {asText(result.reasoning) && <p className="agent-reasoning">{result.reasoning}</p>}
        <h4 className="agent-section-title">Observed Facts</h4>
        <FindingList items={result.observed_facts} empty="No observed facts returned." />
        <h4 className="agent-section-title">Inferences</h4>
        <FindingList items={result.inferences} empty="No inferences returned." />
        <h4 className="agent-section-title">Supporting Evidence</h4>
        <EvidenceRefs ids={result.supporting_evidence_ids} />
        <h4 className="agent-section-title" style={{ color: 'var(--amber-400)' }}>Uncertainties</h4>
        <FindingList items={result.uncertainties} empty="No uncertainties reported." />
      </>
    );
  }
  if (kind === 'malware_analysis_result') {
    return (
      <>
        <div className={`agent-callout ${result.malware_detected ? 'callout-danger' : 'callout-safe'}`}>
          <strong>{result.malware_detected ? 'Malware Detected' : 'No Malware Detected'}</strong>
          <span>
            Confidence: {pct(result.confidence)}
            {result.suspected_family ? ` · Suspected family: ${result.suspected_family}` : ''}
          </span>
        </div>
        <h4 className="agent-section-title">Behavioral Findings</h4>
        <FindingList items={result.behavioral_findings} empty="No behavioral findings returned." />
        <h4 className="agent-section-title">Indicators</h4>
        <FindingList
          items={asList(result.indicators).map((item: AnyRecord) => ({
            finding: `${item.indicator_type}: ${item.value}`,
            supporting_evidence_ids: item.supporting_evidence_ids,
          }))}
          empty="No malware indicators returned."
        />
        <h4 className="agent-section-title">Supporting Evidence</h4>
        <EvidenceRefs ids={result.supporting_evidence_ids} />
        <h4 className="agent-section-title" style={{ color: 'var(--amber-400)' }}>Uncertainties</h4>
        <FindingList items={result.uncertainties} empty="No uncertainties reported." />
      </>
    );
  }
  if (kind === 'log_analysis_result') {
    return (
      <>
        <div className="agent-callout">
          <strong>Log Severity: {prettyStatus(result.severity)}</strong>
          <span>Confidence: {pct(result.confidence)}</span>
        </div>
        <h4 className="agent-section-title">Suspicious Events</h4>
        <FindingList items={result.suspicious_events} empty="No suspicious events returned." />
        <h4 className="agent-section-title">Timeline</h4>
        <FindingList
          items={asList(result.timeline_findings).map((item: AnyRecord) => ({
            ...item,
            finding: item.timestamp ? `${item.timestamp}: ${item.event}` : item.event,
          }))}
          empty="No timeline findings returned."
        />
        <h4 className="agent-section-title">Supporting Evidence</h4>
        <EvidenceRefs ids={result.supporting_evidence_ids} />
        <h4 className="agent-section-title" style={{ color: 'var(--amber-400)' }}>Uncertainties</h4>
        <FindingList items={result.uncertainties} empty="No uncertainties reported." />
      </>
    );
  }
  // vulnerability_assessment_result
  return (
    <>
      <div className="agent-callout">
        <strong>Vulnerability Severity: {prettyStatus(result.severity)}</strong>
        <span>Confidence: {pct(result.confidence)}</span>
      </div>
      {asText(result.exploitability_assessment) && (
        <p className="agent-reasoning">{result.exploitability_assessment}</p>
      )}
      <h4 className="agent-section-title">Identified Vulnerabilities</h4>
      <FindingList items={result.vulnerabilities} empty="No vulnerabilities identified." />
      <h4 className="agent-section-title">Affected Assets</h4>
      <FindingList items={result.affected_assets} empty="No affected assets returned." />
      <h4 className="agent-section-title">Supporting Evidence</h4>
      <EvidenceRefs ids={result.supporting_evidence_ids} />
      <h4 className="agent-section-title" style={{ color: 'var(--amber-400)' }}>Uncertainties</h4>
      <FindingList items={result.uncertainties} empty="No uncertainties reported." />
    </>
  );
}

// ── Tab: Agents ───────────────────────────────────────────────────────────────
function AgentsTab({ detail }: { detail: IncidentDetail }) {
  const state = detail.state as AnyRecord | null;
  const history = detail.execution_history ?? [];
  return (
    <div className="tab-content-grid">
      <div className="tab-section-header">
        <h3>Four Analytical Agents</h3>
        <p>
          These agents run after the Data Normalizer and Threat Intelligence Enrichment complete on the backend.
          Malware Analysis, Log Analysis, and Vulnerability Assessment run in parallel.
        </p>
      </div>
      <div className="agents-grid">
        {AGENT_DEFS.map((agent) => {
          const result = state?.[agent.key] as AnyRecord | undefined;
          const execution = history.find((h) => h.stage === agent.stage);
          const Icon = agent.icon;
          const agentStatus = execution?.status ?? (result ? 'completed' : 'pending');
          return (
            <article key={agent.key} className={`agent-card agent-${agent.color}`}>
              <div className="agent-card-header">
                <div className="agent-card-title-row">
                  <span className={`agent-card-icon icon-${agent.color}`}><Icon size={18} /></span>
                  <div>
                    <h4>{agent.title}</h4>
                    <p>{agent.purpose}</p>
                  </div>
                </div>
                <span className={`agent-status-chip status-${agentStatus}`}>
                  {agentStatus === 'running' && <LoaderCircle size={11} className="spin-icon" />}
                  {agentStatus === 'completed' && <CheckCircle2 size={11} />}
                  {agentStatus === 'error' && <XCircle size={11} />}
                  {agentStatus === 'pending' && <Circle size={11} />}
                  {prettyStatus(agentStatus)}
                </span>
              </div>

              <div className="agent-card-body">
                {!result ? (
                  <div className="agent-pending-state">
                    {agentStatus === 'error' ? (
                      <><AlertTriangle size={16} /><span>{execution?.details || 'This agent reported an error.'}</span></>
                    ) : (
                      <span className="detail-muted">
                        {execution?.details ??
                          (detail.pipeline_stage === 'Completed'
                            ? 'The backend did not return a result for this agent.'
                            : 'This agent has not run yet.')}
                      </span>
                    )}
                  </div>
                ) : (
                  <AgentResultBody kind={agent.key} result={result} />
                )}
              </div>

              {execution?.confidence != null && (
                <div className="agent-confidence-bar">
                  <div
                    className="agent-confidence-fill"
                    style={{ width: `${Math.round(execution.confidence * 100)}%` }}
                  />
                  <span>Confidence: {Math.round(execution.confidence * 100)}%</span>
                </div>
              )}
            </article>
          );
        })}
      </div>
    </div>
  );
}

// ── Tab: Shared Incident State ────────────────────────────────────────────────
function SharedStateTab({ detail }: { detail: IncidentDetail }) {
  const state = detail.state as AnyRecord | null;
  const inc = detail.incident;

  if (!state) {
    return (
      <div className="tab-content-grid">
        <div className="tab-section-header">
          <h3>Shared Incident State</h3>
          <p>The consolidated context passed to the Recovery Planning Agent after the four analytical agents complete.</p>
        </div>
        <div className="empty-section">
          <Activity size={28} />
          <strong>Shared state not yet available</strong>
          <span>The shared incident state is populated after the four analytical agents complete their analysis.</span>
        </div>
      </div>
    );
  }

  const td = state.threat_detection_result as AnyRecord | null;
  const mal = state.malware_analysis_result as AnyRecord | null;
  const log = state.log_analysis_result as AnyRecord | null;
  const vuln = state.vulnerability_assessment_result as AnyRecord | null;
  const allUncertainties = asList(state.overall_uncertainties);
  const allEvidenceIds = asList(state.aggregated_evidence_ids);

  return (
    <div className="tab-content-grid">
      <div className="tab-section-header">
        <h3>Shared Incident State</h3>
        <p>
          This is the consolidated context that the Recovery Planning Agent uses as input.
          It contains validated, cross-referenced outputs from all four analytical agents.
        </p>
      </div>

      {/* Incident Classification */}
      <div className="state-section">
        <h4 className="state-section-title"><ShieldAlert size={14} /> Incident Classification</h4>
        <div className="state-meta-grid">
          <div className="state-meta-item">
            <span>Incident ID</span>
            <code>{inc.incident_id}</code>
          </div>
          <div className="state-meta-item">
            <span>Incident Type</span>
            <strong>{inc.incident_type}</strong>
          </div>
          <div className="state-meta-item">
            <span>Severity</span>
            <strong>{inc.severity ?? '—'}</strong>
          </div>
          <div className="state-meta-item">
            <span>Threat Classification</span>
            <strong>{td?.threat_classification ? prettyStatus(td.threat_classification) : '—'}</strong>
          </div>
          <div className="state-meta-item">
            <span>Detection Confidence</span>
            <strong>{td?.confidence != null ? pct(td.confidence) : '—'}</strong>
          </div>
          <div className="state-meta-item">
            <span>Malware Detected</span>
            <strong style={{ color: mal?.malware_detected ? 'var(--red-400)' : 'var(--green-400)' }}>
              {mal != null ? (mal.malware_detected ? 'Yes' : 'No') : '—'}
            </strong>
          </div>
        </div>
      </div>

      {/* Aggregated Evidence */}
      <div className="state-section">
        <h4 className="state-section-title"><FileText size={14} /> Aggregated Evidence IDs</h4>
        {allEvidenceIds.length ? (
          <div className="evidence-ref-list">
            {allEvidenceIds.map((id) => <span className="evidence-ref" key={id}>{id}</span>)}
          </div>
        ) : (
          <p className="detail-muted">No evidence IDs were aggregated across agent results.</p>
        )}
      </div>

      {/* Consolidated Findings Summary */}
      <div className="state-findings-grid">
        {[
          { title: 'Threat Detection Findings', items: asList(td?.observed_facts), empty: 'No threat detection findings.' },
          { title: 'Malware Behavioral Findings', items: asList(mal?.behavioral_findings), empty: 'No malware behavioral findings.' },
          { title: 'Log Analysis — Suspicious Events', items: asList(log?.suspicious_events), empty: 'No suspicious log events.' },
          { title: 'Vulnerabilities Identified', items: asList(vuln?.vulnerabilities), empty: 'No vulnerabilities identified.' },
        ].map(({ title, items, empty }) => (
          <div key={title} className="state-finding-card">
            <h5>{title}</h5>
            <FindingList items={items.slice(0, 5)} empty={empty} />
            {items.length > 5 && <p className="detail-muted">+{items.length - 5} more findings…</p>}
          </div>
        ))}
      </div>

      {/* Uncertainties */}
      {allUncertainties.length > 0 && (
        <div className="state-section state-uncertainties">
          <h4 className="state-section-title" style={{ color: 'var(--amber-400)' }}>
            <AlertTriangle size={14} /> Outstanding Uncertainties
          </h4>
          <p className="detail-muted" style={{ marginBottom: 8 }}>
            These unresolved uncertainties were aggregated from all four analytical agents and are passed to the Recovery Planning Agent as context.
          </p>
          <FindingList items={allUncertainties} empty="No uncertainties reported." />
        </div>
      )}

      <RawDataToggle data={state} label="raw shared state JSON" />
    </div>
  );
}

// ── Tab: Recovery Plan ────────────────────────────────────────────────────────
function RecoveryTab({ detail }: { detail: IncidentDetail; onRefresh?: () => void }) {
  const plan = detail.recovery_plan as AnyRecord | null;
  const execution = detail.execution_history?.find((h) => h.stage === 'Recovery Planning Agent');

  if (!plan) {
    return (
      <div className="tab-content-grid">
        <div className="tab-section-header">
          <h3>Recovery Plan — Agent 5</h3>
          <p>Generated by the Recovery Planning Agent using the shared incident state as input.</p>
        </div>
        <div className="empty-section">
          <RefreshCw size={28} />
          <strong>Recovery plan not yet available</strong>
          <span>The Recovery Planning Agent runs after the Shared Incident State is validated.</span>
        </div>
      </div>
    );
  }

  const actions = asList(plan.recovery_actions);

  return (
    <div className="tab-content-grid">
      <div className="tab-section-header">
        <h3>Recovery Plan — Agent 5</h3>
        <p>Prioritized remediation recommendations generated by the Recovery Planning Agent. Review only — no actions are executed from this interface.</p>
        {execution && (
          <span className={`agent-status-chip status-${execution.status} chip-inline`}>
            {prettyStatus(execution.status)}
          </span>
        )}
      </div>

      {actions.length === 0 ? (
        <div className="empty-section">
          <RefreshCw size={24} />
          <strong>No recovery actions returned</strong>
          <span>The Recovery Planning Agent did not produce any actions for this incident.</span>
        </div>
      ) : (
        <div className="recovery-actions-list">
          {actions.map((action: AnyRecord, i: number) => {
            const priority = asText(action.action_priority).toLowerCase();
            return (
              <article key={i} className={`recovery-action-card priority-${priority}`}>
                <div className="recovery-action-header">
                  <span className="recovery-action-index">{i + 1}</span>
                  <div className="recovery-action-title">
                    <strong>{asText(action.recovery_action) || 'Recovery action'}</strong>
                    <span className={`priority-badge priority-${priority}`}>
                      {asText(action.action_priority) || '—'} priority
                    </span>
                  </div>
                </div>

                {asText(action.rationale) && (
                  <div className="recovery-detail">
                    <b>Rationale</b>
                    <p>{action.rationale}</p>
                  </div>
                )}
                {asText(action.expected_outcome) && (
                  <div className="recovery-detail">
                    <b>Expected outcome</b>
                    <p>{action.expected_outcome}</p>
                  </div>
                )}
                {asList(action.risks).length > 0 && (
                  <div className="recovery-detail">
                    <b>Risks &amp; considerations</b>
                    <ul className="detail-bullets" style={{ marginTop: 4 }}>
                      {asList(action.risks).map((r: unknown, ri: number) => (
                        <li key={ri}>{String(r)}</li>
                      ))}
                    </ul>
                  </div>
                )}
                <div className="recovery-detail">
                  <b>Supporting evidence</b>
                  <EvidenceRefs ids={action.supporting_evidence_ids} />
                </div>
              </article>
            );
          })}
        </div>
      )}

      {asList(plan.uncertainties).length > 0 && (
        <div className="state-section state-uncertainties">
          <h4 className="state-section-title" style={{ color: 'var(--amber-400)' }}>
            <AlertTriangle size={14} /> Recovery Plan Uncertainties
          </h4>
          <FindingList items={plan.uncertainties} empty="None." />
        </div>
      )}

      <div className="recovery-safety-note">
        <ShieldCheck size={14} />
        <span>
          These recommendations are for analyst review. This interface does not execute recovery actions.
          Approval must be recorded through the Policy &amp; Approval tab.
        </span>
      </div>
    </div>
  );
}

// ── Tab: Policy & Approval ────────────────────────────────────────────────────
function PolicyTab({
  detail,
  onRefresh,
}: {
  detail: IncidentDetail;
  onRefresh: () => void;
}) {
  const [actionLoading, setActionLoading] = useState<string | null>(null);
  const [actionMsg, setActionMsg] = useState<string | null>(null);
  const reviews = detail.policy_reviews ?? [];
  const policyExecution = detail.execution_history?.find((h) => h.stage === 'Deterministic Policy Engine');

  const handleAction = async (reviewId: string, action: 'approve' | 'reject') => {
    setActionLoading(reviewId + action);
    setActionMsg(null);
    try {
      const fn = action === 'approve' ? api.approvePolicyReview : api.rejectPolicyReview;
      const result = await fn(reviewId);
      setActionMsg(result.message);
      await onRefresh();
    } catch (err) {
      setActionMsg(err instanceof ApiError ? err.message : 'Action failed.');
    } finally {
      setActionLoading(null);
    }
  };

  const passed = reviews.filter((r) => String(r.decision).toUpperCase() === 'APPROVED').length;
  const pending = reviews.filter((r) => r.status === 'Pending').length;
  const blocked = reviews.filter((r) => String(r.decision).toUpperCase() === 'REJECTED').length;
  const requiresHuman = reviews.filter((r) => String(r.decision).toUpperCase() === 'REQUIRES_APPROVAL' || String(r.decision).toUpperCase() === 'REQUIRES APPROVAL').length;

  return (
    <div className="tab-content-grid">
      <div className="tab-section-header">
        <h3>Policy Compliance &amp; Validation</h3>
        <p>
          The Deterministic Policy Engine evaluates each recovery action against configured rules.
          Results are authoritative — approval status is recorded by the backend, not this interface.
        </p>
        {policyExecution && (
          <span className={`agent-status-chip status-${policyExecution.status} chip-inline`}>
            Policy Engine: {prettyStatus(policyExecution.status)}
          </span>
        )}
      </div>

      {reviews.length === 0 ? (
        <div className="empty-section">
          <ShieldCheck size={28} />
          <strong>No policy decisions yet</strong>
          <span>Policy decisions appear after the Deterministic Policy Engine processes the recovery plan.</span>
        </div>
      ) : (
        <>
          {/* Summary metrics */}
          <div className="policy-summary-grid">
            <div className="policy-metric">
              <span>Total Evaluated</span>
              <strong>{reviews.length}</strong>
            </div>
            <div className="policy-metric policy-metric-pass">
              <span>Approved</span>
              <strong>{passed}</strong>
            </div>
            <div className="policy-metric policy-metric-warn">
              <span>Requires Human Review</span>
              <strong>{requiresHuman}</strong>
            </div>
            <div className="policy-metric policy-metric-fail">
              <span>Blocked</span>
              <strong>{blocked}</strong>
            </div>
            <div className="policy-metric policy-metric-pending">
              <span>Pending Analyst Decision</span>
              <strong>{pending}</strong>
            </div>
          </div>

          {actionMsg && (
            <div className="policy-action-msg">
              <CheckCircle2 size={14} /> {actionMsg}
            </div>
          )}

          {/* Decision cards */}
          <div className="policy-decisions-list">
            {reviews.map((review) => {
              const decision = String(review.decision).toUpperCase().replace('_', ' ');
              const canReview = (decision === 'REQUIRES APPROVAL' || decision === 'REQUIRES_APPROVAL') && review.status === 'Pending';
              const isBlocked = decision === 'REJECTED';
              return (
                <article
                  key={review.id}
                  className={`policy-decision-card decision-${decision.toLowerCase().replace(/\s+/g, '-')}`}
                >
                  <div className="policy-decision-header">
                    <div className="policy-decision-verdict">
                      {isBlocked ? <ShieldX size={15} /> : decision === 'APPROVED' ? <ShieldCheck size={15} /> : <Clock size={15} />}
                      <span className={`policy-decision-label decision-${decision.toLowerCase().replace(/[\s_]+/g, '-')}`}>
                        {decision}
                      </span>
                    </div>
                    <code className="policy-rule-id">{review.policy_rule_id || 'No rule ID'}</code>
                  </div>

                  <h4 className="policy-action-title">{review.action}</h4>

                  {isBlocked && (
                    <div className="policy-violation-banner">
                      <ShieldX size={13} />
                      <span>This action is blocked by a policy violation. It cannot be approved or executed.</span>
                    </div>
                  )}

                  <div className="policy-reason">
                    <b>Policy decision reason</b>
                    <p>{review.reason || 'No reason returned.'}</p>
                  </div>

                  <div className="policy-evidence">
                    <b>Supporting evidence</b>
                    <EvidenceRefs ids={review.supporting_evidence_ids} />
                  </div>

                  <div className="policy-human-status">
                    <UserCheck size={13} />
                    <span>Human review: <b>{review.status}</b></span>
                    {review.decided_at && (
                      <time dateTime={review.decided_at}>{new Date(review.decided_at).toLocaleString()}</time>
                    )}
                  </div>

                  {review.analyst_notes && (
                    <p className="policy-analyst-notes">Analyst note: {review.analyst_notes}</p>
                  )}

                  {canReview && (
                    <div className="policy-review-actions">
                      <button
                        className="policy-approve-btn"
                        disabled={actionLoading === review.id + 'approve'}
                        onClick={() => void handleAction(review.id, 'approve')}
                      >
                        {actionLoading === review.id + 'approve' ? <LoaderCircle size={13} className="spin-icon" /> : <CheckCircle2 size={13} />}
                        Record Approval
                      </button>
                      <button
                        className="policy-reject-btn"
                        disabled={actionLoading === review.id + 'reject'}
                        onClick={() => void handleAction(review.id, 'reject')}
                      >
                        {actionLoading === review.id + 'reject' ? <LoaderCircle size={13} className="spin-icon" /> : <ShieldX size={13} />}
                        Record Rejection
                      </button>
                    </div>
                  )}
                </article>
              );
            })}
          </div>
        </>
      )}

      <div className="recovery-safety-note">
        <ShieldCheck size={14} />
        <span>
          The backend Policy Engine is authoritative. Approval here records analyst decisions — it does not bypass
          engine decisions or override blocked actions.
        </span>
      </div>
    </div>
  );
}

// ── Tab: Final Report ─────────────────────────────────────────────────────────
function ReportTab({ detail, incidentId }: { detail: IncidentDetail; incidentId: string }) {
  const report = detail.report as AnyRecord | null;

  const handleDownload = () => {
    if (!report) return;
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `report-${incidentId}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  if (!report) {
    return (
      <div className="tab-content-grid">
        <div className="tab-section-header">
          <h3>Final Report — Agent 6</h3>
          <p>Generated by the Report Generation Agent after analysis, recovery planning, and policy review complete.</p>
        </div>
        <div className="empty-section">
          <FileText size={28} />
          <strong>Report not yet available</strong>
          <span>The Report Generation Agent runs after the Policy Engine completes its review.</span>
        </div>
      </div>
    );
  }

  const sections: [string, unknown][] = [
    ['Threat Assessment', report.threat_assessment],
    ['Malware Findings', report.malware_findings],
    ['Log Findings', report.log_findings],
    ['Vulnerability Findings', report.vulnerability_findings],
  ];

  return (
    <div className="tab-content-grid">
      <div className="tab-section-header">
        <h3>Incident Response Report — Agent 6</h3>
        <p>Consolidated report generated by the Report Generation Agent from all pipeline outputs.</p>
        <button className="report-download-btn" onClick={handleDownload}>
          <Download size={14} /> Download Report (JSON)
        </button>
      </div>

      {/* Executive Summary */}
      <div className="report-executive-summary">
        <div className="report-risk-badge">
          FINAL RISK: {prettyStatus(report.final_risk_level ?? report.riskLevel)}
        </div>
        <p>{report.executive_summary?.finding ?? report.executiveSummary ?? 'No executive summary returned.'}</p>
        <EvidenceRefs ids={report.executive_summary?.supporting_evidence_ids} />
      </div>

      {/* Incident Details */}
      <div className="report-section">
        <h4>Incident Details</h4>
        <div className="state-meta-grid">
          <div className="state-meta-item"><span>Incident ID</span><code>{report.incident ?? incidentId}</code></div>
          <div className="state-meta-item"><span>Analyst</span><strong>{report.analyst ?? 'Report Generation Agent'}</strong></div>
          <div className="state-meta-item"><span>Generated</span><strong>{report.generatedAt ? new Date(report.generatedAt).toLocaleString() : '—'}</strong></div>
          <div className="state-meta-item"><span>Risk Level</span><strong style={{ color: 'var(--red-400)' }}>{prettyStatus(report.final_risk_level ?? report.riskLevel)}</strong></div>
        </div>
      </div>

      {/* Agent finding sections */}
      {sections.map(([title, items]) => (
        <div key={title} className="report-section">
          <h4>{title}</h4>
          <FindingList items={items} empty={`No ${title.toLowerCase()} returned.`} />
        </div>
      ))}

      {/* Recovery recommendations */}
      <div className="report-section">
        <h4>Recovery Recommendations</h4>
        {asList(report.recovery_recommendations).length ? (
          <div className="recovery-actions-list compact">
            {asList(report.recovery_recommendations).map((action: AnyRecord, i: number) => (
              <div key={i} className="recovery-action-card compact">
                <div className="recovery-action-header">
                  <span className="recovery-action-index">{i + 1}</span>
                  <div>
                    <strong>{asText(action.recovery_action)}</strong>
                    <span className={`priority-badge priority-${asText(action.action_priority).toLowerCase()}`}>
                      {asText(action.action_priority)} priority
                    </span>
                  </div>
                </div>
                {asText(action.rationale) && <p className="detail-muted" style={{ marginLeft: 36 }}>{action.rationale}</p>}
              </div>
            ))}
          </div>
        ) : (
          <p className="detail-muted">No recovery recommendations included in the report.</p>
        )}
      </div>

      {/* Policy decisions */}
      <div className="report-section">
        <h4>Policy Decisions in Report</h4>
        {asList(report.policy_decisions).length ? (
          <div className="policy-decisions-list compact">
            {asList(report.policy_decisions).map((d: AnyRecord, i: number) => (
              <div key={i} className="policy-compact-row">
                <span className={`policy-compact-decision decision-${String(d.decision).toLowerCase()}`}>
                  {String(d.decision).toUpperCase().replace('_', ' ')}
                </span>
                <span className="policy-compact-action">{d.action}</span>
                <code className="policy-rule-id">{d.policy_rule_id}</code>
              </div>
            ))}
          </div>
        ) : (
          <p className="detail-muted">No policy decisions included in the report.</p>
        )}
      </div>

      {/* Evidence summary */}
      <div className="report-section">
        <h4>Evidence Summary</h4>
        {asList(report.evidence_summary).length ? (
          <div className="evidence-summary-list">
            {asList(report.evidence_summary).map((item: AnyRecord) => (
              <div key={item.evidence_id} className="evidence-summary-row">
                <code className="evidence-id-code">{item.evidence_id}</code>
                <span>{item.summary}</span>
              </div>
            ))}
          </div>
        ) : (
          <p className="detail-muted">No evidence summary returned.</p>
        )}
      </div>

      {/* Uncertainties */}
      {asList(report.uncertainties).length > 0 && (
        <div className="report-section">
          <h4 style={{ color: 'var(--amber-400)' }}>Unresolved Risks &amp; Uncertainties</h4>
          <FindingList items={report.uncertainties} empty="None." />
        </div>
      )}
    </div>
  );
}

// ── Main Page ─────────────────────────────────────────────────────────────────
export const IncidentDetailsPage: React.FC = () => {
  const { incidentId = '' } = useParams();
  const [detail, setDetail] = useState<IncidentDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [tab, setTab] = useState<PipelineTab>('agents');
  const [enriching, setEnriching] = useState(false);
  const [enrichmentMessage, setEnrichmentMessage] = useState<string | null>(null);
  const [runningPipeline, setRunningPipeline] = useState(false);

  const loadDetail = useCallback(async () => {
    setLoading(true);
    setError(null);
    try { setDetail(await api.getIncident(incidentId)); }
    catch (err) { setError(err instanceof ApiError ? err.message : 'Incident details could not be loaded.'); }
    finally { setLoading(false); }
  }, [incidentId]);

  useEffect(() => { void loadDetail(); }, [loadDetail]);

  const handleEnrich = async () => {
    setEnriching(true);
    setEnrichmentMessage(null);
    try {
      const response = await api.enrichIncident(incidentId);
      await loadDetail();
      const failed = asList(response.errors);
      setEnrichmentMessage(
        failed.length
          ? `Some lookups reported errors: ${failed.join('; ')}`
          : `Checked ${response.queried ?? 0} indicators; ${response.success ?? 0} lookups succeeded.`
      );
    } catch (err) {
      setEnrichmentMessage(err instanceof ApiError ? err.message : 'Enrichment failed.');
    } finally { setEnriching(false); }
  };

  const handleRunPipeline = async () => {
    setRunningPipeline(true);
    try {
      await api.runPipeline(incidentId);
      await loadDetail();
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Analysis failed.');
    } finally { setRunningPipeline(false); }
  };

  const canEnrich = Boolean(detail?.incident.indicators.length);
  const canRunPipeline = detail && detail.pipeline_stage !== 'Completed' && detail.status !== 'Resolved';

  return (
    <>
      <Header
        pageTitle="Incident Details"
        pageSubtitle="Evidence-backed analysis and response recommendations."
        rightContent={detail ? <StatusBadge status={detail.status} /> : undefined}
      />
      <main className="detail-page page-enter">
        <Link className="incident-back-link" to="/incidents"><ArrowLeft size={15} /> All incidents</Link>

        {loading && !detail && (
          <div className="detail-state"><LoaderCircle size={22} className="spin-icon" /><span>Loading incident details…</span></div>
        )}
        {error && (
          <div className="incident-inline-error detail-error" role="alert">
            <AlertTriangle size={18} />
            <span>{error}</span>
            <button className="detail-retry" onClick={() => void loadDetail()}>
              <RefreshCw size={15} /> Retry
            </button>
          </div>
        )}

        {detail && (
          <>
            {/* ── Hero ── */}
            <section className="detail-hero-card">
              <div className="detail-hero-content">
                <span className="detail-kicker">INVESTIGATION</span>
                <h2>{detail.summary.title}</h2>
                <p>{detail.incident.description}</p>
                <div className="detail-hero-meta">
                  <code>{detail.incident.incident_id}</code>
                  <SeverityBadge severity={detail.summary.severity} />
                  <StatusBadge status={detail.status} />
                  <span className="detail-pipeline-stage">{prettyStatus(detail.pipeline_stage)}</span>
                </div>
              </div>
              <div className="detail-hero-actions">
                <button
                  className="detail-secondary-button"
                  disabled={!canEnrich || enriching}
                  onClick={() => void handleEnrich()}
                >
                  <Sparkles size={15} />
                  {enriching ? 'Checking sources…' : 'Enrich with threat intel'}
                </button>
                <button
                  className="detail-secondary-button"
                  disabled={!canRunPipeline || runningPipeline}
                  onClick={() => void handleRunPipeline()}
                >
                  <Activity size={15} />
                  {runningPipeline ? 'Running…' : 'Run analysis'}
                </button>
                <button
                  className="detail-secondary-button"
                  onClick={() => void loadDetail()}
                  title="Refresh incident data"
                >
                  <RefreshCw size={15} />
                </button>
              </div>
              {enrichmentMessage && (
                <div className="enrichment-message">{enrichmentMessage}</div>
              )}
            </section>

            {/* ── Pipeline Stepper ── */}
            <PipelineStepper currentTab={tab} onTabChange={setTab} detail={detail} />

            {/* ── Tab Content ── */}
            <div className="tab-panel">
              {tab === 'agents'   && <AgentsTab detail={detail} />}
              {tab === 'state'    && <SharedStateTab detail={detail} />}
              {tab === 'recovery' && <RecoveryTab detail={detail} onRefresh={loadDetail} />}
              {tab === 'policy'   && <PolicyTab detail={detail} onRefresh={loadDetail} />}
              {tab === 'report'   && <ReportTab detail={detail} incidentId={incidentId} />}
            </div>
          </>
        )}
      </main>
    </>
  );
};
