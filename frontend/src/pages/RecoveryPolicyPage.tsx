import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { AlertCircle, ArrowRight, CheckCircle2, Clock3, LoaderCircle, RefreshCw, ShieldCheck, ShieldX, UserRoundCheck } from 'lucide-react';
import { Link } from 'react-router-dom';
import { Header } from '../components/layout/Header';
import { api, ApiError } from '../services/api';
import type { Incident, IncidentDetail, PolicyReview } from '../types';
import './RecoveryPolicyPage.css';

type DataRecord = Record<string, unknown>;
type ReviewDecision = PolicyReview['decision'];

const asRecord = (value: unknown): DataRecord | null =>
  value !== null && typeof value === 'object' && !Array.isArray(value) ? value as DataRecord : null;
const asList = (value: unknown): unknown[] => Array.isArray(value) ? value : [];
const asText = (value: unknown): string | null => typeof value === 'string' && value.trim() ? value : null;
const getPolicyStage = (detail: IncidentDetail) => detail.execution_history.find((stage) => stage.stage === 'Deterministic Policy Engine');
const getRecoveryStage = (detail: IncidentDetail) => detail.execution_history.find((stage) => stage.stage === 'Recovery Planning Agent');
const decisionLabel = (decision: ReviewDecision) => String(decision).toUpperCase().replaceAll('_', ' ');

const EvidenceRefs: React.FC<{ ids: unknown }> = ({ ids }) => {
  const evidence = asList(ids).filter((item): item is string => typeof item === 'string');
  if (!evidence.length) return <span className="rp-muted">No evidence IDs returned.</span>;
  return <div className="rp-evidence">{evidence.map((id) => <code key={id}>{id}</code>)}</div>;
};

const Recommendations: React.FC<{ plan: DataRecord }> = ({ plan }) => {
  const actions = asList(plan.recovery_actions);
  if (!actions.length) return <div className="rp-empty-inline">No recovery recommendations were returned for this incident.</div>;
  return <div className="rp-recommendation-list">{actions.map((value, index) => {
    const action = asRecord(value) || {};
    const name = asText(action.recovery_action) || 'Recommendation details not provided';
    const priority = asText(action.action_priority);
    const risks = asList(action.risks).filter((item): item is string => typeof item === 'string');
    return <article className="rp-recommendation" key={index}>
      <div className="rp-action-heading"><span className="rp-step-number">{index + 1}</span><div><h4>{name}</h4>
        {priority && <span className={'rp-priority priority-' + priority.toLowerCase()}>{priority} priority</span>}
      </div></div>
      {asText(action.rationale) && <div className="rp-action-detail"><strong>Why it is recommended</strong><p>{String(action.rationale)}</p></div>}
      <div className="rp-action-detail"><strong>Supporting evidence</strong><EvidenceRefs ids={action.supporting_evidence_ids} /></div>
      {asText(action.expected_outcome) && <div className="rp-action-detail"><strong>Expected outcome</strong><p>{String(action.expected_outcome)}</p></div>}
      {risks.length > 0 && <div className="rp-action-detail"><strong>Risks to consider</strong><ul>{risks.map((risk) => <li key={risk}>{risk}</li>)}</ul></div>}
    </article>;
  })}</div>;
};

const DecisionCard: React.FC<{
  review: PolicyReview;
  loading: boolean;
  onApprove: () => void;
  onReject: () => void;
}> = ({ review, loading, onApprove, onReject }) => {
  const decision = decisionLabel(review.decision);
  const canReview = decision === 'REQUIRES APPROVAL' && review.status === 'Pending';
  const humanStatus = decision === 'REQUIRES APPROVAL'
    ? review.status === 'Pending' ? 'Waiting for analyst review' : 'Analyst ' + review.status.toLowerCase()
    : decision === 'APPROVED' ? 'Human review not required' : 'Blocked by policy; no action executed';
  return <article className={'rp-decision decision-' + decision.toLowerCase().replaceAll('_', '-')}>
    <header className="rp-decision-header">
      <span className={'rp-outcome outcome-' + decision.toLowerCase().replaceAll('_', '-')}>
        {decision === 'APPROVED' ? <CheckCircle2 size={15} /> : decision === 'REJECTED' ? <ShieldX size={15} /> : <Clock3 size={15} />}
        {decision}
      </span>
      <span className="rp-rule">Rule <code>{review.policy_rule_id || 'Not provided'}</code></span>
    </header>
    <h4>{review.action}</h4>
    <div className="rp-decision-reason"><strong>Why this decision was made</strong><p>{review.reason || 'No reason was returned.'}</p></div>
    <div className="rp-decision-evidence"><strong>Supporting evidence</strong><EvidenceRefs ids={review.supporting_evidence_ids} /></div>
    <div className="rp-human-status"><UserRoundCheck size={15} /><span><strong>Human review:</strong> {humanStatus}</span>
      {review.decided_at && decision === 'REQUIRES APPROVAL' && <time dateTime={review.decided_at}>{new Date(review.decided_at).toLocaleString()}</time>}
    </div>
    {review.analyst_notes && <p className="rp-analyst-notes">Analyst note: {review.analyst_notes}</p>}
    {canReview && <div className="rp-review-actions">
      <button type="button" className="rp-approve" disabled={loading} onClick={onApprove}>{loading ? <LoaderCircle size={14} className="rp-spin" /> : <CheckCircle2 size={14} />} Record approval</button>
      <button type="button" className="rp-reject" disabled={loading} onClick={onReject}>{loading ? <LoaderCircle size={14} className="rp-spin" /> : <ShieldX size={14} />} Record rejection</button>
    </div>}
  </article>;
};

export const RecoveryPolicyPage: React.FC = () => {
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [selectedId, setSelectedId] = useState('');
  const [detail, setDetail] = useState<IncidentDetail | null>(null);
  const [listLoading, setListLoading] = useState(true);
  const [detailLoading, setDetailLoading] = useState(false);
  const [listError, setListError] = useState<string | null>(null);
  const [detailError, setDetailError] = useState<string | null>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [actionLoading, setActionLoading] = useState<string | null>(null);

  const loadIncidents = useCallback(async () => {
    setListLoading(true); setListError(null);
    try { setIncidents(await api.getIncidents()); }
    catch (error) { setListError(error instanceof ApiError ? error.message : 'The incident list could not be loaded.'); }
    finally { setListLoading(false); }
  }, []);

  const loadDetail = useCallback(async (incidentId: string) => {
    setDetail(null); setDetailError(null); setActionError(null);
    if (!incidentId) return;
    setDetailLoading(true);
    try { setDetail(await api.getIncident(incidentId)); }
    catch (error) { setDetailError(error instanceof ApiError ? error.message : 'Incident recovery and policy data could not be loaded.'); }
    finally { setDetailLoading(false); }
  }, []);

  useEffect(() => { void loadIncidents(); }, [loadIncidents]);
  useEffect(() => { void loadDetail(selectedId); }, [loadDetail, selectedId]);

  const reviews = detail?.policy_reviews ?? [];
  const recoveryPlan = asRecord(detail?.recovery_plan);
  const actions = asList(recoveryPlan?.recovery_actions);
  const policyStage = detail ? getPolicyStage(detail) : undefined;
  const recoveryStage = detail ? getRecoveryStage(detail) : undefined;
  const grouped = useMemo(() => ({
    approved: reviews.filter((item) => decisionLabel(item.decision) === 'APPROVED').length,
    approval: reviews.filter((item) => decisionLabel(item.decision) === 'REQUIRES APPROVAL').length,
    rejected: reviews.filter((item) => decisionLabel(item.decision) === 'REJECTED').length,
  }), [reviews]);

  const submitReview = async (review: PolicyReview, outcome: 'approve' | 'reject') => {
    setActionLoading(review.id); setActionError(null);
    try {
      if (outcome === 'approve') await api.approvePolicyReview(review.id, 'Recorded by human analyst');
      else await api.rejectPolicyReview(review.id, 'Recorded by human analyst');
      await loadDetail(selectedId);
    } catch (error) {
      setActionError(error instanceof ApiError ? error.message : 'The analyst review could not be recorded.');
    } finally { setActionLoading(null); }
  };

  return <>
    <Header pageTitle="Recovery & Policy" pageSubtitle="Review recommended actions and the deterministic policy decision for each one."
      rightContent={<button type="button" className="rp-refresh" onClick={() => void loadIncidents()} disabled={listLoading}>
        {listLoading ? <LoaderCircle size={15} className="rp-spin" /> : <RefreshCw size={15} />} Refresh
      </button>} />
    <main className="recovery-policy-page page-enter">
      <section className="rp-intro">
        <div><span className="rp-eyebrow">ANALYST REVIEW</span><h2>Recommendations are reviewed, never executed here</h2>
          <p>The Recovery Planning Agent proposes actions from incident evidence. A separate deterministic Python policy engine evaluates each proposal against configured rules.</p></div>
        <label className="rp-picker"><span>Select incident</span><select value={selectedId} onChange={(event) => setSelectedId(event.target.value)} disabled={listLoading || incidents.length === 0}>
          <option value="">Choose an incident</option>{incidents.map((incident) => <option key={incident.id} value={incident.id}>{incident.id} / {incident.title}</option>)}
        </select></label>
      </section>

      {listError && <div className="rp-message rp-error" role="alert"><AlertCircle size={17} /><span>{listError}</span><button type="button" onClick={() => void loadIncidents()}>Try again</button></div>}
      {listLoading && <div className="rp-message"><LoaderCircle size={17} className="rp-spin" /> Loading incidents...</div>}
      {!listLoading && !listError && incidents.length === 0 && <div className="rp-empty"><ShieldCheck size={25} /><strong>No incidents are available</strong><span>Submit or load an incident before reviewing recommendations.</span><Link to="/incidents">Go to incidents <ArrowRight size={14} /></Link></div>}

      {selectedId && <section className="rp-workflow" aria-label="Recovery and policy workflow">
        <div className="rp-workflow-step"><span>1</span><strong>Recovery Planning Agent</strong><small>Proposes actions from evidence</small></div><ArrowRight size={16} />
        <div className="rp-workflow-step"><span>2</span><strong>Proposed actions</strong><small>Recommendations for review</small></div><ArrowRight size={16} />
        <div className="rp-workflow-step rp-deterministic"><span><ShieldCheck size={15} /></span><strong>Deterministic Policy Engine</strong><small>Python rules; not an LLM agent</small></div><ArrowRight size={16} />
        <div className="rp-workflow-step"><span>3</span><strong>Policy decisions</strong><small>Approved, requires approval, or rejected</small></div><ArrowRight size={16} />
        <div className="rp-workflow-step rp-human"><span><UserRoundCheck size={15} /></span><strong>Human analyst review</strong><small>Records decisions when required</small></div>
      </section>}

      {selectedId && detail && <div className="rp-selected-incident"><span>Selected incident</span><strong>{detail.summary.id}</strong><span>{detail.summary.title}</span></div>}
      {detailLoading && <div className="rp-message"><LoaderCircle size={17} className="rp-spin" /> Loading recovery recommendations and policy decisions...</div>}
      {detailError && <div className="rp-message rp-error" role="alert"><AlertCircle size={17} /><span>{detailError}</span><button type="button" onClick={() => void loadDetail(selectedId)}>Retry</button></div>}
      {actionError && <div className="rp-message rp-error" role="alert"><AlertCircle size={17} /><span>{actionError}</span></div>}

      {selectedId && detail && !detailLoading && !detailError && <>
        <section className="rp-section">
          <header className="rp-section-heading"><div><span className="rp-section-kicker">RECOMMENDATIONS</span><h3>Recovery plan</h3><p>Suggested steps based on this incident. No action has been carried out by this interface.</p></div>
            {actions.length > 0 && <span className="rp-count">{actions.length} {actions.length === 1 ? 'recommendation' : 'recommendations'}</span>}
          </header>
          {!recoveryPlan && <div className="rp-empty-inline">
            {recoveryStage?.status === 'error' ? 'Recovery planning failed: ' + (recoveryStage.details || 'the backend recorded an error.') :
              'No recovery plan is available. Run the incident analysis pipeline to request recommendations.'}
          </div>}
          {recoveryPlan && <Recommendations plan={recoveryPlan} />}
          {asList(recoveryPlan?.uncertainties).length > 0 && <details className="rp-uncertainties"><summary>Planning uncertainties</summary><ul>{asList(recoveryPlan?.uncertainties).map((item, index) => <li key={index}>{String(item)}</li>)}</ul></details>}
          {recoveryPlan && <p className="rp-not-executed"><ShieldCheck size={15} /> Recommendations are not executed, approved, or marked complete by displaying them here. Completion status is not tracked by this application.</p>}
        </section>

        <section className="rp-section">
          <header className="rp-section-heading"><div><span className="rp-section-kicker">DETERMINISTIC PYTHON COMPONENT</span><h3>Policy decisions</h3>
            <p>The policy engine evaluates each proposed action independently. It does not use an LLM.</p></div>
            {reviews.length > 0 && <span className="rp-count">{reviews.length} {reviews.length === 1 ? 'decision' : 'decisions'}</span>}
          </header>
          {reviews.length > 0 && <div className="rp-outcome-legend">
            <span><b className="legend-approved">APPROVED</b> permitted by configured policy ({grouped.approved})</span>
            <span><b className="legend-review">REQUIRES APPROVAL</b> analyst authorization needed ({grouped.approval})</span>
            <span><b className="legend-rejected">REJECTED</b> blocked by configured policy ({grouped.rejected})</span>
          </div>}
          {reviews.length > 0 && <div className="rp-decision-list">{reviews.map((review) =>
            <DecisionCard key={review.id} review={review} loading={actionLoading === review.id}
              onApprove={() => void submitReview(review, 'approve')} onReject={() => void submitReview(review, 'reject')} />)}</div>}
          {reviews.length === 0 && <div className="rp-empty-inline">
            {policyStage?.status === 'error' ? 'Policy evaluation failed: ' + (policyStage.details || 'the backend recorded an error.') :
              policyStage?.status === 'completed' ? actions.length === 0
                ? 'Policy evaluation completed; there were no proposed actions to evaluate.'
                : 'Policy evaluation is recorded as complete, but no decisions were returned.'
                : 'Policy evaluation has not run for this incident yet. Run the incident analysis pipeline to evaluate proposed actions.'}
          </div>}
        </section>
      </>}

      {!selectedId && !listLoading && incidents.length > 0 && <div className="rp-empty"><ShieldCheck size={25} /><strong>Choose an incident to begin</strong><span>This page will show only that incident's stored recovery plan and policy results.</span></div>}
      <p className="rp-safety-note">Human approval records a review decision only. This application does not execute recovery actions.</p>
    </main>
  </>;
};
