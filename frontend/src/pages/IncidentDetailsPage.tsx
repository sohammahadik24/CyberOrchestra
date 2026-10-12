import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { Link, useParams } from 'react-router-dom';
import { Activity, AlertTriangle, ArrowLeft, CheckCircle2, Circle, FileText, LoaderCircle, RefreshCw, Sparkles, XCircle } from 'lucide-react';
import { Header } from '../components/layout/Header';
import { SeverityBadge, StatusBadge } from '../components/ui/Badges';
import { api, ApiError } from '../services/api';
import type { IncidentDetail } from '../types';

type ResultTab = 'overview' | 'findings' | 'response' | 'report';
type AnyRecord = Record<string, any>;

const agentDefinitions = [
  { key: 'threat_detection_result', title: 'Threat Detection', stage: 'Threat Detection Agent', purpose: 'Classifies the incident and explains the evidence behind that assessment.' },
  { key: 'malware_analysis_result', title: 'Malware Analysis', stage: 'Malware Analysis Agent', purpose: 'Reviews malware indicators and observed or suspected behavior.' },
  { key: 'log_analysis_result', title: 'Log Analysis', stage: 'Log Analysis Agent', purpose: 'Correlates suspicious events and timelines from supplied logs.' },
  { key: 'vulnerability_assessment_result', title: 'Vulnerability Assessment', stage: 'Vulnerability Assessment Agent', purpose: 'Reviews supplied vulnerability information and related CVEs.' },
] as const;

const stagePlan = [
  { names: ['Data Normalizer'], title: 'Incident normalization', parallel: false },
  { names: ['Threat Intelligence Enrichment'], title: 'Threat intelligence', parallel: false },
  { names: ['Threat Detection Agent'], title: 'Threat detection', parallel: false },
  { names: ['Malware Analysis Agent', 'Log Analysis Agent', 'Vulnerability Assessment Agent'], title: 'Parallel analysis agents', parallel: true },
  { names: ['Shared Incident State'], title: 'Evidence validation', parallel: false },
  { names: ['Recovery Planning Agent'], title: 'Recovery planning', parallel: false },
  { names: ['Deterministic Policy Engine'], title: 'Policy review', parallel: false },
  { names: ['Report Generation Agent'], title: 'Final report', parallel: false },
];

const asList = (value: unknown): any[] => Array.isArray(value) ? value : [];
const prettyStatus = (value: unknown) => typeof value === 'string' ? value.replaceAll('_', ' ').replace(/^./, (letter) => letter.toUpperCase()) : 'Not available';
const citations = (ids: unknown) => asList(ids).map(String);

const EvidenceRefs: React.FC<{ ids: unknown }> = ({ ids }) => {
  const list = citations(ids);
  if (!list.length) return <span className="detail-muted">No evidence IDs cited.</span>;
  return <div className="evidence-ref-list">{list.map((id) => <span className="evidence-ref" key={id}>{id}</span>)}</div>;
};

const FindingList: React.FC<{ items: unknown; empty: string }> = ({ items, empty }) => {
  const list = asList(items);
  if (!list.length) return <p className="detail-muted">{empty}</p>;
  return <ul className="detail-bullets">{list.map((item, index) => <li key={index}>{typeof item === 'string' ? item : <>{item.finding ?? item.event ?? JSON.stringify(item)}{item.status && <span className="finding-status"> · {prettyStatus(item.status)}</span>}</>}{item.supporting_evidence_ids && <EvidenceRefs ids={item.supporting_evidence_ids} />}</li>)}</ul>;
};

export const IncidentDetailsPage: React.FC = () => {
  const { incidentId = '' } = useParams();
  const [detail, setDetail] = useState<IncidentDetail | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [tab, setTab] = useState<ResultTab>('overview');
  const [enriching, setEnriching] = useState(false);
  const [enrichmentMessage, setEnrichmentMessage] = useState<string | null>(null);

  const loadDetail = useCallback(async () => {
    setLoading(true);
    setError(null);
    try { setDetail(await api.getIncident(incidentId)); }
    catch (err) { setError(err instanceof ApiError ? err.message : 'Incident details could not be loaded.'); }
    finally { setLoading(false); }
  }, [incidentId]);

  useEffect(() => { void loadDetail(); }, [loadDetail]);

  const state = detail?.state as AnyRecord | null | undefined;
  const history = detail?.execution_history ?? [];
  const stageGroups = useMemo(() => stagePlan.map((step) => {
    const matches = history.filter((entry) => step.names.includes(entry.stage));
    const current = detail?.pipeline_stage?.toLowerCase().replace(/[_-]/g, ' ') ?? '';
    const currentlyRunning = !['completed', 'error', 'normalized'].includes(current) &&
      (step.title.toLowerCase().includes(current) || step.names.some((name) => name.toLowerCase().includes(current)));
    const stageStatus = matches.some((entry) => entry.status === 'error') ? 'error' :
      matches.some((entry) => entry.status === 'running') ? 'running' :
      matches.length && matches.every((entry) => entry.status === 'skipped') ? 'skipped' :
      matches.length && matches.every((entry) => entry.status === 'completed' || entry.status === 'skipped') ? 'completed' :
      detail?.pipeline_stage === 'Completed' ? 'unreported' : currentlyRunning ? 'running' : 'pending';
    return { ...step, matches, status: stageStatus };
  }), [history, detail?.pipeline_stage]);
  const evidence = detail?.incident.evidence ?? [];
  const intelEvidence = evidence.filter((item) => /abuseipdb|urlhaus|nvd|mitre|threat.?intel|reputation|vulnerability intelligence/i.test(item.source + ' ' + item.evidence_type));
  const confidence = state?.threat_detection_result?.confidence;
  const classification = state?.threat_detection_result?.threat_classification;
  const canEnrich = Boolean(detail?.incident.indicators.length);

  const handleEnrich = async () => {
    setEnriching(true); setEnrichmentMessage(null);
    try {
      const response = await api.enrichIncident(incidentId);
      await loadDetail();
      const failed = asList(response.errors);
      setEnrichmentMessage(failed.length ? `Some lookups reported errors: ${failed.join('; ')}` : `Threat intelligence checked ${response.queried ?? 0} supported indicators; ${response.success ?? 0} lookups succeeded.`);
    } catch (err) {
      setEnrichmentMessage(err instanceof ApiError ? err.message : 'Threat intelligence enrichment failed.');
    } finally { setEnriching(false); }
  };

  const tabs: { key: ResultTab; label: string }[] = [
    { key: 'overview', label: 'Overview' }, { key: 'findings', label: 'Agent findings' },
    { key: 'response', label: 'Recovery & policy' }, { key: 'report', label: 'Final report' },
  ];

  return (
    <>
      <Header pageTitle="Incident Details" pageSubtitle="Evidence-backed analysis and response recommendations." rightContent={detail && <StatusBadge status={detail.status} />} />
      <main className="incident-screen detail-screen">
        <Link className="incident-back-link" to="/incidents"><ArrowLeft size={15} /> All incidents</Link>
        {loading && !detail && <div className="detail-state"><LoaderCircle size={22} className="spin-icon" /><span>Loading incident details…</span></div>}
        {error && <div className="incident-inline-error detail-error" role="alert"><AlertTriangle size={18} /><span>{error}</span><button className="detail-retry" onClick={() => void loadDetail()}><RefreshCw size={15} /> Retry</button></div>}
        {detail && (
          <>
            <section className="detail-hero">
              <div className="detail-hero-main"><span className="detail-kicker">INVESTIGATION</span><h2>{detail.summary.title}</h2><p>{detail.incident.description}</p><div className="detail-hero-meta"><code>{detail.incident.incident_id}</code><SeverityBadge severity={detail.summary.severity} /><StatusBadge status={detail.status} /></div></div>
              <div className="detail-hero-actions"><button className="detail-secondary-button" disabled={!canEnrich || enriching} onClick={() => void handleEnrich()}><Sparkles size={15} />{enriching ? 'Checking sources…' : 'Enrich with threat intelligence'}</button><button className="incident-primary" disabled={detail.status === 'Resolved' || detail.pipeline_stage === 'Completed'} onClick={async () => { try { await api.runPipeline(incidentId); await loadDetail(); } catch (err) { setError(err instanceof ApiError ? err.message : 'Analysis failed.'); } }}><Activity size={16} /> Run analysis</button></div>
            </section>
            {detail.status === 'Error' && <div className="incident-inline-error"><AlertTriangle size={16}/><span>Pipeline failed. The API did not return an error-stage record; any recorded agent errors are shown under Agent findings.</span></div>}

            <section className="detail-workflow-card">
              <div className="detail-section-heading"><div><h3>Analysis progress</h3><p>Pipeline status reported by the backend. The three specialist agents run in parallel.</p></div><span className="detail-current-stage">{prettyStatus(detail.pipeline_stage)}</span></div>
              <div className="detail-stage-grid">
                {stageGroups.map((step) => <div className={`detail-stage stage-${step.status}`} key={step.title}>
                  <span className="stage-state-icon">{step.status === 'completed' ? <CheckCircle2 size={17} /> : step.status === 'error' ? <XCircle size={17} /> : step.status === 'running' ? <LoaderCircle size={17} className="spin-icon" /> : <Circle size={16} />}</span>
                  <div><strong>{step.title}</strong>{step.parallel && <small>Runs in parallel</small>}<span>{step.matches.length ? step.matches.map((match) => `${match.stage}: ${prettyStatus(match.status)}`).join(' · ') : detail.pipeline_stage === 'Completed' ? 'No stage record returned' : detail.pipeline_stage === 'Normalized' ? 'Pending' : 'Waiting for execution history'}</span></div>
                </div>)}
              </div>
              <p className="plain-note">Execution history is recorded after the synchronous pipeline request finishes. The current stage above is the live value returned by the incident detail endpoint.</p>
            </section>

            <section className="detail-content-card">
              <nav className="detail-tabs" aria-label="Incident detail sections">{tabs.map((item) => <button key={item.key} className={tab === item.key ? 'active' : ''} onClick={() => setTab(item.key)}>{item.label}</button>)}</nav>
              {tab === 'overview' && <div className="detail-tab-content">
                <div className="detail-overview-grid">
                  <article className="detail-metric"><span>Incident ID</span><strong className="detail-id">{detail.incident.incident_id}</strong></article>
                  <article className="detail-metric"><span>Severity</span><strong><SeverityBadge severity={detail.summary.severity} /></strong></article>
                  <article className="detail-metric"><span>Threat classification</span><strong>{classification ? prettyStatus(classification) : 'Not assessed yet'}</strong></article>
                  <article className="detail-metric"><span>Assessment confidence</span><strong>{typeof confidence === 'number' ? `${Math.round(confidence * 100)}%` : 'Not available'}</strong></article>
                </div>
                <div className="detail-section"><div className="detail-section-heading"><div><h3>Incident information</h3><p>Normalized input received by CyberOrchestra</p></div></div><dl className="incident-definition-list"><div><dt>Category</dt><dd>{detail.incident.incident_type}</dd></div><div><dt>Submitted by</dt><dd>{detail.incident.source}</dd></div><div><dt>Received</dt><dd>{detail.incident.timestamp ? new Date(detail.incident.timestamp).toLocaleString() : 'Not recorded'}</dd></div></dl></div>
                <div className="detail-section"><div className="detail-section-heading"><div><h3>Submitted evidence</h3><p>Source material provided with this incident</p></div></div><EvidenceList items={evidence.filter((item) => !intelEvidence.includes(item))} empty="No submitted evidence was included." /></div>
              </div>}

              {tab === 'findings' && <div className="detail-tab-content">
                {agentDefinitions.map((agent) => {
                  const result = state?.[agent.key] as AnyRecord | undefined;
                  const execution = history.find((item) => item.stage === agent.stage);
                  return <article className="agent-finding" key={agent.key}>
                    <div className="agent-finding-heading"><div><h3>{agent.title}</h3><p>{agent.purpose}</p></div><span className={`stage-status-badge status-${execution?.status ?? (result ? 'completed' : 'pending')}`}>{execution ? prettyStatus(execution.status) : result ? 'Completed' : detail.pipeline_stage === 'Completed' ? 'No result' : 'Pending'}</span></div>
                    {!result ? <p className="detail-muted">{execution?.details ?? (detail.pipeline_stage === 'Completed' ? 'The backend did not return a result for this agent.' : 'This agent has not returned a result yet.')}</p> : <AgentResultView kind={agent.key} result={result} />}
                    {execution?.status === 'error' && <div className="agent-error"><AlertTriangle size={15} />{execution.details || 'The backend reported an execution error.'}</div>}
                    {execution?.confidence != null && <small className="agent-confidence">Execution confidence: {execution.confidence}%</small>}
                  </article>;
                })}
              </div>}

              {tab === 'response' && <div className="detail-tab-content">
                <div className="detail-section"><div className="detail-section-heading"><div><h3>Threat intelligence</h3><p>Evidence returned by supported reputation and knowledge sources</p></div><button className="detail-secondary-button" disabled={!canEnrich || enriching} onClick={() => void handleEnrich()}><Sparkles size={14} />{enriching ? 'Checking…' : 'Check sources'}</button></div>{enrichmentMessage && <div className="enrichment-message">{enrichmentMessage}</div>}<EvidenceList items={intelEvidence} empty={canEnrich ? 'No intelligence evidence is attached yet. Use “Check sources” to query configured services.' : 'No supported indicators were provided for intelligence lookup.'} /></div>
                <div className="detail-section"><div className="detail-section-heading"><div><h3>Recommended recovery actions</h3><p>Suggestions for an analyst to review. Nothing is executed from this page.</p></div></div>{detail.recovery_plan ? <RecoveryList plan={detail.recovery_plan as AnyRecord} /> : <p className="detail-muted">No recovery plan has been returned yet.</p>}</div>
                <div className="detail-section"><div className="detail-section-heading"><div><h3>Deterministic policy decisions</h3><p>Rule-engine decision and human approval state are shown separately.</p></div></div>{detail.policy_reviews.length ? <PolicyList items={detail.policy_reviews as unknown as AnyRecord[]} /> : <p className="detail-muted">No policy decisions have been returned yet.</p>}</div>
              </div>}

              {tab === 'report' && <div className="detail-tab-content">
                {!detail.report ? <div className="detail-empty"><FileText size={24} /><strong>Final report is not available yet</strong><span>The report appears here after report generation completes.</span></div> : <ReportView report={detail.report as AnyRecord} />}
              </div>}
            </section>
          </>
        )}
      </main>
    </>
  );
};

const EvidenceList: React.FC<{ items: IncidentDetail['incident']['evidence']; empty: string }> = ({ items, empty }) => !items.length ? <p className="detail-muted">{empty}</p> : <div className="detail-evidence-list">{items.map((item) => <article className="detail-evidence" key={item.evidence_id}><div className="evidence-topline"><code>{item.evidence_id}</code><span>{prettyStatus(item.evidence_type)}</span></div><p>{item.description}</p><div className="evidence-source">Source: {item.source}{item.timestamp && ` · ${new Date(item.timestamp).toLocaleString()}`}</div></article>)}</div>;

const AgentResultView: React.FC<{ kind: string; result: AnyRecord }> = ({ kind, result }) => {
  if (kind === 'threat_detection_result') return <><div className="agent-result-callout"><strong>{prettyStatus(result.threat_classification)}</strong><span>Severity: {prettyStatus(result.severity)} · Confidence: {Math.round((result.confidence ?? 0) * 100)}%</span></div><p>{result.reasoning}</p><FindingList items={result.observed_facts} empty="No observed facts returned."/><h4>Inferences</h4><FindingList items={result.inferences} empty="No inferences returned."/><EvidenceRefs ids={result.supporting_evidence_ids}/><UncertaintyList items={result.uncertainties}/></>;
  if (kind === 'malware_analysis_result') return <><div className="agent-result-callout"><strong>{result.malware_detected ? 'Malware detected' : 'No malware detected'}</strong><span>Confidence: {Math.round((result.confidence ?? 0) * 100)}%{result.suspected_family ? ` · Suspected family: ${result.suspected_family}` : ''}</span></div><h4>Behavioral findings</h4><FindingList items={result.behavioral_findings} empty="No behavioral findings returned."/><h4>Indicators</h4><FindingList items={result.indicators?.map((item: AnyRecord) => ({ finding: `${item.indicator_type}: ${item.value}`, supporting_evidence_ids: item.supporting_evidence_ids })) ?? []} empty="No malware indicators returned."/><EvidenceRefs ids={result.supporting_evidence_ids}/><UncertaintyList items={result.uncertainties}/></>;
  if (kind === 'log_analysis_result') return <><div className="agent-result-callout"><strong>Log severity: {prettyStatus(result.severity)}</strong><span>Confidence: {Math.round((result.confidence ?? 0) * 100)}%</span></div><h4>Suspicious events</h4><FindingList items={result.suspicious_events} empty="No suspicious events returned."/><h4>Timeline</h4><FindingList items={result.timeline_findings?.map((item: AnyRecord) => ({ ...item, finding: item.timestamp ? `${item.timestamp}: ${item.event}` : item.event }))} empty="No timeline findings returned."/><EvidenceRefs ids={result.supporting_evidence_ids}/><UncertaintyList items={result.uncertainties}/></>;
  return <><div className="agent-result-callout"><strong>Vulnerability severity: {prettyStatus(result.severity)}</strong><span>Confidence: {Math.round((result.confidence ?? 0) * 100)}%</span></div><p>{result.exploitability_assessment}</p><h4>Vulnerabilities</h4><FindingList items={result.vulnerabilities} empty="No vulnerabilities identified in the supplied input."/><h4>Affected assets</h4><FindingList items={result.affected_assets} empty="No affected assets returned."/><EvidenceRefs ids={result.supporting_evidence_ids}/><UncertaintyList items={result.uncertainties}/></>;
};

const UncertaintyList: React.FC<{ items: unknown }> = ({ items }) => <div className="uncertainty-block"><h4>Uncertainties</h4><FindingList items={items} empty="No uncertainties were reported by this agent."/></div>;

const RecoveryList: React.FC<{ plan: AnyRecord }> = ({ plan }) => {
  const actions = asList(plan.recovery_actions);
  return <>{actions.length ? actions.map((action, index) => <article className="response-item" key={index}><div className="response-title"><span className="recommendation-index">{index + 1}</span><div><strong>{action.recovery_action}</strong><span className="stage-status-badge">{prettyStatus(action.action_priority)} priority</span></div></div><p>{action.rationale}</p><div className="response-detail"><b>Expected outcome</b><span>{action.expected_outcome}</span></div>{asList(action.risks).length > 0 && <div className="response-detail"><b>Risks</b><span>{asList(action.risks).join('; ')}</span></div>}<div className="response-detail"><b>Supporting evidence</b><EvidenceRefs ids={action.supporting_evidence_ids}/></div></article>) : <p className="detail-muted">The recovery plan contains no recommended actions.</p>}<UncertaintyList items={plan.uncertainties}/></>;
};

const PolicyList: React.FC<{ items: AnyRecord[] }> = ({ items }) => <div className="detail-evidence-list">{items.map((item) => <article className="policy-item" key={item.id}><div className="policy-item-head"><strong>{item.action}</strong><span className={`stage-status-badge policy-${String(item.decision).toLowerCase()}`}>{prettyStatus(item.decision)}</span></div><p>{item.reason}</p><div className="policy-meta"><span>Rule: <code>{item.policy_rule_id}</code></span><span>Human approval: <b>{item.status ?? 'Not recorded'}</b></span></div><EvidenceRefs ids={item.supporting_evidence_ids}/></article>)}</div>;

const ReportView: React.FC<{ report: AnyRecord }> = ({ report }) => {
  const sections = [
    ['Threat assessment', report.threat_assessment], ['Malware findings', report.malware_findings],
    ['Log findings', report.log_findings], ['Vulnerability findings', report.vulnerability_findings],
  ] as const;
  return <div className="final-report"><div className="report-summary"><span>FINAL RISK: {prettyStatus(report.final_risk_level)}</span><p>{report.executive_summary?.finding ?? 'No executive summary was returned.'}</p><EvidenceRefs ids={report.executive_summary?.supporting_evidence_ids}/></div>{sections.map(([title, items]) => <section className="detail-section" key={title}><h3>{title}</h3><FindingList items={items} empty="No findings returned in this section."/></section>)}<section className="detail-section"><h3>Recovery recommendations in report</h3>{asList(report.recovery_recommendations).length ? <RecoveryList plan={{ recovery_actions: report.recovery_recommendations, uncertainties: [] }} /> : <p className="detail-muted">No recommendations included in the report.</p>}</section><section className="detail-section"><h3>Policy decisions in report</h3>{asList(report.policy_decisions).length ? <PolicyList items={report.policy_decisions} /> : <p className="detail-muted">No policy decisions included in the report.</p>}</section><section className="detail-section"><h3>Evidence summary</h3>{asList(report.evidence_summary).length ? asList(report.evidence_summary).map((item) => <p className="report-evidence" key={item.evidence_id}><code>{item.evidence_id}</code> {item.summary}</p>) : <p className="detail-muted">No evidence summary returned.</p>}</section><section className="detail-section"><h3>Report uncertainties</h3><FindingList items={report.uncertainties} empty="No report uncertainties returned."/></section></div>;
};
