import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { Activity, AlertCircle, ArrowRight, Bug, CheckCircle2, CircleDashed, FileText, LoaderCircle, Network, RefreshCw, Shield, ShieldAlert, Workflow, X } from 'lucide-react';
import { Header } from '../components/layout/Header';
import { api, ApiError } from '../services/api';
import type { AgentStage, Incident, IncidentDetail, PipelineStageExecution } from '../types';
import './AgentMonitorPage.css';

type RecordValue = Record<string, unknown>;
type StatusLabel = 'Completed' | 'Running' | 'Failed' | 'Not Started';

const definitions = [
  { id: 'threat-detection', name: 'Threat Detection', purpose: 'Classifies the incident and estimates severity.', stage: 'Threat Detection Agent', path: 'threat_detection_result', icon: ShieldAlert },
  { id: 'malware-analysis', name: 'Malware Analysis', purpose: 'Examines supplied malware indicators and evidence.', stage: 'Malware Analysis Agent', path: 'malware_analysis_result', icon: Bug },
  { id: 'log-analysis', name: 'Log Analysis', purpose: 'Identifies suspicious events and timeline patterns.', stage: 'Log Analysis Agent', path: 'log_analysis_result', icon: Activity },
  { id: 'vuln-assessment', name: 'Vulnerability Assessment', purpose: 'Evaluates supplied CVE and vulnerability evidence.', stage: 'Vulnerability Assessment Agent', path: 'vulnerability_assessment_result', icon: Shield },
  { id: 'recovery-planning', name: 'Recovery Planning', purpose: 'Recommends recovery actions for analyst review.', stage: 'Recovery Planning Agent', path: 'recovery_plan', icon: Workflow },
  { id: 'report-generation', name: 'Report Generation', purpose: 'Compiles the final incident report.', stage: 'Report Generation Agent', path: 'report', icon: FileText },
] as const;

const record = (value: unknown): RecordValue | null =>
  value !== null && typeof value === 'object' && !Array.isArray(value) ? value as RecordValue : null;
const list = (value: unknown): unknown[] => Array.isArray(value) ? value : [];
const text = (value: unknown): string | null => typeof value === 'string' && value.trim() ? value : null;
const findStage = (history: PipelineStageExecution[], name: string) => history.find((stage) => stage.stage === name);
const statusOf = (stage?: PipelineStageExecution): StatusLabel => {
  if (stage?.status === 'completed') return 'Completed';
  if (stage?.status === 'running') return 'Running';
  if (stage?.status === 'error') return 'Failed';
  return 'Not Started';
};
const statusSlug = (value: StatusLabel) => value.toLowerCase().replace(' ', '-');

function resultFor(detail: IncidentDetail | null, path: string): unknown {
  if (!detail) return null;
  if (path === 'recovery_plan') return detail.recovery_plan;
  if (path === 'report') return detail.report;
  return record(detail.state)?.[path] ?? null;
}

function evidenceIds(value: unknown): string[] {
  const ids = new Set<string>();
  const visit = (entry: unknown): void => {
    if (Array.isArray(entry)) { entry.forEach(visit); return; }
    const object = record(entry);
    if (!object) return;
    list(object.supporting_evidence_ids).forEach((id) => { if (typeof id === 'string') ids.add(id); });
    Object.values(object).forEach(visit);
  };
  visit(value);
  return [...ids];
}

function summaryFor(id: string, result: RecordValue): string | null {
  if (id === 'threat-detection') return [text(result.threat_classification), text(result.severity)].filter(Boolean).join(' / ') || null;
  if (id === 'malware-analysis') return result.malware_detected === true ? 'Malware detected' : result.malware_detected === false ? 'No malware detected' : null;
  if (id === 'log-analysis') return text(result.severity) ? 'Log severity: ' + String(result.severity) : null;
  if (id === 'vuln-assessment') return text(result.severity) ? 'Assessment severity: ' + String(result.severity) : null;
  if (id === 'recovery-planning') return list(result.recovery_actions).length + ' recommended actions';
  return text(record(result.executive_summary)?.finding);
}

const EvidenceIds: React.FC<{ ids: unknown }> = ({ ids }) => {
  const values = list(ids).filter((value): value is string => typeof value === 'string');
  return values.length
    ? <div className="am-evidence-ids">{values.map((id) => <code key={id}>{id}</code>)}</div>
    : <p className="am-muted">No evidence IDs cited.</p>;
};

const FindingList: React.FC<{ title: string; items: unknown; empty?: string }> = ({ title, items, empty = 'None recorded.' }) => {
  const values = list(items);
  return <section className="am-result-section">
    {title && <h4>{title}</h4>}
    {values.length ? <ul>{values.map((value, index) => {
      const item = record(value);
      const finding = typeof value === 'string' ? value :
        text(item?.finding) || text(item?.event) || text(item?.recovery_action) || text(item?.value) || 'Recorded result';
      const when = text(item?.timestamp);
      const extra = text(item?.rationale) || text(item?.expected_outcome);
      return <li key={index}>
        <span>{when ? when + ': ' : ''}{finding}</span>
        {text(item?.status) && <small>{String(item?.status).replaceAll('_', ' ')}</small>}
        {extra && <p>{extra}</p>}
        {list(item?.risks).length > 0 && <p>Risks: {list(item?.risks).map(String).join('; ')}</p>}
        {list(item?.supporting_evidence_ids).length > 0 && <EvidenceIds ids={item?.supporting_evidence_ids} />}
      </li>;
    })}</ul> : <p className="am-muted">{empty}</p>}
  </section>;
};

const Findings: React.FC<{ id: string; result: RecordValue }> = ({ id, result }) => {
  const confidence = typeof result.confidence === 'number' && Number.isFinite(result.confidence)
    ? Math.round(result.confidence * 100) + '%' : null;
  return <div className="am-findings-content">
    {summaryFor(id, result) && <div className="am-result-summary"><strong>{summaryFor(id, result)}</strong>{confidence && <span>Confidence: {confidence}</span>}</div>}
    {id === 'threat-detection' && <>
      <FindingList title="Reasoning" items={result.reasoning ? [result.reasoning] : []} />
      <FindingList title="Observed facts" items={result.observed_facts} />
      <FindingList title="Inferences" items={result.inferences} />
      <FindingList title="Related techniques" items={result.mitre_techniques} />
      <FindingList title="Related vulnerabilities" items={result.related_cves} />
    </>}
    {id === 'malware-analysis' && <>
      <FindingList title="Behavioral findings" items={result.behavioral_findings} />
      <FindingList title="Indicators" items={list(result.indicators).map((value) => {
        const item = record(value); return item ? { ...item, finding: [item.indicator_type, item.value].filter(Boolean).join(': ') } : value;
      })} />
      {text(result.suspected_family) && <p className="am-muted">Suspected family: {String(result.suspected_family)}</p>}
    </>}
    {id === 'log-analysis' && <>
      <FindingList title="Suspicious events" items={result.suspicious_events} />
      <FindingList title="Timeline" items={list(result.timeline_findings).map((value) => {
        const item = record(value); return item ? { ...item, event: [item.timestamp, item.event].filter(Boolean).join(' / ') } : value;
      })} />
      <FindingList title="Attack indicators" items={list(result.attack_indicators).map((value) => {
        const item = record(value); return item ? { ...item, finding: [item.indicator_type, item.value].filter(Boolean).join(': ') } : value;
      })} />
    </>}
    {id === 'vuln-assessment' && <>
      <FindingList title="Vulnerabilities" items={result.vulnerabilities} />
      <FindingList title="Related CVEs" items={result.related_cves} />
      <FindingList title="Affected assets" items={result.affected_assets} />
      <FindingList title="Exploitability assessment" items={result.exploitability_assessment ? [result.exploitability_assessment] : []} />
    </>}
    {id === 'recovery-planning' && <FindingList title="Recommended actions" items={result.recovery_actions} />}
    {id === 'report-generation' && <>
      <FindingList title="Executive summary" items={record(result.executive_summary)?.finding ? [record(result.executive_summary)?.finding] : []} />
      <FindingList title="Threat findings" items={result.threat_assessment} />
      <FindingList title="Malware findings" items={result.malware_findings} />
      <FindingList title="Log findings" items={result.log_findings} />
      <FindingList title="Vulnerability findings" items={result.vulnerability_findings} />
      <FindingList title="Recommendations" items={result.recovery_recommendations} />
      <FindingList title="Policy decisions" items={result.policy_decisions} />
    </>}
    <section className="am-result-section"><h4>Supporting evidence</h4><EvidenceIds ids={evidenceIds(result)} /></section>
    <FindingList title="Uncertainties" items={result.uncertainties} empty="No uncertainties were returned." />
    <details className="am-raw"><summary>View raw result data</summary><pre>{JSON.stringify(result, null, 2)}</pre></details>
  </div>;
};

const WorkflowNode: React.FC<{ title: string; stage?: PipelineStageExecution; note?: string }> = ({ title, stage, note }) => {
  const state = statusOf(stage);
  return <div className={'am-flow-node' + (note ? ' am-flow-special' : '')}>
    <strong>{title}</strong>{note && <small>{note}</small>}
    <span className={'am-flow-state state-' + statusSlug(state)}>{state}</span>
  </div>;
};

export const AgentMonitorPage: React.FC = () => {
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [selectedId, setSelectedId] = useState('');
  const [detail, setDetail] = useState<IncidentDetail | null>(null);
  const [configured, setConfigured] = useState<AgentStage[]>([]);
  const [loading, setLoading] = useState(true);
  const [detailLoading, setDetailLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [detailError, setDetailError] = useState<string | null>(null);
  const [activeAgentId, setActiveAgentId] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true); setError(null);
    try {
      const [rows, agentRows] = await Promise.all([
        api.getIncidents(),
        api.getAgentsStatus().catch(() => [] as AgentStage[]),
      ]);
      setIncidents(rows); setConfigured(agentRows);
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Incidents could not be loaded.');
    } finally { setLoading(false); }
  }, []);

  const loadDetail = useCallback(async (id: string) => {
    setDetail(null); setActiveAgentId(null); setDetailError(null);
    if (!id) return;
    setDetailLoading(true);
    try { setDetail(await api.getIncident(id)); }
    catch (err) { setDetailError(err instanceof ApiError ? err.message : 'Incident analysis could not be loaded.'); }
    finally { setDetailLoading(false); }
  }, []);

  useEffect(() => { void load(); }, [load]);
  useEffect(() => { void loadDetail(selectedId); }, [loadDetail, selectedId]);

  const history = detail?.execution_history ?? [];
  const modelMap = useMemo(() => new Map(configured.map((agent) => [agent.id, agent.model])), [configured]);
  const activeAgent = definitions.find((agent) => agent.id === activeAgentId);
  const activeResult = activeAgent ? record(resultFor(detail, activeAgent.path)) : null;

  return <>
    <Header pageTitle="Agent Monitor" pageSubtitle="Understand each specialist's role and review the work recorded for an incident."
      rightContent={<button className="am-refresh" onClick={() => void load()} disabled={loading}><RefreshCw size={15} /> Refresh</button>} />
    <main className="agent-monitor page-enter">
      <section className="am-intro">
        <div><span className="am-eyebrow">INVESTIGATION WORKSPACE</span><h2>Follow the analysis, step by step</h2>
          <p>Choose an incident to see actual agent results and workflow stages saved by the backend.</p></div>
        <label className="am-picker"><span>Select incident</span>
          <select value={selectedId} onChange={(event) => setSelectedId(event.target.value)} disabled={loading || incidents.length === 0}>
            <option value="">Choose an incident</option>{incidents.map((incident) =>
              <option key={incident.id} value={incident.id}>{incident.id} / {incident.title}</option>)}
          </select>
        </label>
      </section>

      {error && <div className="am-message am-error" role="alert"><AlertCircle size={17} /><span>{error}</span><button onClick={() => void load()}>Try again</button></div>}
      {loading && <div className="am-message"><LoaderCircle size={17} className="am-spin" /> Loading incidents from the backend...</div>}
      {!loading && !error && incidents.length === 0 && <div className="am-empty"><CircleDashed size={25} /><strong>No incidents available yet</strong><span>Create or load an incident from Incidents to review agent analysis.</span></div>}

      <section className="am-section">
        <div className="am-section-heading"><div><h3>Six specialist agents</h3><p>Execution status and findings come from the selected incident's saved analysis.</p></div>
          {selectedId && <code>{selectedId}</code>}</div>
        {detailLoading && <div className="am-message"><LoaderCircle size={17} className="am-spin" /> Loading the selected incident's recorded analysis...</div>}
        {detailError && <div className="am-message am-error" role="alert"><AlertCircle size={17} /><span>{detailError}</span><button onClick={() => void loadDetail(selectedId)}>Retry details</button></div>}
        {!detailLoading && !detailError && <div className="am-agent-grid">
          {definitions.map((agent) => {
            const execution = findStage(history, agent.stage);
            const state = statusOf(execution);
            const result = resultFor(detail, agent.path);
            const hasResult = record(result) !== null;
            const failed = execution?.status === 'error';
            const model = execution?.model || modelMap.get(agent.id);
            const Icon = agent.icon;
            return <article className={'am-agent-card' + (activeAgentId === agent.id ? ' is-active' : '')} key={agent.id}>
              <div className="am-card-top"><span className="am-icon"><Icon size={18} /></span><span className={'am-status state-' + statusSlug(state)}><i />{state}</span></div>
              <h4>{agent.name}</h4><p className="am-purpose">{agent.purpose}</p>
              <div className="am-meta"><span>Model</span><strong title={model || undefined}>{model || 'Configuration unavailable'}</strong></div>
              {execution?.duration && <div className="am-meta"><span>Recorded duration</span><strong>{execution.duration}</strong></div>}
              {failed && <p className="am-failure">{execution?.details || 'An execution error was recorded.'}</p>}
              {(hasResult || failed) && <button className="am-findings-button" onClick={() => setActiveAgentId(agent.id)}>
                {failed && !hasResult ? 'View error details' : 'View findings'} <ArrowRight size={14} />
              </button>}
            </article>;
          })}
        </div>}
        {!selectedId && !loading && incidents.length > 0 && <div className="am-before-select"><CircleDashed size={17} />Choose an incident above to load its actual agent statuses and findings. No incident is selected yet.</div>}
      </section>

      {activeAgent && selectedId && !detailLoading && !detailError && <section className="am-findings" aria-live="polite">
        <div className="am-findings-heading"><div><span className="am-eyebrow">RECORDED OUTPUT / {selectedId}</span><h3>{activeAgent.name} findings</h3><p>{activeAgent.purpose}</p></div>
          <button className="am-close" onClick={() => setActiveAgentId(null)} aria-label="Close findings"><X size={18} /></button></div>
        {activeResult ? <Findings id={activeAgent.id} result={activeResult} /> :
          <div className="am-message">{findStage(history, activeAgent.stage)?.details || 'No result was stored for this agent in the selected incident.'}</div>}
      </section>}

      <section className="am-section am-workflow-section">
        <div className="am-section-heading"><div><h3>Investigation workflow</h3><p>Stage states are shown from the selected incident's stored execution history. The policy engine is deterministic, not an LLM agent.</p></div></div>
        {detail && <div className="am-recorded-note"><CheckCircle2 size={15} /> Recorded workflow for {detail.summary.id}. This page does not poll for live progress.</div>}
        <div className="am-flow-scroll"><div className="am-flow">
          <WorkflowNode title="Threat Detection" stage={findStage(history, 'Threat Detection Agent')} />
          <ArrowRight className="am-flow-arrow" size={17} />
          <div className="am-parallel"><span>Parallel analysis</span>{definitions.slice(1, 4).map((agent) =>
            <WorkflowNode key={agent.id} title={agent.name} stage={findStage(history, agent.stage)} />)}</div>
          <ArrowRight className="am-flow-arrow" size={17} />
          <WorkflowNode title="Shared Incident State" stage={findStage(history, 'Shared Incident State')} note="Infrastructure stage" />
          <ArrowRight className="am-flow-arrow" size={17} />
          <WorkflowNode title="Recovery Planning" stage={findStage(history, 'Recovery Planning Agent')} />
          <ArrowRight className="am-flow-arrow" size={17} />
          <WorkflowNode title="Policy Engine" stage={findStage(history, 'Deterministic Policy Engine')} note="Deterministic component; not an LLM agent" />
          <ArrowRight className="am-flow-arrow" size={17} />
          <WorkflowNode title="Report Generation" stage={findStage(history, 'Report Generation Agent')} />
        </div></div>
        <div className="am-workflow-notes"><span><Network size={14} /> Parallel findings are validated in shared incident state.</span><span><Shield size={14} /> Policy rules review proposed actions; they do not execute them.</span></div>
        {!selectedId && <p className="am-muted">Select an incident to see recorded workflow statuses. The diagram shows the configured order.</p>}
      </section>
      <p className="am-api-note">The backend does not expose per-agent execution timestamps. Last execution time is not available.</p>
    </main>
  </>;
};
