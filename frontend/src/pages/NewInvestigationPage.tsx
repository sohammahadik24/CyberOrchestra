import React, { useEffect, useState } from 'react';
import { Link, useNavigate } from 'react-router-dom';
import { ArrowLeft, ArrowRight, CheckCircle2, CircleAlert, ClipboardPaste, LoaderCircle, Play, RadioTower } from 'lucide-react';
import { Header } from '../components/layout/Header';
import { api, ApiError } from '../services/api';
import type { Incident, IncidentDetail, ScenarioItem } from '../types';

type InputMode = 'paste' | 'simulation';
type RunState = 'ready' | 'creating' | 'running' | 'failed';

const progressStages = [
  { label: 'Normalize incident', match: ['Normalization', 'Data Normalizer'] },
  { label: 'Threat intelligence', match: ['Threat Intelligence Enrichment'] },
  { label: 'Threat detection', match: ['Threat Detection Agent'] },
  { label: 'Parallel analysis agents', match: ['Malware Analysis Agent', 'Log Analysis Agent', 'Vulnerability Assessment Agent'], parallel: true },
  { label: 'Validate shared evidence', match: ['Shared Incident State'] },
  { label: 'Plan recovery', match: ['Recovery Planning Agent'] },
  { label: 'Review policy', match: ['Deterministic Policy Engine', 'Policy Review'] },
  { label: 'Generate final report', match: ['Report Generation Agent', 'Report Generation'] },
];

export const NewInvestigationPage: React.FC = () => {
  const navigate = useNavigate();
  const [mode, setMode] = useState<InputMode>('paste');
  const [title, setTitle] = useState('');
  const [description, setDescription] = useState('');
  const [incidentType, setIncidentType] = useState('');
  const [payloadText, setPayloadText] = useState('');
  const [scenarios, setScenarios] = useState<ScenarioItem[]>([]);
  const [selectedScenario, setSelectedScenario] = useState('');
  const [scenarioError, setScenarioError] = useState<string | null>(null);
  const [loadingScenarios, setLoadingScenarios] = useState(true);
  const [incidentId, setIncidentId] = useState<string | null>(null);
  const [liveDetail, setLiveDetail] = useState<IncidentDetail | null>(null);
  const [runState, setRunState] = useState<RunState>('ready');
  const [error, setError] = useState<string | null>(null);
  const [fieldError, setFieldError] = useState<string | null>(null);

  useEffect(() => {
    let active = true;
    api.getScenarios().then((items) => { if (active) setScenarios(items); })
      .catch((err: unknown) => { if (active) setScenarioError(err instanceof ApiError ? err.message : 'Could not load the available simulations.'); })
      .finally(() => { if (active) setLoadingScenarios(false); });
    return () => { active = false; };
  }, []);

  const executePipeline = async (id: string) => {
    setIncidentId(id);
    setRunState('running');
    setError(null);
    let active = true;
    const poll = window.setInterval(() => {
      void api.getIncident(id).then((detail) => { if (active) setLiveDetail(detail); }).catch(() => undefined);
    }, 1600);
    try {
      await api.runPipeline(id);
      active = false;
      window.clearInterval(poll);
      navigate(`/incidents/${encodeURIComponent(id)}`, { replace: true });
    } catch (err) {
      active = false;
      window.clearInterval(poll);
      setRunState('failed');
      setError(err instanceof ApiError ? err.message : 'Analysis could not be completed.');
      try { setLiveDetail(await api.getIncident(id)); } catch { /* Keep the pipeline error visible. */ }
    }
  };

  const validateAndBuildPayload = (): Record<string, unknown> | null => {
    setFieldError(null);
    let pasted: Record<string, unknown> = {};
    if (payloadText.trim()) {
      try {
        const parsed: unknown = JSON.parse(payloadText);
        if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) throw new Error('Paste a JSON object.');
        pasted = parsed as Record<string, unknown>;
      } catch (err) {
        setFieldError(err instanceof Error ? `Incident data: ${err.message}` : 'Incident data must be valid JSON.');
        return null;
      }
    }
    const finalTitle = title.trim() || (typeof pasted.description === 'string' ? pasted.description.trim() : '');
    const finalType = incidentType.trim() || (typeof pasted.incident_type === 'string' ? pasted.incident_type.trim() : '');
    if (!finalTitle) { setFieldError('Add an incident title or include a description in the pasted data.'); return null; }
    if (!description.trim() && typeof pasted.description !== 'string') { setFieldError('Add a short description of what happened.'); return null; }
    if (!finalType) { setFieldError('Choose an incident category or include incident_type in the pasted data.'); return null; }

    const finalDescription = description.trim() || (typeof pasted.description === 'string' ? pasted.description.trim() : '');
    return {
      ...pasted,
      incident_id: typeof pasted.incident_id === 'string' && pasted.incident_id.trim() ? pasted.incident_id : `ANALYST-${Date.now()}`,
      incident_type: finalType,
      description: finalDescription && finalDescription !== finalTitle ? `${finalTitle}\n\n${finalDescription}` : finalTitle,
      source: typeof pasted.source === 'string' ? pasted.source : 'analyst_console',
      indicators: Array.isArray(pasted.indicators) ? pasted.indicators : [],
      evidence: Array.isArray(pasted.evidence) ? pasted.evidence : [],
    };
  };

  const handleSubmit = async (event: React.FormEvent) => {
    event.preventDefault();
    if (mode === 'simulation') {
      const scenario = scenarios.find((item) => item.filename === selectedScenario);
      if (!scenario) { setFieldError('Choose one of the available simulations.'); return; }
      setFieldError(null);
      setRunState('creating');
      setError(null);
      try {
        const created: Incident = await api.loadScenario(scenario.filename);
        await executePipeline(created.id);
      } catch (err) {
        setRunState('failed');
        setError(err instanceof ApiError ? err.message : 'The selected simulation could not be loaded.');
      }
      return;
    }

    const payload = validateAndBuildPayload();
    if (!payload) return;
    setRunState('creating');
    setError(null);
    try {
      const created = await api.createIncident(payload);
      await executePipeline(created.id);
    } catch (err) {
      setRunState('failed');
      setError(err instanceof ApiError ? err.message : 'The incident could not be submitted.');
    }
  };

  const isBusy = runState === 'creating' || runState === 'running';

  return (
    <>
      <Header pageTitle="New Investigation" pageSubtitle="Submit incident information and ask CyberOrchestra to analyze it." />
      <main className="incident-screen">
        <Link className="incident-back-link" to="/incidents"><ArrowLeft size={15} /> Back to incidents</Link>
        <div className="incident-screen-grid">
          <section className="incident-form-card">
            <div className="incident-form-heading"><span className="incident-heading-icon"><ClipboardPaste size={20} /></span><div><h2>Start an investigation</h2><p>Provide incident details or choose a clearly labelled simulation.</p></div></div>
            {runState === 'running' ? (
              <div className="analysis-progress" aria-live="polite">
                <span className="progress-spinner"><LoaderCircle size={22} /></span>
                <h3>Analysis is running</h3>
                <p>Incident <strong>{incidentId}</strong> has been submitted. The backend is processing the pipeline request.</p>
                <div className="current-stage"><span>Backend status</span><strong>{liveDetail?.status ?? 'Waiting for the backend response'}</strong></div>
                <div className="current-stage"><span>Current backend stage</span><strong>{liveDetail?.pipeline_stage ?? 'Not reported yet'}</strong></div>
                <ol className="live-stage-list">{progressStages.map((stage) => {
                  const records = liveDetail?.execution_history.filter((entry) => stage.match.includes(entry.stage)) ?? [];
                  const backendStage = liveDetail?.pipeline_stage ?? '';
                  const isCurrent = stage.match.some((name) => backendStage.toLowerCase().includes(name.toLowerCase()) || name.toLowerCase().includes(backendStage.toLowerCase())) && !['Normalized', 'Completed', 'Error'].includes(backendStage);
                  const status = records.some((entry) => entry.status === 'error') ? 'failed' : records.length && records.every((entry) => entry.status === 'skipped') ? 'skipped' : records.length && records.every((entry) => ['completed', 'skipped'].includes(entry.status)) ? 'completed' : records.some((entry) => entry.status === 'running') || isCurrent ? 'running' : 'pending';
                  return <li className={`live-stage stage-${status}`} key={stage.label}><span className="live-stage-dot" /> <span>{stage.label}{stage.parallel && <small> · malware, log, and vulnerability agents</small>}</span><b>{status === 'failed' ? 'Failed' : status[0].toUpperCase() + status.slice(1)}</b></li>;
                })}</ol>
                <p className="plain-note">Stage-by-stage progress is available from the incident detail endpoint after the backend records its execution history. This screen does not estimate progress.</p>
              </div>
            ) : runState === 'failed' && incidentId ? (
              <div className="analysis-progress failed" role="alert">
                <CircleAlert size={23} /><h3>Analysis did not complete</h3><p>{error}</p>
                <div className="current-stage"><span>Incident ID</span><strong>{incidentId}</strong></div>
                <button className="incident-primary" onClick={() => navigate(`/incidents/${encodeURIComponent(incidentId)}`)}>Open incident details <ArrowRight size={16} /></button>
              </div>
            ) : (
              <form onSubmit={handleSubmit} className="incident-form">
                <fieldset className="input-method">
                  <legend>How would you like to provide the incident?</legend>
                  <label className={mode === 'paste' ? 'method-option selected' : 'method-option'}><input type="radio" name="input-mode" checked={mode === 'paste'} onChange={() => { setMode('paste'); setFieldError(null); }} /><span><ClipboardPaste size={17} /><strong>Enter incident data</strong><small>Describe the event and optionally paste JSON telemetry.</small></span></label>
                  <label className={mode === 'simulation' ? 'method-option selected' : 'method-option'}><input type="radio" name="input-mode" checked={mode === 'simulation'} onChange={() => { setMode('simulation'); setFieldError(null); }} /><span><RadioTower size={17} /><strong>Use a simulation</strong><small>Load a built-in test incident from the backend.</small></span></label>
                </fieldset>

                {mode === 'paste' ? (
                  <>
                    <label className="incident-field"><span>Incident title <b>*</b></span><input value={title} onChange={(event) => setTitle(event.target.value)} maxLength={120} placeholder="Briefly name this security event" /></label>
                    <label className="incident-field"><span>What happened? <b>*</b></span><textarea value={description} onChange={(event) => setDescription(event.target.value)} rows={4} placeholder="Describe the observed activity, affected system, or alert." /></label>
                    <label className="incident-field"><span>Incident type or category <b>*</b></span><input value={incidentType} onChange={(event) => setIncidentType(event.target.value)} maxLength={80} placeholder="For example: suspicious_network_activity" /><small>This value is sent as incident_type to the existing normalizer.</small></label>
                    <label className="incident-field"><span>Paste incident data (optional JSON)</span><textarea className="json-input" value={payloadText} onChange={(event) => setPayloadText(event.target.value)} rows={5} placeholder={'Paste a JSON object with supported fields such as indicators and evidence.'} /><small>Use JSON accepted by the incident normalizer. File upload is not supported.</small></label>
                  </>
                ) : (
                  <div className="scenario-picker">
                    <label className="incident-field"><span>Available simulated incidents <b>*</b></span>
                      {loadingScenarios ? <div className="incident-inline-state"><LoaderCircle size={15} /> Loading simulations…</div> :
                        scenarios.length ? <select value={selectedScenario} onChange={(event) => { setSelectedScenario(event.target.value); setFieldError(null); }}><option value="">Select a simulation</option>{scenarios.map((item) => <option key={item.filename} value={item.filename}>{item.incident_id} · {item.incident_type}</option>)}</select> :
                          <div className="incident-empty-inline">No simulations are currently available from the backend.</div>}
                    </label>
                    {selectedScenario && (() => { const item = scenarios.find((scenario) => scenario.filename === selectedScenario); return item ? <div className="scenario-summary"><span className="simulation-label">SIMULATION</span><strong>{item.incident_id}</strong><p>{item.description}</p><small>{item.indicatorsCount} indicators · {item.evidenceCount} evidence items · severity {item.severity}</small></div> : null; })()}
                    {scenarioError && <div className="incident-inline-error">{scenarioError}</div>}
                  </div>
                )}

                {fieldError && <div className="incident-inline-error" role="alert">{fieldError}</div>}
                {error && <div className="incident-inline-error" role="alert">{error}</div>}
                <button className="incident-primary" type="submit" disabled={isBusy || (mode === 'simulation' && (loadingScenarios || !scenarios.length))}><Play size={16} /> Submit and Analyze</button>
              </form>
            )}
          </section>
          <aside className="incident-explainer">
            <span className="explainer-kicker">WHAT HAPPENS NEXT</span>
            <h3>From incident data to a reviewable report</h3>
            <ol><li><b>Normalize</b><span>Incident fields are checked and standardized.</span></li><li><b>Analyze</b><span>Threat detection runs, followed by the specialized analysis agents.</span></li><li><b>Review</b><span>Recovery recommendations are checked by deterministic policy rules.</span></li><li><b>Read results</b><span>Open the report, evidence citations, and any uncertainties.</span></li></ol>
            <div className="safety-note"><CheckCircle2 size={16} /><span>Recommendations are displayed for review. This interface does not run recovery actions.</span></div>
          </aside>
        </div>
        {runState === 'creating' && <div className="submission-toast" role="status"><LoaderCircle size={17} /> Submitting incident to the backend…</div>}
      </main>
    </>
  );
};
