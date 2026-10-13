import React, { useEffect, useState } from 'react';
import { useNavigate } from 'react-router-dom';
import {
  ArrowRight, CheckCircle2, CircleAlert, ClipboardPaste,
  LoaderCircle, Play, RadioTower, RefreshCw, Search, Zap
} from 'lucide-react';
import { Header } from '../components/layout/Header';
import { api, ApiError } from '../services/api';
import type { Incident, ScenarioItem } from '../types';

type InputMode = 'simulation' | 'paste';
type FetchState = 'idle' | 'loading' | 'done' | 'error';
type RunState = 'ready' | 'creating' | 'running' | 'failed';

export const NewInvestigationPage: React.FC = () => {
  const navigate = useNavigate();
  const [mode, setMode] = useState<InputMode>('simulation');

  // ── Simulation mode state ─────────────────────────────────────────────────
  const [fetchState, setFetchState] = useState<FetchState>('idle');
  const [scenarios, setScenarios] = useState<ScenarioItem[]>([]);
  const [fetchError, setFetchError] = useState<string | null>(null);
  const [selectedScenario, setSelectedScenario] = useState<ScenarioItem | null>(null);
  const [searchQuery, setSearchQuery] = useState('');

  // ── Paste mode state ──────────────────────────────────────────────────────
  const [title, setTitle] = useState('');
  const [description, setDescription] = useState('');
  const [incidentType, setIncidentType] = useState('');
  const [payloadText, setPayloadText] = useState('');
  const [fieldError, setFieldError] = useState<string | null>(null);

  // ── Pipeline execution state ──────────────────────────────────────────────
  const [runState, setRunState] = useState<RunState>('ready');
  const [error, setError] = useState<string | null>(null);
  const [createdId, setCreatedId] = useState<string | null>(null);

  // ── Load scenarios from backend ───────────────────────────────────────────
  const fetchLiveIncidents = async () => {
    if (fetchState === 'loading') return; // prevent duplicate requests
    setFetchState('loading');
    setFetchError(null);
    setSelectedScenario(null);
    try {
      const items = await api.getScenarios();
      setScenarios(items);
      setFetchState('done');
    } catch (err) {
      setFetchError(err instanceof ApiError ? err.message : 'Could not load incidents from the backend.');
      setFetchState('error');
    }
  };

  // Pre-load scenarios on mount for immediate availability
  useEffect(() => {
    void fetchLiveIncidents();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const filteredScenarios = scenarios.filter((s) => {
    if (!searchQuery.trim()) return true;
    const q = searchQuery.toLowerCase();
    return (
      s.incident_id.toLowerCase().includes(q) ||
      s.incident_type.toLowerCase().includes(q) ||
      s.description.toLowerCase().includes(q) ||
      s.severity.toLowerCase().includes(q)
    );
  });

  // ── Execute pipeline ──────────────────────────────────────────────────────
  const executePipeline = async (id: string) => {
    setCreatedId(id);
    setRunState('running');
    setError(null);
    try {
      await api.runPipeline(id);
      navigate(`/incidents/${encodeURIComponent(id)}`, { replace: true });
    } catch (err) {
      setRunState('failed');
      setError(err instanceof ApiError ? err.message : 'Analysis could not be completed.');
    }
  };

  const handleAnalyzeSimulation = async () => {
    if (!selectedScenario) { setFieldError('Select an incident to analyze.'); return; }
    setFieldError(null);
    setRunState('creating');
    setError(null);
    try {
      const created: Incident = await api.loadScenario(selectedScenario.filename);
      await executePipeline(created.id);
    } catch (err) {
      setRunState('failed');
      setError(err instanceof ApiError ? err.message : 'The selected simulation could not be loaded.');
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

  const handleSubmitPaste = async (event: React.FormEvent) => {
    event.preventDefault();
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
  const severityColor: Record<string, string> = {
    critical: 'var(--red-400)',
    high: 'var(--amber-400)',
    medium: '#eab308',
    low: 'var(--green-400)',
    info: 'var(--cyan-400)',
  };

  // ── Running state ─────────────────────────────────────────────────────────
  if (runState === 'running') {
    return (
      <>
        <Header pageTitle="Analyzing Incident" pageSubtitle="CyberOrchestra pipeline is running." />
        <main className="sim-screen">
          <div className="sim-running-card">
            <div className="sim-running-spinner">
              <LoaderCircle size={36} />
            </div>
            <h2>Analysis in progress</h2>
            <p>
              Incident <strong>{createdId}</strong> has been submitted.
              The backend is running the full six-agent pipeline.
            </p>
            <div className="sim-pipeline-stages">
              {[
                'Data Normalizer',
                'Threat Detection Agent',
                'Malware Analysis Agent',
                'Log Analysis Agent',
                'Vulnerability Assessment Agent',
                'Recovery Planning Agent',
                'Deterministic Policy Engine',
                'Report Generation Agent',
              ].map((stage, i) => (
                <div key={stage} className="sim-stage-row">
                  <span className="sim-stage-dot" style={{ animationDelay: `${i * 0.15}s` }} />
                  <span>{stage}</span>
                </div>
              ))}
            </div>
            <p className="sim-note">
              Results will appear automatically when the pipeline finishes. You will be redirected to the incident detail page.
            </p>
          </div>
        </main>
      </>
    );
  }

  if (runState === 'failed' && createdId) {
    return (
      <>
        <Header pageTitle="Analysis Failed" pageSubtitle="An error occurred during pipeline execution." />
        <main className="sim-screen">
          <div className="sim-failed-card">
            <CircleAlert size={36} />
            <h2>Analysis did not complete</h2>
            <p>{error}</p>
            <div className="sim-failed-id">
              <span>Incident ID</span>
              <code>{createdId}</code>
            </div>
            <button
              className="sim-primary-btn"
              onClick={() => navigate(`/incidents/${encodeURIComponent(createdId)}`)}
            >
              Open incident details <ArrowRight size={16} />
            </button>
          </div>
        </main>
      </>
    );
  }

  return (
    <>
      <Header
        pageTitle="Live Incident Simulation"
        pageSubtitle="Fetch available incidents from the backend, select one, and run the CyberOrchestra analysis pipeline."
      />
      <main className="sim-screen page-enter">
        {/* ── Mode Toggle ── */}
        <div className="sim-mode-toggle">
          <button
            className={`sim-mode-btn ${mode === 'simulation' ? 'active' : ''}`}
            onClick={() => { setMode('simulation'); setFieldError(null); }}
          >
            <RadioTower size={15} /> Live Incidents
          </button>
          <button
            className={`sim-mode-btn ${mode === 'paste' ? 'active' : ''}`}
            onClick={() => { setMode('paste'); setFieldError(null); }}
          >
            <ClipboardPaste size={15} /> Manual Entry
          </button>
        </div>

        {/* ── Simulation Mode ── */}
        {mode === 'simulation' && (
          <div className="sim-layout">
            {/* Left: incident list */}
            <div className="sim-left">
              <div className="sim-section-header">
                <div>
                  <h2>Available Incidents</h2>
                  <p>Scenarios from the backend data repository</p>
                </div>
                <button
                  className="sim-fetch-btn"
                  onClick={() => void fetchLiveIncidents()}
                  disabled={fetchState === 'loading'}
                  id="fetch-live-incidents-btn"
                >
                  {fetchState === 'loading' ? (
                    <><LoaderCircle size={15} className="spin-icon" /> Fetching…</>
                  ) : (
                    <><Zap size={15} /> Fetch Live Incidents</>
                  )}
                </button>
              </div>

              {/* Search */}
              {fetchState === 'done' && scenarios.length > 0 && (
                <div className="sim-search">
                  <Search size={14} />
                  <input
                    type="text"
                    placeholder="Search by ID, type, or severity…"
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                  />
                </div>
              )}

              {/* States */}
              {fetchState === 'idle' && (
                <div className="sim-empty-state">
                  <RadioTower size={28} />
                  <strong>No incidents loaded</strong>
                  <span>Click "Fetch Live Incidents" to load available scenarios from the backend.</span>
                  <button className="sim-fetch-btn" onClick={() => void fetchLiveIncidents()}>
                    <Zap size={15} /> Fetch Live Incidents
                  </button>
                </div>
              )}

              {fetchState === 'loading' && (
                <div className="sim-loading-state">
                  <LoaderCircle size={22} className="spin-icon" />
                  <span>Fetching incidents from the backend…</span>
                </div>
              )}

              {fetchState === 'error' && (
                <div className="sim-error-state">
                  <CircleAlert size={18} />
                  <span>{fetchError}</span>
                  <button className="sim-retry-btn" onClick={() => void fetchLiveIncidents()}>
                    <RefreshCw size={13} /> Retry
                  </button>
                </div>
              )}

              {fetchState === 'done' && filteredScenarios.length === 0 && (
                <div className="sim-empty-state">
                  <Search size={24} />
                  <strong>{searchQuery ? 'No matching incidents' : 'No incidents available'}</strong>
                  <span>{searchQuery ? 'Try a different search term.' : 'The backend did not return any incidents.'}</span>
                </div>
              )}

              {fetchState === 'done' && filteredScenarios.length > 0 && (
                <div className="sim-incident-list">
                  {filteredScenarios.map((scenario) => {
                    const sevColor = severityColor[scenario.severity.toLowerCase()] ?? 'var(--text-muted)';
                    return (
                      <button
                        key={scenario.filename}
                        className={`sim-incident-card ${selectedScenario?.filename === scenario.filename ? 'selected' : ''}`}
                        onClick={() => { setSelectedScenario(scenario); setFieldError(null); }}
                      >
                        <div className="sim-inc-top">
                          <code className="sim-inc-id">{scenario.incident_id}</code>
                          <span className="sim-inc-severity" style={{ color: sevColor, borderColor: sevColor }}>
                            {scenario.severity}
                          </span>
                        </div>
                        <div className="sim-inc-type">{scenario.incident_type.replace(/_/g, ' ')}</div>
                        <p className="sim-inc-desc">{scenario.description}</p>
                        <div className="sim-inc-meta">
                          <span>{scenario.indicatorsCount} indicators</span>
                          <span>·</span>
                          <span>{scenario.evidenceCount} evidence items</span>
                          <span>·</span>
                          <span>{scenario.source}</span>
                        </div>
                      </button>
                    );
                  })}
                </div>
              )}
            </div>

            {/* Right: selected incident + analyze button */}
            <div className="sim-right">
              {selectedScenario ? (
                <div className="sim-selected-card">
                  <div className="sim-selected-header">
                    <span className="sim-selected-badge">SELECTED INCIDENT</span>
                    <h3>{selectedScenario.incident_id}</h3>
                    <span
                      className="sim-selected-severity"
                      style={{
                        color: severityColor[selectedScenario.severity.toLowerCase()] ?? 'var(--text-muted)',
                      }}
                    >
                      {selectedScenario.severity} severity
                    </span>
                  </div>

                  <div className="sim-selected-meta">
                    <div className="sim-meta-row"><span>Type</span><strong>{selectedScenario.incident_type.replace(/_/g, ' ')}</strong></div>
                    <div className="sim-meta-row"><span>Source</span><strong>{selectedScenario.source}</strong></div>
                    <div className="sim-meta-row"><span>Indicators</span><strong>{selectedScenario.indicatorsCount}</strong></div>
                    <div className="sim-meta-row"><span>Evidence items</span><strong>{selectedScenario.evidenceCount}</strong></div>
                  </div>

                  <p className="sim-selected-desc">{selectedScenario.description}</p>

                  {fieldError && (
                    <div className="sim-field-error" role="alert">
                      <CircleAlert size={14} /> {fieldError}
                    </div>
                  )}
                  {error && runState === 'failed' && !createdId && (
                    <div className="sim-field-error" role="alert">
                      <CircleAlert size={14} /> {error}
                    </div>
                  )}

                  <button
                    className="sim-analyze-btn"
                    onClick={() => void handleAnalyzeSimulation()}
                    disabled={isBusy}
                    id="analyze-incident-btn"
                  >
                    {runState === 'creating' ? (
                      <><LoaderCircle size={16} className="spin-icon" /> Loading scenario…</>
                    ) : (
                      <><Play size={16} /> Analyze Incident</>
                    )}
                  </button>

                  <div className="sim-pipeline-hint">
                    <CheckCircle2 size={13} />
                    <span>
                      Running analysis will invoke all six CyberOrchestra agents via the existing backend pipeline.
                      Results are displayed for review only — no remediation is executed.
                    </span>
                  </div>
                </div>
              ) : (
                <div className="sim-no-selection">
                  <RadioTower size={32} />
                  <strong>No incident selected</strong>
                  <span>
                    {fetchState === 'done'
                      ? 'Select an incident from the list to review its details and start analysis.'
                      : 'Fetch incidents first, then select one to analyze.'}
                  </span>
                </div>
              )}

              {/* Pipeline explainer */}
              <div className="sim-explainer">
                <span className="sim-explainer-kicker">ANALYSIS PIPELINE</span>
                <ol className="sim-explainer-steps">
                  {[
                    { label: 'Data Normalizer', desc: 'Backend component — standardizes fields.' },
                    { label: 'Threat Detection Agent', desc: 'Classifies the incident and assesses severity.' },
                    { label: 'Malware / Log / Vulnerability Agents', desc: 'Three parallel specialist agents produce findings.' },
                    { label: 'Shared Incident State', desc: 'Consolidated context for downstream agents.' },
                    { label: 'Recovery Planning Agent', desc: 'Generates prioritized remediation actions.' },
                    { label: 'Deterministic Policy Engine', desc: 'Backend component — validates each action.' },
                    { label: 'Report Generation Agent', desc: 'Produces the final incident response report.' },
                  ].map((step) => (
                    <li key={step.label}>
                      <b>{step.label}</b>
                      <span>{step.desc}</span>
                    </li>
                  ))}
                </ol>
              </div>
            </div>
          </div>
        )}

        {/* ── Paste Mode ── */}
        {mode === 'paste' && (
          <div className="sim-paste-layout">
            <form className="sim-paste-form" onSubmit={(e) => void handleSubmitPaste(e)}>
              <h2>Enter Incident Data</h2>
              <p>Describe the incident manually or paste JSON telemetry to create and analyze a new incident.</p>

              <label className="incident-field">
                <span>Incident title <b>*</b></span>
                <input value={title} onChange={(e) => setTitle(e.target.value)} maxLength={120} placeholder="Briefly name this security event" />
              </label>

              <label className="incident-field">
                <span>What happened? <b>*</b></span>
                <textarea value={description} onChange={(e) => setDescription(e.target.value)} rows={4} placeholder="Describe the observed activity, affected system, or alert." />
              </label>

              <label className="incident-field">
                <span>Incident type or category <b>*</b></span>
                <input value={incidentType} onChange={(e) => setIncidentType(e.target.value)} maxLength={80} placeholder="e.g. suspicious_network_activity" />
                <small>Sent as incident_type to the existing normalizer.</small>
              </label>

              <label className="incident-field">
                <span>Paste incident data (optional JSON)</span>
                <textarea
                  className="json-input"
                  value={payloadText}
                  onChange={(e) => setPayloadText(e.target.value)}
                  rows={5}
                  placeholder={'Paste a JSON object with indicators and evidence.'}
                />
                <small>Accepted by the existing incident normalizer. File upload is not supported.</small>
              </label>

              {fieldError && <div className="incident-inline-error" role="alert">{fieldError}</div>}
              {error && <div className="incident-inline-error" role="alert">{error}</div>}

              <button className="incident-primary" type="submit" disabled={isBusy}>
                <Play size={16} /> Submit and Analyze
              </button>
            </form>

            <div className="incident-explainer">
              <span className="explainer-kicker">WHAT HAPPENS NEXT</span>
              <h3>From incident data to a reviewable report</h3>
              <ol>
                <li><b>Normalize</b><span>Incident fields are checked and standardized by the backend Data Normalizer.</span></li>
                <li><b>Analyze</b><span>Threat Detection Agent runs, followed by the three specialist analysis agents in parallel.</span></li>
                <li><b>Plan</b><span>Recovery Planning Agent generates prioritized remediation actions.</span></li>
                <li><b>Review</b><span>Deterministic Policy Engine validates each recommended action.</span></li>
                <li><b>Report</b><span>Report Generation Agent produces the final consolidated report.</span></li>
              </ol>
              <div className="safety-note">
                <CheckCircle2 size={16} />
                <span>Recommendations are displayed for review. This interface does not execute recovery actions.</span>
              </div>
            </div>
          </div>
        )}

        {isBusy && runState === 'creating' && (
          <div className="submission-toast" role="status">
            <LoaderCircle size={17} /> Submitting incident to the backend…
          </div>
        )}
      </main>
    </>
  );
};
