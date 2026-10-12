import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import {
  Activity, AlertTriangle, ArrowRight, CheckCircle2, Circle, Clock3,
  FileText, Plus, RefreshCw, ShieldAlert, ShieldCheck, Wifi, WifiOff,
} from 'lucide-react';
import { Header } from '../components/layout/Header';
import { SeverityBadge, StatusBadge } from '../components/ui/Badges';
import { api, ApiError } from '../services/api';
import type { Incident, SystemHealthResponse } from '../types';

const workflow = [
  { label: 'Incident Input', icon: Activity },
  { label: 'Threat Detection', icon: ShieldAlert },
  { label: 'Parallel Analysis', icon: Activity },
  { label: 'Recovery Plan', icon: ShieldCheck },
  { label: 'Policy Review', icon: CheckCircle2 },
  { label: 'Final Report', icon: FileText },
];

const healthLabel = (status: string) =>
  status === 'operational' ? 'Connected' : status === 'degraded' ? 'Needs attention' : 'Unavailable';

export const DashboardPage: React.FC = () => {
  const [incidents, setIncidents] = useState<Incident[] | null>(null);
  const [health, setHealth] = useState<SystemHealthResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [refreshing, setRefreshing] = useState(false);

  const loadDashboard = useCallback(async (refresh = false) => {
    refresh ? setRefreshing(true) : setLoading(true);
    setError(null);
    try {
      const [incidentResult, healthResult] = await Promise.allSettled([
        api.getIncidents(),
        api.getSystemHealth(),
      ]);
      setIncidents(incidentResult.status === 'fulfilled' ? incidentResult.value : null);
      setHealth(healthResult.status === 'fulfilled' ? healthResult.value : null);
      if (incidentResult.status === 'rejected' || healthResult.status === 'rejected') {
        const failed = incidentResult.status === 'rejected' ? incidentResult.reason : healthResult.status === 'rejected' ? healthResult.reason : null;
        setError(failed instanceof ApiError ? failed.message : 'Some dashboard information could not be loaded.');
      }
    } catch (err) {
      setError(err instanceof ApiError ? err.message : 'Could not load dashboard information.');
      setIncidents(null);
      setHealth(null);
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, []);

  useEffect(() => { void loadDashboard(); }, [loadDashboard]);

  const counts = useMemo(() => {
    if (!incidents) return null;
    return {
      total: incidents.length,
      critical: incidents.filter((incident) => incident.severity.toLowerCase() === 'critical').length,
      inProgress: incidents.filter((incident) =>
        ['new', 'investigating', 'containment', 'eradication', 'recovery', 'policy review', 'reporting'].includes(incident.status.toLowerCase())
      ).length,
      completed: incidents.filter((incident) => incident.hasReport === true || incident.status.toLowerCase() === 'resolved').length,
    };
  }, [incidents]);

  const integrationComponents = (health?.components ?? []).filter((component) =>
    /abuseipdb|urlhaus|nvd|mitre|threat feed|intelligence/i.test(component.component)
  );
  const backend = health?.components.find((component) => /fastapi backend/i.test(component.component));
  const activeIncident = incidents?.find((incident) =>
    ['investigating', 'containment', 'eradication', 'recovery', 'policy review', 'reporting'].includes(incident.status.toLowerCase())
  );

  return (
    <>
      <Header pageTitle="Security Operations Center" pageSubtitle="Review investigations, check connected intelligence sources, and follow incident analysis." />
      <main className="page-enter dashboard-workspace">
        <section className="dashboard-intro">
          <div>
            <div className="dashboard-eyebrow"><ShieldCheck size={15} /> CYBERORCHESTRA OPERATIONS</div>
            <h2>Investigation overview</h2>
            <p>Monitor security incidents and the services that support your investigations.</p>
          </div>
          <div className="dashboard-actions">
            <span className={`connection-pill ${backend?.status === 'operational' ? 'is-online' : backend ? 'is-warning' : 'is-unknown'}`}>
              {backend?.status === 'operational' ? <Wifi size={15} /> : <WifiOff size={15} />}
              {backend ? healthLabel(backend.status) : loading ? 'Checking connection' : 'Status unavailable'}
            </span>
            <Link className="primary-action" to="/incidents?new=1"><Plus size={18} /> New Investigation</Link>
          </div>
        </section>

        {error && (
          <div className="dashboard-error" role="alert">
            <AlertTriangle size={18} />
            <div><strong>Dashboard information is unavailable</strong><span>{error}</span></div>
            <button className="secondary-action" onClick={() => void loadDashboard()}><RefreshCw size={15} /> Retry</button>
          </div>
        )}

        <section className="dashboard-stats" aria-label="Incident statistics">
          {[
            { label: 'Total Incidents', value: counts?.total, icon: Activity, tone: 'cyan' },
            { label: 'Critical Incidents', value: counts?.critical, icon: ShieldAlert, tone: 'red' },
            { label: 'Investigations In Progress', value: counts?.inProgress, icon: Clock3, tone: 'amber' },
            { label: 'Completed Analyses', value: counts?.completed, icon: CheckCircle2, tone: 'green' },
          ].map(({ label, value, icon: Icon, tone }) => (
            <article className="dashboard-stat" key={label}>
              <span className={`stat-icon tone-${tone}`}><Icon size={18} /></span>
              <div><span className="stat-label">{label}</span><strong>{value === undefined ? '--' : value}</strong></div>
            </article>
          ))}
        </section>

        <section className="dashboard-columns">
          <article className="workspace-panel investigations-panel">
            <div className="workspace-panel-heading">
              <div><h3>Recent Investigations</h3><p>Latest incidents received by CyberOrchestra</p></div>
              <button className="icon-action" aria-label="Refresh dashboard" title="Refresh" disabled={refreshing} onClick={() => void loadDashboard(true)}>
                <RefreshCw size={16} className={refreshing ? 'spin-icon' : ''} />
              </button>
            </div>
            {loading && !incidents ? (
              <div className="dashboard-state"><span className="loading-mark" /> Loading recent investigations…</div>
            ) : incidents?.length === 0 ? (
              <div className="dashboard-empty"><ShieldCheck size={25} /><strong>No investigations yet</strong><span>Start by submitting an incident for analysis.</span><Link to="/incidents?new=1">Create an investigation <ArrowRight size={14} /></Link></div>
            ) : incidents ? (
              <div className="investigation-table-wrap">
                <table className="investigation-table">
                  <thead><tr><th>Incident</th><th>Severity</th><th>Status</th><th>Date received</th><th><span className="sr-only">Details</span></th></tr></thead>
                  <tbody>
                    {[...incidents].reverse().slice(0, 7).map((incident) => (
                      <tr key={incident.id}>
                        <td><span className="incident-id">{incident.id}</span><strong className="incident-title">{incident.title}</strong></td>
                        <td><SeverityBadge severity={incident.severity} /></td>
                        <td><StatusBadge status={incident.status} /></td>
                        <td className="incident-date">{incident.createdAt ? new Date(incident.createdAt).toLocaleDateString() : '—'}</td>
                        <td><Link className="details-link" to={`/incidents?incident=${encodeURIComponent(incident.id)}`}>View details <ArrowRight size={14} /></Link></td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            ) : (
              <div className="dashboard-state"><WifiOff size={18} /> Incident data could not be loaded.</div>
            )}
          </article>

          <article className="workspace-panel health-panel">
            <div className="workspace-panel-heading"><div><h3>System Health</h3><p>Backend and configured intelligence integrations</p></div><span className={`health-indicator ${backend?.status === 'operational' ? 'healthy' : ''}`}><span />{backend ? healthLabel(backend.status) : 'Unavailable'}</span></div>
            {!health && loading ? <div className="dashboard-state"><span className="loading-mark" /> Checking service status…</div> :
              !health ? <div className="dashboard-state"><WifiOff size={18} /> Health information is unavailable. Use Retry above to check again.</div> : (
                <div className="health-list">
                  <div className="health-row"><span className="health-symbol"><Activity size={16} /></span><span className="health-name">API backend</span><span className={`health-state state-${backend?.status ?? 'unknown'}`}>{backend ? healthLabel(backend.status) : 'Not reported'}</span></div>
                  {integrationComponents.length ? integrationComponents.map((component) => (
                    <div className="health-row" key={component.component}>
                      <span className="health-symbol"><Circle size={10} fill="currentColor" /></span><span className="health-name">{component.component.replace(/ (Threat Feed|Intelligence)$/i, '')}</span>
                      <span className={`health-state state-${component.status}`}>{healthLabel(component.status)}</span>
                    </div>
                  )) : <div className="health-unconfigured"><WifiOff size={16} /> No intelligence integrations were reported by the backend.</div>}
                </div>
              )}
            <div className="health-footnote">Integration status comes from the backend health endpoint.</div>
          </article>
        </section>

        <section className="workspace-panel workflow-panel">
          <div className="workspace-panel-heading"><div><h3>Analysis workflow</h3><p>{activeIncident ? `Current investigation: ${activeIncident.id} · ${activeIncident.status}` : 'The steps used to review and report an incident'}</p></div>{activeIncident && <StatusBadge status={activeIncident.status} />}</div>
          <div className="workflow-track">
            {workflow.map(({ label, icon: Icon }, index) => {
              const current = activeIncident ? activeIncident.pipelineStage.toLowerCase().replace(/[_-]/g, ' ') : '';
              const position = workflow.findIndex((step) => current.includes(step.label.toLowerCase().split(' ')[0]));
              const done = Boolean(activeIncident && position >= 0 && index < position);
              const running = Boolean(activeIncident && position === index);
              return <React.Fragment key={label}>
                <div className={`workflow-step ${done ? 'step-done' : ''} ${running ? 'step-running' : ''}`}>
                  <span className="workflow-icon"><Icon size={17} /></span><span>{label}</span>
                  {running && <small>In progress</small>}
                </div>
                {index < workflow.length - 1 && <span className={`workflow-connector ${done ? 'connector-done' : ''}`} />}
              </React.Fragment>;
            })}
          </div>
          {!activeIncident && <div className="workflow-note"><CheckCircle2 size={15} /> No analysis is currently in progress.</div>}
          {activeIncident && <div className="workflow-note"><Clock3 size={15} /> Progress reflects the latest incident status reported by the backend.</div>}
        </section>
      </main>
    </>
  );
};
