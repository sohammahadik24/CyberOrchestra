import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { Link } from 'react-router-dom';
import {
  Activity, AlertTriangle, ArrowRight, CheckCircle2, Clock3,
  FileText, Plus, RefreshCw, ShieldAlert, ShieldCheck, WifiOff,
} from 'lucide-react';
import { Header } from '../components/layout/Header';
import { SeverityBadge, StatusBadge } from '../components/ui/Badges';
import { api, ApiError } from '../services/api';
import type { Incident, SeverityDistributionItem } from '../types';

// ── Donut Chart ──────────────────────────────────────────────────────────────
interface DonutChartProps {
  data: SeverityDistributionItem[];
  total: number;
}

const DonutChart: React.FC<DonutChartProps> = ({ data, total }) => {
  const size = 200;
  const cx = size / 2;
  const cy = size / 2;
  const outerR = 80;
  const innerR = 52;
  const [hovered, setHovered] = useState<string | null>(null);
  const gap = 2.5;

  const nonZero = data.filter((d) => d.value > 0);
  const totalVal = nonZero.reduce((sum, d) => sum + d.value, 0);

  const arcs = useMemo(() => {
    if (totalVal === 0) return [];
    let angle = -90;
    return nonZero.map((item) => {
      const pct = item.value / totalVal;
      const sweep = pct * 360 - gap;
      const startRad = (angle * Math.PI) / 180;
      const endRad = ((angle + sweep) * Math.PI) / 180;
      const x1 = cx + outerR * Math.cos(startRad);
      const y1 = cy + outerR * Math.sin(startRad);
      const x2 = cx + outerR * Math.cos(endRad);
      const y2 = cy + outerR * Math.sin(endRad);
      const ix1 = cx + innerR * Math.cos(startRad);
      const iy1 = cy + innerR * Math.sin(startRad);
      const ix2 = cx + innerR * Math.cos(endRad);
      const iy2 = cy + innerR * Math.sin(endRad);
      const large = sweep > 180 ? 1 : 0;
      const path = [
        `M ${x1.toFixed(2)} ${y1.toFixed(2)}`,
        `A ${outerR} ${outerR} 0 ${large} 1 ${x2.toFixed(2)} ${y2.toFixed(2)}`,
        `L ${ix2.toFixed(2)} ${iy2.toFixed(2)}`,
        `A ${innerR} ${innerR} 0 ${large} 0 ${ix1.toFixed(2)} ${iy1.toFixed(2)}`,
        'Z',
      ].join(' ');
      angle += pct * 360;
      return { ...item, path, pct };
    });
  }, [nonZero, totalVal, cx, cy, outerR, innerR, gap]);

  const hoveredItem = hovered ? data.find((d) => d.name === hovered) : null;

  return (
    <div className="donut-chart-wrapper">
      <svg
        width={size}
        height={size}
        viewBox={`0 0 ${size} ${size}`}
        aria-label="Severity distribution donut chart"
        role="img"
      >
        <defs>
          {arcs.map((arc) => (
            <filter key={`glow-${arc.name}`} id={`glow-${arc.name}`}>
              <feGaussianBlur stdDeviation="3" result="coloredBlur" />
              <feMerge>
                <feMergeNode in="coloredBlur" />
                <feMergeNode in="SourceGraphic" />
              </feMerge>
            </filter>
          ))}
        </defs>

        {totalVal === 0 ? (
          <circle cx={cx} cy={cy} r={outerR} fill="none" stroke="rgba(255,255,255,0.06)" strokeWidth={outerR - innerR} />
        ) : (
          arcs.map((arc) => (
            <path
              key={arc.name}
              d={arc.path}
              fill={arc.fill}
              opacity={hovered && hovered !== arc.name ? 0.3 : 1}
              style={{
                cursor: 'pointer',
                transition: 'opacity 0.2s ease, transform 0.15s ease',
                transformOrigin: `${cx}px ${cy}px`,
                transform: hovered === arc.name ? 'scale(1.04)' : 'scale(1)',
                filter: hovered === arc.name ? `drop-shadow(0 0 6px ${arc.fill})` : 'none',
              }}
              onMouseEnter={() => setHovered(arc.name)}
              onMouseLeave={() => setHovered(null)}
            />
          ))
        )}

        {/* Center label */}
        <text x={cx} y={cy - 10} textAnchor="middle" fill="var(--text-primary)" fontSize="26" fontWeight="700" fontFamily="Inter, sans-serif">
          {hoveredItem ? hoveredItem.value : total}
        </text>
        <text x={cx} y={cy + 12} textAnchor="middle" fill="var(--text-muted)" fontSize="10" fontFamily="Inter, sans-serif">
          {hoveredItem ? hoveredItem.name.toUpperCase() : 'TOTAL'}
        </text>
      </svg>
    </div>
  );
};



// ── Dashboard Page ────────────────────────────────────────────────────────────
export const DashboardPage: React.FC = () => {
  const [incidents, setIncidents] = useState<Incident[] | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [refreshing, setRefreshing] = useState(false);

  const loadDashboard = useCallback(async (refresh = false) => {
    refresh ? setRefreshing(true) : setLoading(true);
    setError(null);
    try {
      const incidentResult = await api.getIncidents().catch((err: unknown) => {
        setError(err instanceof ApiError ? err.message : 'Could not load dashboard information.');
        return null;
      });
      setIncidents(incidentResult);
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
      critical: incidents.filter((i) => i.severity.toLowerCase() === 'critical').length,
      inProgress: incidents.filter((i) =>
        ['new', 'investigating', 'containment', 'eradication', 'recovery', 'policy review', 'reporting'].includes(i.status.toLowerCase())
      ).length,
      completed: incidents.filter((i) => i.hasReport === true || i.status.toLowerCase() === 'resolved').length,
    };
  }, [incidents]);

  const severityDistribution = useMemo((): SeverityDistributionItem[] => {
    if (!incidents) return [];
    const counts = { Critical: 0, High: 0, Medium: 0, Low: 0, Info: 0 };
    for (const inc of incidents) {
      const sev = inc.severity as keyof typeof counts;
      if (sev in counts) counts[sev]++;
      else counts.Info++;
    }
    return [
      { name: 'Critical', value: counts.Critical, fill: '#e53e3e' },
      { name: 'High',     value: counts.High,     fill: '#f59e0b' },
      { name: 'Medium',   value: counts.Medium,   fill: '#eab308' },
      { name: 'Low',      value: counts.Low,       fill: '#48bb78' },
      { name: 'Info',     value: counts.Info,      fill: '#22d3ee' },
    ];
  }, [incidents]);

  const recentIncidents = useMemo(() =>
    incidents ? [...incidents].reverse().slice(0, 8) : [],
    [incidents]
  );

  return (
    <>
      <Header
        pageTitle="Security Operations Center"
        pageSubtitle="Monitor investigations, track threats, and follow incident analysis."
      />
      <main className="page-enter dashboard-workspace">
        {/* ── Header row ── */}
        <section className="dashboard-intro">
          <div>
            <div className="dashboard-eyebrow"><ShieldCheck size={15} /> CYBERORCHESTRA OPERATIONS</div>
            <h2>Investigation overview</h2>
            <p>Monitor security incidents managed by the six-agent CyberOrchestra pipeline.</p>
          </div>
          <div className="dashboard-actions">
            <Link className="primary-action" to="/incidents/new"><Plus size={18} /> New Investigation</Link>
          </div>
        </section>

        {error && (
          <div className="dashboard-error" role="alert">
            <AlertTriangle size={18} />
            <div><strong>Dashboard information is unavailable</strong><span>{error}</span></div>
            <button className="secondary-action" onClick={() => void loadDashboard()}>
              <RefreshCw size={15} /> Retry
            </button>
          </div>
        )}

        {/* ── KPI Stats ── */}
        <section className="dashboard-stats" aria-label="Incident statistics">
          {[
            { label: 'Total Incidents', value: counts?.total, icon: Activity, tone: 'cyan' },
            { label: 'Critical Incidents', value: counts?.critical, icon: ShieldAlert, tone: 'red' },
            { label: 'Active Investigations', value: counts?.inProgress, icon: Clock3, tone: 'amber' },
            { label: 'Completed Analyses', value: counts?.completed, icon: CheckCircle2, tone: 'green' },
          ].map(({ label, value, icon: Icon, tone }) => (
            <article className="dashboard-stat" key={label}>
              <span className={`stat-icon tone-${tone}`}><Icon size={18} /></span>
              <div>
                <span className="stat-label">{label}</span>
                <strong>{loading ? '—' : value === undefined ? '--' : value}</strong>
              </div>
            </article>
          ))}
        </section>

        {/* ── Two-column layout ── */}
        <section className="dashboard-columns">

          {/* LEFT: Severity Distribution Donut */}
          <article className="workspace-panel severity-panel">
            <div className="workspace-panel-heading">
              <div>
                <h3>Incident Severity Distribution</h3>
                <p>Breakdown of all incidents by severity level</p>
              </div>
              <button
                className="icon-action"
                aria-label="Refresh dashboard"
                title="Refresh"
                disabled={refreshing}
                onClick={() => void loadDashboard(true)}
              >
                <RefreshCw size={16} className={refreshing ? 'spin-icon' : ''} />
              </button>
            </div>

            {loading && !incidents ? (
              <div className="dashboard-state"><span className="loading-mark" /> Loading severity data…</div>
            ) : incidents && incidents.length === 0 ? (
              <div className="dashboard-empty">
                <ShieldCheck size={28} />
                <strong>No incidents yet</strong>
                <span>Submit an incident to see distribution.</span>
                <Link to="/incidents/new">Start investigation <ArrowRight size={14} /></Link>
              </div>
            ) : (
              <div className="donut-chart-section">
                <DonutChart data={severityDistribution} total={counts?.total ?? 0} />
                <div className="severity-legend">
                  {severityDistribution.map((item) => (
                    <div key={item.name} className="legend-row">
                      <span className="legend-dot" style={{ background: item.fill, boxShadow: `0 0 6px ${item.fill}` }} />
                      <span className="legend-name">{item.name}</span>
                      <span className="legend-value">{item.value}</span>
                      <div className="legend-bar-track">
                        <div
                          className="legend-bar-fill"
                          style={{
                            width: counts?.total ? `${Math.round((item.value / counts.total) * 100)}%` : '0%',
                            background: item.fill,
                          }}
                        />
                      </div>
                      <span className="legend-pct">
                        {counts?.total ? Math.round((item.value / counts.total) * 100) : 0}%
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </article>

          {/* RIGHT: Recent Investigations */}
          <article className="workspace-panel investigations-panel">
            <div className="workspace-panel-heading">
              <div><h3>Recent Investigations</h3><p>Latest incidents in the system</p></div>
            </div>

            {loading && !incidents ? (
              <div className="dashboard-state"><span className="loading-mark" /> Loading investigations…</div>
            ) : incidents?.length === 0 ? (
              <div className="dashboard-empty">
                <ShieldCheck size={25} />
                <strong>No investigations yet</strong>
                <span>Start by submitting an incident for analysis.</span>
                <Link to="/incidents?new=1">Create an investigation <ArrowRight size={14} /></Link>
              </div>
            ) : incidents ? (
              <div className="recent-inv-list">
                {recentIncidents.map((incident) => (
                  <Link
                    key={incident.id}
                    className="recent-inv-row"
                    to={`/incidents/${encodeURIComponent(incident.id)}`}
                  >
                    <div className="recent-inv-main">
                      <span className="incident-id">{incident.id}</span>
                      <strong className="recent-inv-title">{incident.title}</strong>
                      <span className="recent-inv-type">{incident.source}</span>
                    </div>
                    <div className="recent-inv-meta">
                      <SeverityBadge severity={incident.severity} />
                      <StatusBadge status={incident.status} />
                      <span className="recent-inv-date">
                        {incident.createdAt ? new Date(incident.createdAt).toLocaleDateString() : '—'}
                      </span>
                      <ArrowRight size={13} className="recent-inv-arrow" />
                    </div>
                  </Link>
                ))}
                {incidents.length > 8 && (
                  <Link className="view-all-link" to="/incidents">
                    View all {incidents.length} incidents <ArrowRight size={13} />
                  </Link>
                )}
              </div>
            ) : (
              <div className="dashboard-state"><WifiOff size={18} /> Incident data could not be loaded.</div>
            )}
          </article>
        </section>

        {/* ── Pipeline Workflow ── */}
        <section className="workspace-panel workflow-panel">
          <div className="workspace-panel-heading">
            <div>
              <h3>Analysis Pipeline</h3>
              <p>Six-agent CyberOrchestra workflow — Data Normalizer and Policy Engine are backend components</p>
            </div>
          </div>
          <div className="pipeline-track">
            {[
              { label: 'Threat Detection', icon: ShieldAlert, color: 'cyan', desc: 'Agent 1' },
              { label: 'Malware Analysis', icon: Activity, color: 'amber', desc: 'Agent 2 (parallel)' },
              { label: 'Log Analysis', icon: FileText, color: 'amber', desc: 'Agent 3 (parallel)' },
              { label: 'Vulnerability Assessment', icon: AlertTriangle, color: 'amber', desc: 'Agent 4 (parallel)' },
              { label: 'Recovery Planning', icon: RefreshCw, color: 'green', desc: 'Agent 5' },
              { label: 'Report Generation', icon: FileText, color: 'blue', desc: 'Agent 6' },
            ].map(({ label, icon: Icon, color, desc }, index, arr) => (
              <React.Fragment key={label}>
                <div className={`pipeline-step color-${color}`}>
                  <span className="pipeline-icon"><Icon size={16} /></span>
                  <span className="pipeline-label">{label}</span>
                  <small className="pipeline-desc">{desc}</small>
                </div>
                {index < arr.length - 1 && <span className="pipeline-connector" />}
              </React.Fragment>
            ))}
          </div>
          <div className="pipeline-note">
            <CheckCircle2 size={13} />
            <span>Threat intelligence enrichment, data normalization, and policy enforcement run automatically on the backend.</span>
          </div>
        </section>
      </main>
    </>
  );
};
