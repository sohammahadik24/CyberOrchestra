import React, { useEffect, useState, useCallback } from 'react';
import { useNavigate, useSearchParams } from 'react-router-dom';
import {
  Play,
  Plus,
  Search,
  RefreshCw,
  FolderOpen,
  X,
} from 'lucide-react';

import { Header } from '../components/layout/Header';
import { Panel } from '../components/ui/Panel';
import { SeverityBadge, StatusBadge } from '../components/ui/Badges';
import { api, ApiError } from '../services/api';
import type { Incident, IncidentDetail, ScenarioItem } from '../types';

export const IncidentsPage: React.FC = () => {
  const navigate = useNavigate();
  const [searchParams] = useSearchParams();
  const [incidents, setIncidents] = useState<Incident[]>([]);
  const [scenarios, setScenarios] = useState<ScenarioItem[]>([]);
  const [selectedIncident, setSelectedIncident] = useState<IncidentDetail | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [runningPipeline, setRunningPipeline] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [severityFilter, setSeverityFilter] = useState<string>('');
  const [statusFilter, setStatusFilter] = useState<string>('');

  // Modals
  const [showNewModal, setShowNewModal] = useState<boolean>(false);
  const [showScenarioModal, setShowScenarioModal] = useState<boolean>(false);
  const [rawJsonInput, setRawJsonInput] = useState<string>('');
  const [modalError, setModalError] = useState<string | null>(null);

  const fetchIncidents = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [incList, scenList] = await Promise.all([
        api.getIncidents({
          search: searchQuery || undefined,
          severity: severityFilter || undefined,
          status: statusFilter || undefined,
        }),
        api.getScenarios(),
      ]);
      setIncidents(incList);
      setScenarios(scenList);
    } catch (err: any) {
      setError(err instanceof ApiError ? err.message : 'Failed to fetch incidents.');
    } finally {
      setLoading(false);
    }
  }, [searchQuery, severityFilter, statusFilter]);

  useEffect(() => {
    fetchIncidents();
  }, [fetchIncidents]);

  useEffect(() => {
    const requestedIncident = searchParams.get('incident');
    const createNew = searchParams.get('new') === '1';
    if (requestedIncident) navigate(`/incidents/${encodeURIComponent(requestedIncident)}`, { replace: true });
    if (createNew) navigate('/incidents/new', { replace: true });
  }, [searchParams, navigate]);

  const handleRunPipeline = async (id: string) => {
    setRunningPipeline(true);
    try {
      await api.runPipeline(id);
      await fetchIncidents();
      navigate(`/incidents/${encodeURIComponent(id)}`);
    } catch {
      navigate(`/incidents/${encodeURIComponent(id)}`);
    } finally {
      setRunningPipeline(false);
    }
  };

  const handleLoadScenario = async (filename: string) => {
    setModalError(null);
    try {
      const created = await api.loadScenario(filename);
      setShowScenarioModal(false);
      await fetchIncidents();
      navigate(`/incidents/${encodeURIComponent(created.id)}`);
    } catch (err: any) {
      setModalError(err.message);
    }
  };

  const handleCreateRawIncident = async () => {
    setModalError(null);
    try {
      const parsed = JSON.parse(rawJsonInput);
      const created = await api.createIncident(parsed);
      setShowNewModal(false);
      setRawJsonInput('');
      await fetchIncidents();
      navigate(`/incidents/${encodeURIComponent(created.id)}`);
    } catch (err: any) {
      setModalError(err.message || 'Invalid JSON syntax.');
    }
  };

  return (
    <>
      <Header
        pageTitle="Incidents Management"
        pageSubtitle="All normalized security incidents, raw telemetry ingestion, and end-to-end pipeline execution"
        rightContent={
          <div style={{ display: 'flex', gap: '8px' }}>
            <button
              onClick={() => setShowScenarioModal(true)}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '6px',
                padding: '7px 14px',
                background: 'var(--cyan-glow)',
                border: '1px solid var(--cyan-border)',
                borderRadius: 'var(--radius-md)',
                color: 'var(--cyan-400)',
                fontSize: '12px',
                fontWeight: 600,
                cursor: 'pointer',
              }}
            >
              <FolderOpen size={14} /> Load Benchmark Scenario
            </button>
            <button
              onClick={() => navigate('/incidents/new')}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '6px',
                padding: '7px 14px',
                background: 'var(--bg-elevated)',
                border: '1px solid var(--border-default)',
                borderRadius: 'var(--radius-md)',
                color: 'var(--text-primary)',
                fontSize: '12px',
                fontWeight: 600,
                cursor: 'pointer',
              }}
            >
              <Plus size={14} /> New Investigation
            </button>
          </div>
        }
      />

      <main
        className="page-enter"
        style={{
          flex: 1,
          overflowY: 'auto',
          padding: '24px',
          display: 'flex',
          flexDirection: 'column',
          gap: '20px',
        }}
      >
        {/* Error notification banner */}
        {error && (
          <div
            style={{
              padding: '14px 18px',
              background: 'var(--red-glow)',
              border: '1px solid var(--red-border)',
              borderRadius: 'var(--radius-md)',
              color: 'var(--red-400)',
              fontSize: '13px',
              display: 'flex',
              alignItems: 'center',
              justifyContent: 'space-between',
            }}
          >
            <span>{error}</span>
            <button
              onClick={() => fetchIncidents()}
              style={{
                background: 'transparent',
                border: 'none',
                color: 'var(--red-400)',
                cursor: 'pointer',
                fontWeight: 600,
              }}
            >
              Retry
            </button>
          </div>
        )}

        {/* Filter Toolbar */}
        <div
          style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            gap: '12px',
            flexWrap: 'wrap',
          }}
        >
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flex: 1, maxWidth: '400px' }}>
            <div
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '8px',
                padding: '6px 12px',
                background: 'var(--bg-elevated)',
                border: '1px solid var(--border-dim)',
                borderRadius: 'var(--radius-md)',
                width: '100%',
              }}
            >
              <Search size={14} style={{ color: 'var(--text-muted)' }} />
              <input
                type="text"
                placeholder="Search incident ID, description, or IOCs..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                style={{
                  background: 'transparent',
                  border: 'none',
                  color: 'var(--text-primary)',
                  fontSize: '12px',
                  width: '100%',
                  outline: 'none',
                }}
              />
            </div>
          </div>

          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            <select
              value={severityFilter}
              onChange={(e) => setSeverityFilter(e.target.value)}
              style={{
                padding: '6px 12px',
                background: 'var(--bg-elevated)',
                border: '1px solid var(--border-dim)',
                borderRadius: 'var(--radius-md)',
                color: 'var(--text-secondary)',
                fontSize: '12px',
                cursor: 'pointer',
              }}
            >
              <option value="">All Severities</option>
              <option value="Critical">Critical</option>
              <option value="High">High</option>
              <option value="Medium">Medium</option>
              <option value="Low">Low</option>
            </select>

            <select
              value={statusFilter}
              onChange={(e) => setStatusFilter(e.target.value)}
              style={{
                padding: '6px 12px',
                background: 'var(--bg-elevated)',
                border: '1px solid var(--border-dim)',
                borderRadius: 'var(--radius-md)',
                color: 'var(--text-secondary)',
                fontSize: '12px',
                cursor: 'pointer',
              }}
            >
              <option value="">All Statuses</option>
              <option value="New">New</option>
              <option value="Investigating">Investigating</option>
              <option value="Policy Review">Policy Review</option>
              <option value="Resolved">Resolved</option>
            </select>

            <button
              onClick={() => fetchIncidents()}
              style={{
                display: 'flex',
                alignItems: 'center',
                gap: '6px',
                padding: '6px 12px',
                background: 'var(--bg-elevated)',
                border: '1px solid var(--border-dim)',
                borderRadius: 'var(--radius-md)',
                color: 'var(--text-secondary)',
                fontSize: '12px',
                cursor: 'pointer',
              }}
            >
              <RefreshCw size={12} /> Sync
            </button>
          </div>
        </div>

        {/* Incidents Table */}
        <Panel
          title="Canonical Incident Repository"
          subtitle={`${incidents.length} normalized incidents from actual telemetry`}
          noPadding
        >
          {loading && incidents.length === 0 ? (
            <div style={{ padding: '40px', textAlign: 'center', color: 'var(--text-muted)', fontSize: '13px' }}>
              Loading incidents from backend...
            </div>
          ) : incidents.length === 0 ? (
            <div style={{ padding: '40px', textAlign: 'center', color: 'var(--text-muted)', fontSize: '13px' }}>
              No incidents found matching your query.
            </div>
          ) : (
            <div style={{ overflowX: 'auto' }}>
              <table style={{ width: '100%', borderCollapse: 'collapse' }}>
                <thead>
                  <tr>
                    {['ID', 'Description', 'Severity', 'Status', 'Stage', 'IOCs', 'Evidence', 'Created', 'Action'].map(
                      (h) => (
                        <th
                          key={h}
                          style={{
                            padding: '10px 14px',
                            textAlign: 'left',
                            fontSize: '10px',
                            fontWeight: 600,
                            color: 'var(--text-muted)',
                            textTransform: 'uppercase',
                            letterSpacing: '0.08em',
                            borderBottom: '1px solid var(--border-subtle)',
                            whiteSpace: 'nowrap',
                          }}
                        >
                          {h}
                        </th>
                      )
                    )}
                  </tr>
                </thead>
                <tbody>
                  {incidents.map((inc) => (
                    <tr
                      key={inc.id}
                      onClick={() => navigate(`/incidents/${encodeURIComponent(inc.id)}`)}
                      style={{
                        borderBottom: '1px solid var(--border-subtle)',
                        cursor: 'pointer',
                        background: selectedIncident?.summary.id === inc.id ? 'var(--bg-hover)' : 'transparent',
                        transition: 'background var(--transition-fast)',
                      }}
                      onMouseEnter={(e) => ((e.currentTarget as HTMLElement).style.background = 'var(--bg-hover)')}
                      onMouseLeave={(e) => {
                        if (selectedIncident?.summary.id !== inc.id) {
                          (e.currentTarget as HTMLElement).style.background = 'transparent';
                        }
                      }}
                    >
                      <td
                        style={{
                          padding: '12px 14px',
                          fontFamily: 'var(--font-mono)',
                          fontSize: '11px',
                          color: 'var(--cyan-400)',
                          whiteSpace: 'nowrap',
                          fontWeight: 600,
                        }}
                      >
                        {inc.id}
                      </td>
                      <td style={{ padding: '12px 14px', maxWidth: '240px' }}>
                        <span
                          style={{
                            fontSize: '12px',
                            color: 'var(--text-primary)',
                            display: 'block',
                            overflow: 'hidden',
                            textOverflow: 'ellipsis',
                            whiteSpace: 'nowrap',
                          }}
                        >
                          {inc.title}
                        </span>
                      </td>
                      <td style={{ padding: '12px 14px' }}>
                        <SeverityBadge severity={inc.severity} />
                      </td>
                      <td style={{ padding: '12px 14px' }}>
                        <StatusBadge status={inc.status} />
                      </td>
                      <td
                        style={{
                          padding: '12px 14px',
                          fontSize: '12px',
                          color: 'var(--text-secondary)',
                          whiteSpace: 'nowrap',
                        }}
                      >
                        {inc.pipelineStage}
                      </td>
                      <td style={{ padding: '12px 14px' }}>
                        <span
                          style={{
                            fontSize: '11px',
                            padding: '2px 6px',
                            background: 'var(--bg-elevated)',
                            borderRadius: '4px',
                            color: 'var(--text-secondary)',
                            fontFamily: 'var(--font-mono)',
                          }}
                        >
                          {inc.indicatorCount || inc.iocs.length}
                        </span>
                      </td>
                      <td style={{ padding: '12px 14px' }}>
                        <span
                          style={{
                            fontSize: '11px',
                            padding: '2px 6px',
                            background: 'var(--bg-elevated)',
                            borderRadius: '4px',
                            color: 'var(--text-secondary)',
                            fontFamily: 'var(--font-mono)',
                          }}
                        >
                          {inc.evidenceCount || 0}
                        </span>
                      </td>
                      <td
                        style={{
                          padding: '12px 14px',
                          fontSize: '11px',
                          color: 'var(--text-muted)',
                          fontFamily: 'var(--font-mono)',
                          whiteSpace: 'nowrap',
                        }}
                      >
                        {new Date(inc.createdAt).toLocaleDateString()}
                      </td>
                      <td style={{ padding: '12px 14px' }}>
                        <button
                          onClick={(e) => {
                            e.stopPropagation();
                            handleRunPipeline(inc.id);
                          }}
                          disabled={runningPipeline}
                          style={{
                            display: 'flex',
                            alignItems: 'center',
                            gap: '4px',
                            padding: '5px 10px',
                            background: 'var(--cyan-glow)',
                            border: '1px solid var(--cyan-border)',
                            borderRadius: 'var(--radius-md)',
                            color: 'var(--cyan-400)',
                            fontSize: '11px',
                            fontWeight: 600,
                            cursor: runningPipeline ? 'not-allowed' : 'pointer',
                          }}
                        >
                          <Play size={11} /> Launch Pipeline
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Panel>

        {/* Incident Inspection & Pipeline Results Inspector */}
        {selectedIncident && (
          <Panel
            title={`Incident Inspector: ${selectedIncident.summary.id}`}
            subtitle={`${selectedIncident.incident.description} (${selectedIncident.incident.incident_type})`}
            headerRight={
              <div style={{ display: 'flex', gap: '8px' }}>
                <button
                  onClick={() => handleRunPipeline(selectedIncident.summary.id)}
                  disabled={runningPipeline}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: '6px',
                    padding: '6px 14px',
                    background: 'var(--cyan-glow)',
                    border: '1px solid var(--cyan-border)',
                    borderRadius: 'var(--radius-md)',
                    color: 'var(--cyan-400)',
                    fontSize: '12px',
                    fontWeight: 600,
                    cursor: runningPipeline ? 'not-allowed' : 'pointer',
                  }}
                >
                  <Play size={13} className={runningPipeline ? 'spin-icon' : ''} />
                  {runningPipeline ? 'Executing 8 Agents...' : 'Run Full Pipeline'}
                </button>
                <button
                  onClick={() => setSelectedIncident(null)}
                  style={{
                    background: 'transparent',
                    border: '1px solid var(--border-dim)',
                    borderRadius: 'var(--radius-md)',
                    color: 'var(--text-muted)',
                    cursor: 'pointer',
                    padding: '4px 8px',
                  }}
                >
                  <X size={14} />
                </button>
              </div>
            }
          >
            <div style={{ display: 'flex', flexDirection: 'column', gap: '16px' }}>
              {/* Pipeline Stage Progress Track */}
              {selectedIncident.execution_history && selectedIncident.execution_history.length > 0 && (
                <div>
                  <h4 style={{ fontSize: '13px', color: 'var(--text-primary)', marginBottom: '10px' }}>
                    Pipeline Execution Stages
                  </h4>
                  <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(280px, 1fr))', gap: '10px' }}>
                    {selectedIncident.execution_history.map((st, idx) => (
                      <div
                        key={idx}
                        style={{
                          padding: '12px',
                          background: 'var(--bg-elevated)',
                          border: `1px solid ${st.status === 'completed' ? 'var(--green-border)' : st.status === 'error' ? 'var(--red-border)' : 'var(--border-dim)'}`,
                          borderRadius: 'var(--radius-md)',
                        }}
                      >
                        <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '4px' }}>
                          <span style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-primary)' }}>
                            {st.stage}
                          </span>
                          <span style={{ fontSize: '11px', color: 'var(--text-muted)', fontFamily: 'var(--font-mono)' }}>
                            {st.duration}
                          </span>
                        </div>
                        <div style={{ fontSize: '11px', color: 'var(--cyan-400)', marginBottom: '4px' }}>
                          Model: {st.model}
                        </div>
                        <p style={{ fontSize: '11px', color: 'var(--text-secondary)', margin: 0, lineHeight: 1.4 }}>
                          {st.details}
                        </p>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Indicators & Evidence */}
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '16px' }}>
                <div
                  style={{
                    padding: '14px',
                    background: 'var(--bg-elevated)',
                    borderRadius: 'var(--radius-md)',
                    border: '1px solid var(--border-dim)',
                  }}
                >
                  <h5 style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-primary)', marginBottom: '10px' }}>
                    Normalized Indicators ({selectedIncident.incident.indicators.length})
                  </h5>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '6px' }}>
                    {selectedIncident.incident.indicators.map((ind, i) => (
                      <div
                        key={i}
                        style={{
                          display: 'flex',
                          alignItems: 'center',
                          justifyContent: 'space-between',
                          padding: '6px 10px',
                          background: 'var(--bg-hover)',
                          borderRadius: 'var(--radius-sm)',
                          fontSize: '11px',
                        }}
                      >
                        <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--cyan-400)' }}>{ind.value}</span>
                        <span style={{ color: 'var(--text-muted)' }}>{ind.indicator_type}</span>
                      </div>
                    ))}
                  </div>
                </div>

                <div
                  style={{
                    padding: '14px',
                    background: 'var(--bg-elevated)',
                    borderRadius: 'var(--radius-md)',
                    border: '1px solid var(--border-dim)',
                  }}
                >
                  <h5 style={{ fontSize: '12px', fontWeight: 600, color: 'var(--text-primary)', marginBottom: '10px' }}>
                    Forensic Evidence Artifacts ({selectedIncident.incident.evidence.length})
                  </h5>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: '6px', maxHeight: '180px', overflowY: 'auto' }}>
                    {selectedIncident.incident.evidence.map((evid, i) => (
                      <div
                        key={i}
                        style={{
                          padding: '6px 10px',
                          background: 'var(--bg-hover)',
                          borderRadius: 'var(--radius-sm)',
                          fontSize: '11px',
                        }}
                      >
                        <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '2px' }}>
                          <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--amber-400)' }}>
                            {evid.evidence_id}
                          </span>
                          <span style={{ color: 'var(--text-muted)' }}>{evid.evidence_type}</span>
                        </div>
                        <p style={{ margin: 0, color: 'var(--text-secondary)' }}>{evid.description}</p>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          </Panel>
        )}
      </main>

      {/* Scenario Loader Modal */}
      {showScenarioModal && (
        <div
          style={{
            position: 'fixed',
            inset: 0,
            background: 'rgba(0,0,0,0.7)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            zIndex: 1000,
            padding: '20px',
          }}
        >
          <div
            style={{
              background: 'var(--bg-surface)',
              border: '1px solid var(--border-default)',
              borderRadius: 'var(--radius-lg)',
              width: '100%',
              maxWidth: '650px',
              padding: '24px',
              boxShadow: 'var(--shadow-lg)',
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
              <h3 style={{ fontSize: '16px', fontWeight: 700, color: 'var(--text-primary)', margin: 0 }}>
                Load Ground-Truth Benchmark Scenario
              </h3>
              <button
                onClick={() => setShowScenarioModal(false)}
                style={{ background: 'transparent', border: 'none', color: 'var(--text-muted)', cursor: 'pointer' }}
              >
                <X size={18} />
              </button>
            </div>
            <p style={{ fontSize: '12px', color: 'var(--text-secondary)', marginBottom: '16px' }}>
              Select a pre-packaged benchmark scenario from <code>backend/data/raw/incidents/</code> to test the pipeline with
              auditable, grounded telemetry.
            </p>

            {modalError && (
              <div
                style={{
                  padding: '10px 14px',
                  background: 'var(--red-glow)',
                  border: '1px solid var(--red-border)',
                  borderRadius: 'var(--radius-md)',
                  color: 'var(--red-400)',
                  fontSize: '12px',
                  marginBottom: '14px',
                }}
              >
                {modalError}
              </div>
            )}

            <div style={{ display: 'flex', flexDirection: 'column', gap: '10px', maxHeight: '360px', overflowY: 'auto' }}>
              {scenarios.map((scen) => (
                <div
                  key={scen.filename}
                  style={{
                    padding: '14px',
                    background: 'var(--bg-elevated)',
                    border: '1px solid var(--border-dim)',
                    borderRadius: 'var(--radius-md)',
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'space-between',
                  }}
                >
                  <div style={{ maxWidth: '450px' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '4px' }}>
                      <span style={{ fontFamily: 'var(--font-mono)', fontSize: '12px', fontWeight: 700, color: 'var(--cyan-400)' }}>
                        {scen.incident_id}
                      </span>
                      <span style={{ fontSize: '11px', color: 'var(--text-muted)' }}>({scen.filename})</span>
                    </div>
                    <p style={{ fontSize: '12px', color: 'var(--text-secondary)', margin: 0 }}>{scen.description}</p>
                    <div style={{ marginTop: '6px', fontSize: '11px', color: 'var(--text-muted)' }}>
                      {scen.indicatorsCount} Indicators · {scen.evidenceCount} Evidence Items · Source: {scen.source}
                    </div>
                  </div>
                  <button
                    onClick={() => handleLoadScenario(scen.filename)}
                    style={{
                      padding: '7px 14px',
                      background: 'var(--cyan-glow)',
                      border: '1px solid var(--cyan-border)',
                      borderRadius: 'var(--radius-md)',
                      color: 'var(--cyan-400)',
                      fontSize: '12px',
                      fontWeight: 600,
                      cursor: 'pointer',
                      whiteSpace: 'nowrap',
                    }}
                  >
                    Import & Ingest
                  </button>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* Raw JSON Ingestion Modal */}
      {showNewModal && (
        <div
          style={{
            position: 'fixed',
            inset: 0,
            background: 'rgba(0,0,0,0.7)',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            zIndex: 1000,
            padding: '20px',
          }}
        >
          <div
            style={{
              background: 'var(--bg-surface)',
              border: '1px solid var(--border-default)',
              borderRadius: 'var(--radius-lg)',
              width: '100%',
              maxWidth: '650px',
              padding: '24px',
              boxShadow: 'var(--shadow-lg)',
            }}
          >
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '16px' }}>
              <h3 style={{ fontSize: '16px', fontWeight: 700, color: 'var(--text-primary)', margin: 0 }}>
                Ingest Raw Telemetry JSON
              </h3>
              <button
                onClick={() => setShowNewModal(false)}
                style={{ background: 'transparent', border: 'none', color: 'var(--text-muted)', cursor: 'pointer' }}
              >
                <X size={18} />
              </button>
            </div>
            <p style={{ fontSize: '12px', color: 'var(--text-secondary)', marginBottom: '14px' }}>
              Submit heterogeneous raw incident JSON. The Data Normalizer service will standardize indicators and forensic
              evidence into canonical format.
            </p>

            {modalError && (
              <div
                style={{
                  padding: '10px 14px',
                  background: 'var(--red-glow)',
                  border: '1px solid var(--red-border)',
                  borderRadius: 'var(--radius-md)',
                  color: 'var(--red-400)',
                  fontSize: '12px',
                  marginBottom: '14px',
                }}
              >
                {modalError}
              </div>
            )}

            <textarea
              rows={12}
              value={rawJsonInput}
              onChange={(e) => setRawJsonInput(e.target.value)}
              style={{
                width: '100%',
                background: 'var(--bg-elevated)',
                border: '1px solid var(--border-dim)',
                borderRadius: 'var(--radius-md)',
                color: 'var(--text-primary)',
                fontFamily: 'var(--font-mono)',
                fontSize: '12px',
                padding: '12px',
                outline: 'none',
                boxSizing: 'border-box',
                marginBottom: '16px',
              }}
            />

            <div style={{ display: 'flex', justifyContent: 'flex-end', gap: '10px' }}>
              <button
                onClick={() => setShowNewModal(false)}
                style={{
                  padding: '8px 16px',
                  background: 'transparent',
                  border: '1px solid var(--border-dim)',
                  borderRadius: 'var(--radius-md)',
                  color: 'var(--text-secondary)',
                  fontSize: '12px',
                  cursor: 'pointer',
                }}
              >
                Cancel
              </button>
              <button
                onClick={handleCreateRawIncident}
                style={{
                  padding: '8px 18px',
                  background: 'var(--cyan-glow)',
                  border: '1px solid var(--cyan-border)',
                  borderRadius: 'var(--radius-md)',
                  color: 'var(--cyan-400)',
                  fontSize: '12px',
                  fontWeight: 600,
                  cursor: 'pointer',
                }}
              >
                Normalize & Register Incident
              </button>
            </div>
          </div>
        </div>
      )}
    </>
  );
};
