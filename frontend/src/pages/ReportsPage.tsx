import React, { useEffect, useState, useCallback } from 'react';
import {
  FileText,
  Download,
  ExternalLink,
  RefreshCw,
  X,
} from 'lucide-react';

import { Header } from '../components/layout/Header';
import { Panel } from '../components/ui/Panel';
import { api, ApiError } from '../services/api';
import type { ReportDetail, ReportSummary } from '../types';

export const ReportsPage: React.FC = () => {
  const [reports, setReports] = useState<ReportSummary[]>([]);
  const [selectedReport, setSelectedReport] = useState<ReportDetail | null>(null);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  const fetchReports = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await api.getReports();
      setReports(data);
    } catch (err: any) {
      setError(err instanceof ApiError ? err.message : 'Failed to fetch reports.');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchReports();
  }, [fetchReports]);

  const handleViewReport = async (reportId: string) => {
    try {
      const detail = await api.getReport(reportId);
      setSelectedReport(detail);
    } catch (err: any) {
      alert(`Could not load report details: ${err.message}`);
    }
  };

  const handleExportJson = (report: ReportDetail) => {
    const blob = new Blob([JSON.stringify(report, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${report.id}.json`;
    a.click();
    URL.revokeObjectURL(url);
  };

  return (
    <>
      <Header
        pageTitle="Incident Reports"
        pageSubtitle="Synthesized reports from Report Generation Agent (Groq qwen3-32b) with full evidence grounding"
        rightContent={
          <button
            onClick={() => fetchReports()}
            style={{
              display: 'flex',
              alignItems: 'center',
              gap: '6px',
              padding: '6px 14px',
              background: 'var(--bg-elevated)',
              border: '1px solid var(--border-dim)',
              borderRadius: 'var(--radius-md)',
              color: 'var(--text-secondary)',
              fontSize: '12px',
              cursor: 'pointer',
            }}
          >
            <RefreshCw size={13} /> Refresh Reports
          </button>
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
              onClick={() => fetchReports()}
              style={{ background: 'transparent', border: 'none', color: 'var(--red-400)', cursor: 'pointer', fontWeight: 600 }}
            >
              Retry
            </button>
          </div>
        )}

        <Panel
          title="Generated Incident Reports"
          subtitle={`${reports.length} synthesized incident reports in repository`}
        >
          {loading && reports.length === 0 ? (
            <div style={{ padding: '40px', textAlign: 'center', color: 'var(--text-muted)' }}>
              Loading reports from backend...
            </div>
          ) : reports.length === 0 ? (
            <div style={{ padding: '40px', textAlign: 'center', color: 'var(--text-muted)' }}>
              No incident reports generated yet. Go to Incidents and run the CyberOrchestra pipeline to synthesize reports.
            </div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '12px' }}>
              {reports.map((rep) => (
                <div
                  key={rep.id}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: '16px',
                    padding: '16px',
                    background: 'var(--bg-elevated)',
                    border: '1px solid var(--border-dim)',
                    borderRadius: 'var(--radius-md)',
                    transition: 'border-color var(--transition-base)',
                  }}
                  onMouseEnter={(e) => ((e.currentTarget as HTMLElement).style.borderColor = 'var(--border-default)')}
                  onMouseLeave={(e) => ((e.currentTarget as HTMLElement).style.borderColor = 'var(--border-dim)')}
                >
                  <div
                    style={{
                      width: 44,
                      height: 44,
                      background: 'rgba(59,130,246,0.10)',
                      border: '1px solid var(--blue-border)',
                      borderRadius: 'var(--radius-md)',
                      display: 'flex',
                      alignItems: 'center',
                      justifyContent: 'center',
                      flexShrink: 0,
                    }}
                  >
                    <FileText size={20} style={{ color: 'var(--blue-500)' }} />
                  </div>

                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '4px' }}>
                      <span style={{ fontSize: '14px', fontWeight: 700, color: 'var(--text-primary)' }}>
                        {rep.title}
                      </span>
                      <span
                        style={{
                          fontSize: '11px',
                          padding: '1px 6px',
                          background: 'var(--bg-hover)',
                          borderRadius: '4px',
                          color: rep.riskLevel.toLowerCase() === 'high' ? 'var(--red-400)' : 'var(--amber-400)',
                          fontWeight: 600,
                        }}
                      >
                        {rep.riskLevel.toUpperCase()} RISK
                      </span>
                    </div>

                    <p
                      style={{
                        fontSize: '12px',
                        color: 'var(--text-secondary)',
                        margin: '0 0 6px 0',
                        overflow: 'hidden',
                        textOverflow: 'ellipsis',
                        whiteSpace: 'nowrap',
                      }}
                    >
                      {rep.executiveSummary}
                    </p>

                    <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
                      <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--cyan-400)' }}>
                        {rep.incident}
                      </span>
                      {' · '}
                      {rep.findingsCount} Findings · {rep.recommendationsCount} Recovery Actions · Generated{' '}
                      {new Date(rep.generatedAt).toLocaleString()}
                    </div>
                  </div>

                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px', flexShrink: 0 }}>
                    <button
                      onClick={() => handleViewReport(rep.id)}
                      style={{
                        display: 'flex',
                        alignItems: 'center',
                        gap: '4px',
                        padding: '6px 14px',
                        background: 'var(--cyan-glow)',
                        border: '1px solid var(--cyan-border)',
                        borderRadius: 'var(--radius-md)',
                        color: 'var(--cyan-400)',
                        fontSize: '12px',
                        fontWeight: 600,
                        cursor: 'pointer',
                      }}
                    >
                      <ExternalLink size={13} /> View Report
                    </button>
                  </div>
                </div>
              ))}
            </div>
          )}
        </Panel>

        {/* Complete Report Modal */}
        {selectedReport && (
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
                maxWidth: '850px',
                maxHeight: '90vh',
                overflowY: 'auto',
                padding: '28px',
                boxShadow: 'var(--shadow-lg)',
              }}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '16px' }}>
                <div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '4px' }}>
                    <span style={{ fontFamily: 'var(--font-mono)', fontSize: '13px', color: 'var(--cyan-400)' }}>
                      {selectedReport.id}
                    </span>
                    <span className="badge badge-resolved">{selectedReport.status}</span>
                  </div>
                  <h2 style={{ fontSize: '18px', fontWeight: 800, color: 'var(--text-primary)', margin: 0 }}>
                    {selectedReport.title}
                  </h2>
                </div>
                <div style={{ display: 'flex', gap: '8px' }}>
                  <button
                    onClick={() => handleExportJson(selectedReport)}
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      gap: '4px',
                      padding: '6px 12px',
                      background: 'var(--bg-elevated)',
                      border: '1px solid var(--border-dim)',
                      borderRadius: 'var(--radius-md)',
                      color: 'var(--text-secondary)',
                      fontSize: '12px',
                      cursor: 'pointer',
                    }}
                  >
                    <Download size={13} /> Export JSON
                  </button>
                  <button
                    onClick={() => setSelectedReport(null)}
                    style={{ background: 'transparent', border: 'none', color: 'var(--text-muted)', cursor: 'pointer' }}
                  >
                    <X size={20} />
                  </button>
                </div>
              </div>

              {/* Executive Summary */}
              <div
                style={{
                  padding: '16px',
                  background: 'var(--bg-elevated)',
                  border: '1px solid var(--border-dim)',
                  borderRadius: 'var(--radius-md)',
                  marginBottom: '20px',
                }}
              >
                <h4 style={{ fontSize: '13px', fontWeight: 700, color: 'var(--cyan-400)', marginBottom: '8px' }}>
                  Executive Summary
                </h4>
                <p style={{ fontSize: '13px', color: 'var(--text-primary)', lineHeight: 1.6, margin: 0 }}>
                  {selectedReport.executiveSummary}
                </p>
              </div>

              {/* Findings */}
              <div style={{ marginBottom: '20px' }}>
                <h4 style={{ fontSize: '14px', fontWeight: 700, color: 'var(--text-primary)', marginBottom: '10px' }}>
                  Threat Assessment Findings
                </h4>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '8px' }}>
                  {selectedReport.threatAssessment.map((f, i) => (
                    <div
                      key={i}
                      style={{
                        padding: '12px',
                        background: 'var(--bg-elevated)',
                        borderRadius: 'var(--radius-md)',
                        border: '1px solid var(--border-subtle)',
                        fontSize: '12px',
                      }}
                    >
                      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '4px' }}>
                        <span style={{ fontWeight: 600, color: 'var(--text-primary)' }}>{f.finding}</span>
                        <span style={{ color: 'var(--green-400)', textTransform: 'capitalize' }}>{f.status}</span>
                      </div>
                      <span style={{ color: 'var(--text-muted)', fontSize: '11px' }}>
                        Evidence: {f.supporting_evidence_ids.join(', ')}
                      </span>
                    </div>
                  ))}
                </div>
              </div>

              {/* Recovery Recommendations & Policy Decisions */}
              <div style={{ marginBottom: '20px' }}>
                <h4 style={{ fontSize: '14px', fontWeight: 700, color: 'var(--text-primary)', marginBottom: '10px' }}>
                  Recovery Recommendations & Deterministic Policy Decisions
                </h4>
                <div style={{ display: 'flex', flexDirection: 'column', gap: '10px' }}>
                  {selectedReport.recoveryRecommendations.map((rec, i) => {
                    const dec = selectedReport.policyDecisions.find((d) => d.action === rec.recovery_action);
                    return (
                      <div
                        key={i}
                        style={{
                          padding: '14px',
                          background: 'var(--bg-elevated)',
                          borderRadius: 'var(--radius-md)',
                          border: '1px solid var(--border-dim)',
                        }}
                      >
                        <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: '6px' }}>
                          <span style={{ fontSize: '13px', fontWeight: 600, color: 'var(--text-primary)' }}>
                            {rec.recovery_action}
                          </span>
                          <span
                            style={{
                              fontSize: '11px',
                              fontWeight: 700,
                              color:
                                dec?.decision.toLowerCase() === 'approved'
                                  ? 'var(--green-400)'
                                  : dec?.decision.toLowerCase() === 'requires_approval'
                                  ? 'var(--amber-400)'
                                  : 'var(--red-400)',
                            }}
                          >
                            Policy: {dec?.decision} ({dec?.policy_rule_id})
                          </span>
                        </div>
                        <p style={{ fontSize: '12px', color: 'var(--text-secondary)', margin: '0 0 6px 0' }}>
                          Rationale: {rec.rationale}
                        </p>
                        <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
                          Evidence: {rec.supporting_evidence_ids.join(', ')} · Expected: {rec.expected_outcome}
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>
            </div>
          </div>
        )}
      </main>
    </>
  );
};
