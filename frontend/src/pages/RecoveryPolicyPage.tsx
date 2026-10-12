import React, { useEffect, useState, useCallback } from 'react';
import {
  CheckCircle2,
  XCircle,
  Clock,
  RefreshCw,
} from 'lucide-react';

import { Header } from '../components/layout/Header';
import { Panel } from '../components/ui/Panel';
import { api, ApiError } from '../services/api';
import type { PolicyReview } from '../types';

export const RecoveryPolicyPage: React.FC = () => {
  const [reviews, setReviews] = useState<PolicyReview[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [actionLoading, setActionLoading] = useState<string | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [statusFilter, setStatusFilter] = useState<string>('');

  const fetchReviews = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await api.getPolicyReviews(statusFilter || undefined);
      setReviews(data);
    } catch (err: any) {
      setError(err instanceof ApiError ? err.message : 'Failed to fetch policy reviews.');
    } finally {
      setLoading(false);
    }
  }, [statusFilter]);

  useEffect(() => {
    fetchReviews();
  }, [fetchReviews]);

  const handleApprove = async (id: string) => {
    setActionLoading(id);
    try {
      await api.approvePolicyReview(id, 'Approved by Human SOC Analyst');
      await fetchReviews();
    } catch (err: any) {
      alert(`Approval failed: ${err.message}`);
    } finally {
      setActionLoading(null);
    }
  };

  const handleReject = async (id: string) => {
    setActionLoading(id);
    try {
      await api.rejectPolicyReview(id, 'Rejected by Human SOC Analyst');
      await fetchReviews();
    } catch (err: any) {
      alert(`Rejection failed: ${err.message}`);
    } finally {
      setActionLoading(null);
    }
  };

  const pendingCount = reviews.filter((r) => r.status === 'Pending').length;
  const approvedCount = reviews.filter((r) => r.status === 'Approved').length;
  const rejectedCount = reviews.filter((r) => r.status === 'Rejected').length;

  return (
    <>
      <Header
        pageTitle="Recovery & Deterministic Policy"
        pageSubtitle="Pure deterministic policy evaluation (PE-001..PE-004) — human-in-the-loop review queue"
        rightContent={
          <button
            onClick={() => fetchReviews()}
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
            <RefreshCw size={13} /> Refresh Queue
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
              onClick={() => fetchReviews()}
              style={{ background: 'transparent', border: 'none', color: 'var(--red-400)', cursor: 'pointer', fontWeight: 600 }}
            >
              Retry
            </button>
          </div>
        )}

        {/* Status Count Summary */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: '16px' }}>
          {[
            { label: 'Pending Human Review', value: pendingCount, color: 'var(--amber-400)', border: 'var(--amber-border)' },
            { label: 'Approved Actions', value: approvedCount, color: 'var(--green-400)', border: 'var(--green-border)' },
            { label: 'Rejected Actions', value: rejectedCount, color: 'var(--red-400)', border: 'var(--red-border)' },
          ].map((s) => (
            <div key={s.label} className="card" style={{ padding: '20px', borderColor: s.border }}>
              <div style={{ fontSize: '32px', fontWeight: 800, color: s.color, lineHeight: 1 }}>{s.value}</div>
              <div style={{ fontSize: '12px', color: 'var(--text-secondary)', marginTop: '6px', fontWeight: 500 }}>
                {s.label}
              </div>
            </div>
          ))}
        </div>

        {/* Filter and Rule Guide */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
          <div style={{ display: 'flex', gap: '8px' }}>
            {['', 'Pending', 'Approved', 'Rejected'].map((status) => (
              <button
                key={status}
                onClick={() => setStatusFilter(status)}
                style={{
                  padding: '5px 12px',
                  background: statusFilter === status ? 'var(--cyan-glow)' : 'var(--bg-elevated)',
                  border: `1px solid ${statusFilter === status ? 'var(--cyan-border)' : 'var(--border-dim)'}`,
                  borderRadius: 'var(--radius-md)',
                  color: statusFilter === status ? 'var(--cyan-400)' : 'var(--text-secondary)',
                  fontSize: '12px',
                  fontWeight: 600,
                  cursor: 'pointer',
                }}
              >
                {status || 'All Decisions'}
              </button>
            ))}
          </div>

          <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>
            Deterministic Rules: <strong>PE-001</strong> (Citations) · <strong>PE-002</strong> (High Risk) · <strong>PE-003</strong> (Uncertainty) · <strong>PE-004</strong> (Auto-Approve)
          </span>
        </div>

        {/* Policy Review Queue */}
        <Panel
          title="Deterministic Policy Review Queue"
          subtitle="Actions evaluated strictly by rule engine; human approval required for high-risk operations"
        >
          {loading && reviews.length === 0 ? (
            <div style={{ padding: '40px', textAlign: 'center', color: 'var(--text-muted)' }}>
              Loading policy evaluation queue...
            </div>
          ) : reviews.length === 0 ? (
            <div style={{ padding: '40px', textAlign: 'center', color: 'var(--text-muted)' }}>
              No policy decisions in this queue. Run the pipeline on an incident to generate recovery recommendations.
            </div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
              {reviews.map((rev) => (
                <div
                  key={rev.id}
                  style={{
                    padding: '18px',
                    background: 'var(--bg-elevated)',
                    border: `1px solid ${
                      rev.status === 'Pending'
                        ? 'var(--amber-border)'
                        : rev.status === 'Approved'
                        ? 'var(--green-border)'
                        : 'var(--red-border)'
                    }`,
                    borderRadius: 'var(--radius-md)',
                  }}
                >
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '10px' }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                      {rev.status === 'Pending' ? (
                        <Clock size={16} style={{ color: 'var(--amber-400)' }} />
                      ) : rev.status === 'Approved' ? (
                        <CheckCircle2 size={16} style={{ color: 'var(--green-400)' }} />
                      ) : (
                        <XCircle size={16} style={{ color: 'var(--red-400)' }} />
                      )}
                      <span style={{ fontFamily: 'var(--font-mono)', fontSize: '13px', fontWeight: 700, color: 'var(--cyan-400)' }}>
                        {rev.id}
                      </span>
                      <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>→ Incident: {rev.incident}</span>
                      <span
                        style={{
                          fontSize: '11px',
                          padding: '2px 8px',
                          background: 'var(--bg-hover)',
                          borderRadius: '4px',
                          color: 'var(--cyan-300)',
                          fontFamily: 'var(--font-mono)',
                        }}
                      >
                        Rule {rev.policy_rule_id}
                      </span>
                    </div>

                    <div style={{ display: 'flex', gap: '8px' }}>
                      {rev.status === 'Pending' && (
                        <>
                          <button
                            onClick={() => handleApprove(rev.id)}
                            disabled={actionLoading === rev.id}
                            style={{
                              padding: '6px 16px',
                              background: 'var(--green-glow)',
                              border: '1px solid var(--green-border)',
                              borderRadius: 'var(--radius-md)',
                              color: 'var(--green-400)',
                              fontSize: '12px',
                              fontWeight: 600,
                              cursor: actionLoading === rev.id ? 'not-allowed' : 'pointer',
                            }}
                          >
                            Approve Action
                          </button>
                          <button
                            onClick={() => handleReject(rev.id)}
                            disabled={actionLoading === rev.id}
                            style={{
                              padding: '6px 16px',
                              background: 'var(--red-glow)',
                              border: '1px solid var(--red-border)',
                              borderRadius: 'var(--radius-md)',
                              color: 'var(--red-400)',
                              fontSize: '12px',
                              fontWeight: 600,
                              cursor: actionLoading === rev.id ? 'not-allowed' : 'pointer',
                            }}
                          >
                            Reject Action
                          </button>
                        </>
                      )}
                      {rev.status !== 'Pending' && (
                        <span className={`badge ${rev.status === 'Approved' ? 'badge-resolved' : 'badge-critical'}`}>
                          {rev.status}
                        </span>
                      )}
                    </div>
                  </div>

                  <p style={{ fontSize: '14px', color: 'var(--text-primary)', marginBottom: '8px', fontWeight: 600 }}>
                    {rev.action}
                  </p>

                  <div
                    style={{
                      display: 'flex',
                      alignItems: 'center',
                      gap: '8px',
                      padding: '8px 12px',
                      background: rev.status === 'Pending' ? 'var(--amber-glow)' : 'var(--bg-hover)',
                      border: `1px solid ${rev.status === 'Pending' ? 'var(--amber-border)' : 'var(--border-dim)'}`,
                      borderRadius: 'var(--radius-sm)',
                      marginBottom: '10px',
                    }}
                  >
                    <span style={{ fontSize: '12px', color: rev.status === 'Pending' ? 'var(--amber-400)' : 'var(--text-secondary)' }}>
                      Policy Decision ({rev.decision}): {rev.reason}
                    </span>
                  </div>

                  <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: '11px', color: 'var(--text-muted)' }}>
                    <span>
                      Supporting Evidence IDs:{' '}
                      {rev.supporting_evidence_ids.length > 0 ? (
                        <span style={{ fontFamily: 'var(--font-mono)', color: 'var(--cyan-400)' }}>
                          {rev.supporting_evidence_ids.join(', ')}
                        </span>
                      ) : (
                        <span style={{ color: 'var(--red-400)' }}>None (Violation of PE-001)</span>
                      )}
                    </span>
                    <span>Created: {new Date(rev.created_at).toLocaleString()}</span>
                  </div>
                </div>
              ))}
            </div>
          )}
        </Panel>
      </main>
    </>
  );
};
