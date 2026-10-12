import React, { useEffect, useState, useCallback } from 'react';
import { RefreshCw, AlertTriangle } from 'lucide-react';

import { Header } from '../components/layout/Header';
import { Panel } from '../components/ui/Panel';
import { AgentCard } from '../components/ui/AgentCard';
import { api, ApiError } from '../services/api';
import type { AgentStage } from '../types';

export const AgentMonitorPage: React.FC = () => {
  const [agents, setAgents] = useState<AgentStage[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  const fetchAgents = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const data = await api.getAgentsStatus();
      setAgents(data);
    } catch (err: any) {
      setError(err instanceof ApiError ? err.message : 'Failed to fetch agent status.');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchAgents();
  }, [fetchAgents]);

  const running = agents.filter((a) => a.status === 'running');
  const waiting = agents.filter((a) => a.status === 'waiting');
  const completed = agents.filter((a) => a.status === 'completed');
  const idle = agents.filter((a) => a.status === 'idle');

  return (
    <>
      <Header
        pageTitle="Agent Monitor"
        pageSubtitle="Real-time multi-agent pipeline status, assigned LLM profiles, and execution metrics"
        rightContent={
          <button
            onClick={() => fetchAgents()}
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
            <RefreshCw size={13} /> Refresh Agents
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
            <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
              <AlertTriangle size={16} />
              <span>{error}</span>
            </div>
            <button
              onClick={() => fetchAgents()}
              style={{ background: 'transparent', border: 'none', color: 'var(--red-400)', cursor: 'pointer', fontWeight: 600 }}
            >
              Retry
            </button>
          </div>
        )}

        {/* Status Count Summary */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: '16px' }}>
          {[
            { label: 'Completed', count: completed.length, color: 'var(--green-400)' },
            { label: 'Running', count: running.length, color: 'var(--cyan-400)' },
            { label: 'Waiting', count: waiting.length, color: 'var(--amber-400)' },
            { label: 'Idle / Ready', count: idle.length, color: 'var(--text-muted)' },
          ].map((s) => (
            <div key={s.label} className="card" style={{ padding: '20px', textAlign: 'center' }}>
              <div style={{ fontSize: '32px', fontWeight: 800, color: s.color, lineHeight: 1 }}>{s.count}</div>
              <div
                style={{
                  fontSize: '12px',
                  color: 'var(--text-secondary)',
                  marginTop: '6px',
                  textTransform: 'uppercase',
                  letterSpacing: '0.06em',
                  fontWeight: 600,
                }}
              >
                {s.label}
              </div>
            </div>
          ))}
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: '1.2fr 0.8fr', gap: '20px' }}>
          <Panel title="All Pipeline Agents" subtitle="CyberOrchestra 8-stage active agents and model assignments">
            {loading && agents.length === 0 ? (
              <div style={{ padding: '40px', textAlign: 'center', color: 'var(--text-muted)' }}>
                Loading agent telemetry...
              </div>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: '0' }}>
                {agents.map((agent) => (
                  <AgentCard key={agent.id} agent={agent} />
                ))}
              </div>
            )}
          </Panel>

          <Panel title="Locked Architecture" subtitle="CyberOrchestra multi-agent pipeline topology — v1.0">
            <div
              style={{
                background: 'var(--bg-elevated)',
                border: '1px solid var(--border-dim)',
                borderRadius: 'var(--radius-md)',
                padding: '20px',
                fontFamily: 'var(--font-mono)',
                fontSize: '11px',
                color: 'var(--text-secondary)',
                lineHeight: 1.8,
                whiteSpace: 'pre',
                overflowX: 'auto',
              }}
            >
{`Threat Intel / CVE / Incident Logs
           ↓
     Data Normalizer (Schema Standardizer)
           ↓
   Threat Detection Agent [Groq gpt-oss-120b]
           ↓
   ┌────────┼────────┐
   ↓        ↓        ↓
Malware   Log     Vuln.
Analysis Analysis Assess.
[120b]   [32b]    [32b]
   └────────┼────────┘
           ↓
   Shared Incident State (Validated Evidence)
           ↓
    Recovery Planning Agent [Groq qwen3-32b]
           ↓
 Deterministic Policy Engine (PE-001..PE-004)
           ↓
    Report Generation Agent [Groq qwen3-32b]
           ↓
       Final Report
           ↓
   Human SOC Analyst (Approval Queue)`}
            </div>

            <div style={{ marginTop: '16px', padding: '14px', background: 'var(--bg-elevated)', borderRadius: 'var(--radius-md)', border: '1px solid var(--border-subtle)' }}>
              <h5 style={{ fontSize: '12px', fontWeight: 600, color: 'var(--cyan-400)', marginBottom: '6px' }}>
                Model Assignment Integrity
              </h5>
              <ul style={{ margin: 0, paddingLeft: '16px', fontSize: '11px', color: 'var(--text-secondary)', lineHeight: 1.6 }}>
                <li><strong>Threat Detection:</strong> Groq <code>openai/gpt-oss-120b</code></li>
                <li><strong>Malware Analysis:</strong> Groq <code>openai/gpt-oss-120b</code></li>
                <li><strong>Log Analysis:</strong> Groq <code>qwen/qwen3-32b</code></li>
                <li><strong>Vulnerability Assessment:</strong> Groq <code>qwen/qwen3-32b</code></li>
                <li><strong>Recovery Planning:</strong> Groq <code>qwen/qwen3-32b</code></li>
                <li><strong>Report Generation:</strong> Groq <code>qwen/qwen3-32b</code></li>
                <li><strong>Policy Engine:</strong> Pure Deterministic Code (Zero LLM drift)</li>
              </ul>
            </div>
          </Panel>
        </div>
      </main>
    </>
  );
};
