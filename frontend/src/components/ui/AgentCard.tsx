import React from 'react';
import type { AgentStage, AgentStatus } from '../../services/mockData';
import { StatusBadge } from './Badges';

interface AgentCardProps {
  agent: AgentStage;
}

const statusColors: Record<AgentStatus, string> = {
  idle:      'var(--text-muted)',
  running:   'var(--cyan-400)',
  completed: 'var(--green-400)',
  error:     'var(--red-400)',
  waiting:   'var(--amber-400)',
};

const progressBarColors: Record<AgentStatus, string> = {
  idle:      'var(--border-default)',
  running:   'var(--cyan-500)',
  completed: 'var(--green-500)',
  error:     'var(--red-500)',
  waiting:   'var(--amber-500)',
};

export const AgentCard: React.FC<AgentCardProps> = ({ agent }) => {
  const color = statusColors[agent.status];
  const barColor = progressBarColors[agent.status];

  return (
    <div
      style={{
        padding: '14px 16px',
        background: 'var(--bg-elevated)',
        border: '1px solid var(--border-dim)',
        borderRadius: 'var(--radius-md)',
        marginBottom: '8px',
        transition: 'border-color var(--transition-base)',
      }}
      onMouseEnter={e => ((e.currentTarget as HTMLElement).style.borderColor = 'var(--border-default)')}
      onMouseLeave={e => ((e.currentTarget as HTMLElement).style.borderColor = 'var(--border-dim)')}
    >
      {/* Header row */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: '8px' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: '8px', minWidth: 0 }}>
          {/* Status indicator */}
          <div
            style={{
              width: 7,
              height: 7,
              borderRadius: '50%',
              background: color,
              boxShadow: agent.status === 'running' ? `0 0 6px ${color}` : 'none',
              flexShrink: 0,
              animation: agent.status === 'running' ? 'pulse-dot 2s ease-in-out infinite' : 'none',
            }}
          />
          <span
            style={{
              fontSize: '12px',
              fontWeight: 600,
              color: 'var(--text-primary)',
              overflow: 'hidden',
              textOverflow: 'ellipsis',
              whiteSpace: 'nowrap',
            }}
          >
            {agent.name}
          </span>
        </div>
        <StatusBadge status={agent.status} />
      </div>

      {/* Role */}
      <div style={{ fontSize: '11px', color: 'var(--text-muted)', marginBottom: '10px' }}>
        {agent.role}
      </div>

      {/* Progress bar */}
      <div
        style={{
          height: '3px',
          background: 'var(--bg-hover)',
          borderRadius: '2px',
          overflow: 'hidden',
          marginBottom: '10px',
        }}
      >
        <div
          style={{
            height: '100%',
            width: `${agent.progress}%`,
            background: barColor,
            borderRadius: '2px',
            transition: 'width 600ms ease',
          }}
        />
      </div>

      {/* Footer row */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <span
          style={{
            fontSize: '11px',
            color: 'var(--text-muted)',
            overflow: 'hidden',
            textOverflow: 'ellipsis',
            whiteSpace: 'nowrap',
            maxWidth: '220px',
          }}
          title={agent.lastAction}
        >
          {agent.lastAction}
        </span>
        <div style={{ display: 'flex', alignItems: 'center', gap: '10px', flexShrink: 0 }}>
          {agent.confidence !== null && (
            <span style={{ fontSize: '11px', color: color, fontWeight: 600 }}>
              {agent.confidence}%
            </span>
          )}
          <span
            style={{
              fontSize: '11px',
              color: 'var(--text-muted)',
              fontFamily: 'var(--font-mono)',
            }}
          >
            {agent.processingTime}
          </span>
        </div>
      </div>
    </div>
  );
};
