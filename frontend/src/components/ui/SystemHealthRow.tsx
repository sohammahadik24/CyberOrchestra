import React from 'react';
import type { SystemHealth } from '../../services/mockData';

interface SystemHealthRowProps {
  item: SystemHealth;
}

const statusConfig = {
  operational: {
    dot: 'pulse-dot pulse-dot-green',
    label: 'Operational',
    color: 'var(--green-400)',
    bg: 'var(--green-glow)',
    border: 'var(--green-border)',
  },
  degraded: {
    dot: 'pulse-dot pulse-dot-amber',
    label: 'Degraded',
    color: 'var(--amber-400)',
    bg: 'var(--amber-glow)',
    border: 'var(--amber-border)',
  },
  down: {
    dot: 'pulse-dot pulse-dot-red',
    label: 'Down',
    color: 'var(--red-400)',
    bg: 'var(--red-glow)',
    border: 'var(--red-border)',
  },
};

export const SystemHealthRow: React.FC<SystemHealthRowProps> = ({ item }) => {
  const cfg = statusConfig[item.status];

  return (
    <div
      style={{
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
        padding: '9px 0',
        borderBottom: '1px solid var(--border-subtle)',
      }}
    >
      <div style={{ display: 'flex', alignItems: 'center', gap: '10px', minWidth: 0 }}>
        <div className={cfg.dot} />
        <span
          style={{
            fontSize: '12px',
            color: 'var(--text-primary)',
            overflow: 'hidden',
            textOverflow: 'ellipsis',
            whiteSpace: 'nowrap',
          }}
        >
          {item.component}
        </span>
      </div>

      <div style={{ display: 'flex', alignItems: 'center', gap: '16px', flexShrink: 0 }}>
        <span
          style={{
            fontSize: '11px',
            color: 'var(--text-muted)',
            fontFamily: 'var(--font-mono)',
          }}
        >
          {item.latency}
        </span>
        <span
          className="badge"
          style={{
            fontSize: '10px',
            padding: '2px 7px',
            background: cfg.bg,
            color: cfg.color,
            border: `1px solid ${cfg.border}`,
          }}
        >
          {cfg.label}
        </span>
      </div>
    </div>
  );
};
