import React from 'react';
import type { Severity } from '../../types';

interface SeverityBadgeProps {
  severity: Severity | string;
  className?: string;
}

const classMap: Record<string, string> = {
  Critical: 'badge badge-critical',
  High:     'badge badge-high',
  Medium:   'badge badge-medium',
  Low:      'badge badge-low',
  Info:     'badge badge-info',
  System:   'badge badge-info',
};

export const SeverityBadge: React.FC<SeverityBadgeProps> = ({ severity, className }) => {
  const cls = classMap[severity] ?? 'badge badge-info';
  return <span className={`${cls} ${className ?? ''}`}>{severity}</span>;
};

// ── Status Badge ─────────────────────────────────────────
interface StatusBadgeProps {
  status: string;
  className?: string;
}

const statusMap: Record<string, string> = {
  New:            'badge badge-info',
  Investigating:  'badge badge-active',
  Containment:    'badge badge-high',
  Eradication:    'badge badge-high',
  Recovery:       'badge badge-review',
  'Policy Review':'badge badge-review',
  Reporting:      'badge badge-review',
  Resolved:       'badge badge-resolved',
  idle:           'badge badge-resolved',
  running:        'badge badge-active',
  completed:      'badge badge-resolved',
  error:          'badge badge-critical',
  waiting:        'badge badge-medium',
};

export const StatusBadge: React.FC<StatusBadgeProps> = ({ status, className }) => {
  const cls = statusMap[status] ?? 'badge badge-info';
  return <span className={`${cls} ${className ?? ''}`}>{status}</span>;
};
