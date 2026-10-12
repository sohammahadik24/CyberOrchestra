import React from 'react';

interface StatCardProps {
  label: string;
  value: string | number;
  subtitle?: string;
  icon: React.ReactNode;
  trend?: { value: string; up: boolean } | null;
  accentColor?: 'red' | 'amber' | 'green' | 'cyan' | 'blue' | 'purple';
  className?: string;
}

const accentStyles: Record<string, { border: string; glow: string; iconBg: string; iconColor: string }> = {
  red:    { border: 'var(--red-border)',    glow: 'var(--red-glow)',    iconBg: 'rgba(229,62,62,0.10)',    iconColor: 'var(--red-400)'   },
  amber:  { border: 'var(--amber-border)',  glow: 'var(--amber-glow)',  iconBg: 'rgba(245,158,11,0.10)',   iconColor: 'var(--amber-400)' },
  green:  { border: 'var(--green-border)',  glow: 'var(--green-glow)',  iconBg: 'rgba(56,161,105,0.10)',   iconColor: 'var(--green-400)' },
  cyan:   { border: 'var(--cyan-border)',   glow: 'var(--cyan-glow)',   iconBg: 'rgba(6,182,212,0.10)',    iconColor: 'var(--cyan-400)'  },
  blue:   { border: 'var(--blue-border)',   glow: 'var(--blue-glow)',   iconBg: 'rgba(59,130,246,0.10)',   iconColor: 'var(--blue-500)'  },
  purple: { border: 'rgba(139,92,246,0.30)',glow: 'var(--purple-glow)', iconBg: 'rgba(139,92,246,0.10)',   iconColor: 'var(--purple-400)'},
};

export const StatCard: React.FC<StatCardProps> = ({
  label, value, subtitle, icon, trend, accentColor = 'cyan', className = ''
}) => {
  const a = accentStyles[accentColor];

  return (
    <div
      className={`card ${className}`}
      style={{
        padding: '20px',
        borderColor: a.border,
        boxShadow: `var(--shadow-card), 0 0 18px ${a.glow}`,
        transition: 'border-color 200ms ease, transform 200ms ease',
        cursor: 'default',
      }}
      onMouseEnter={e => (e.currentTarget.style.transform = 'translateY(-2px)')}
      onMouseLeave={e => (e.currentTarget.style.transform = 'translateY(0)')}
    >
      <div className="flex items-center justify-between" style={{ marginBottom: '14px' }}>
        <span
          style={{
            fontSize: '11px',
            fontWeight: 600,
            letterSpacing: '0.08em',
            textTransform: 'uppercase',
            color: 'var(--text-secondary)',
          }}
        >
          {label}
        </span>
        <div
          style={{
            width: 36,
            height: 36,
            borderRadius: 'var(--radius-md)',
            background: a.iconBg,
            border: `1px solid ${a.border}`,
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            color: a.iconColor,
            flexShrink: 0,
          }}
        >
          {icon}
        </div>
      </div>

      <div
        style={{
          fontSize: '32px',
          fontWeight: 800,
          lineHeight: 1,
          color: 'var(--text-primary)',
          letterSpacing: '-0.02em',
          marginBottom: '6px',
        }}
      >
        {value}
      </div>

      {(subtitle || trend) && (
        <div className="flex items-center gap-2" style={{ marginTop: '6px' }}>
          {subtitle && (
            <span style={{ fontSize: '12px', color: 'var(--text-muted)' }}>{subtitle}</span>
          )}
          {trend && (
            <span
              style={{
                fontSize: '11px',
                fontWeight: 600,
                color: trend.up ? 'var(--red-400)' : 'var(--green-400)',
              }}
            >
              {trend.up ? '↑' : '↓'} {trend.value}
            </span>
          )}
        </div>
      )}
    </div>
  );
};
