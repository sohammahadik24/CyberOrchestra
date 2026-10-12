import React from 'react';

interface PanelProps {
  title: string;
  subtitle?: string;
  headerRight?: React.ReactNode;
  children: React.ReactNode;
  className?: string;
  style?: React.CSSProperties;
  noPadding?: boolean;
}

export const Panel: React.FC<PanelProps> = ({
  title, subtitle, headerRight, children, className = '', style, noPadding = false,
}) => {
  return (
    <div
      className={`card ${className}`}
      style={{ display: 'flex', flexDirection: 'column', ...style }}
    >
      {/* Header */}
      <div
        style={{
          padding: '16px 20px',
          borderBottom: '1px solid var(--border-subtle)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'space-between',
          flexShrink: 0,
        }}
      >
        <div>
          <h3
            style={{
              fontSize: '13px',
              fontWeight: 600,
              color: 'var(--text-primary)',
              letterSpacing: '0.01em',
            }}
          >
            {title}
          </h3>
          {subtitle && (
            <p style={{ fontSize: '11px', color: 'var(--text-muted)', marginTop: '2px' }}>
              {subtitle}
            </p>
          )}
        </div>
        {headerRight && (
          <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
            {headerRight}
          </div>
        )}
      </div>

      {/* Body */}
      <div style={{ padding: noPadding ? 0 : '16px 20px', flex: 1, overflow: 'hidden' }}>
        {children}
      </div>
    </div>
  );
};
