import React from 'react';

interface HeaderProps {
  pageTitle: string;
  pageSubtitle?: string;
  rightContent?: React.ReactNode;
}

export const Header: React.FC<HeaderProps> = ({ pageTitle, pageSubtitle, rightContent }) => {
  return (
    <header className="app-page-header">
      <div className="app-page-heading">
        <div style={{ display: 'flex', flexDirection: 'column', gap: '2px' }}>
          <div style={{ fontSize: '13px', fontWeight: 600, color: 'var(--text-primary)' }}>
            {pageTitle}
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: '6px', fontSize: '11px', color: 'var(--text-muted)' }}>
            <span>CyberOrchestra</span>
            <span>/</span>
            <span>{pageSubtitle || pageTitle}</span>
          </div>
        </div>
      </div>
      <div className="app-page-actions">
        {rightContent ? (
          rightContent
        ) : (
          <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
            <div
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: '6px',
                padding: '4px 10px',
                borderRadius: '999px',
                border: '1px solid var(--border-default)',
                background: '#ffffff',
                fontSize: '11px',
                color: 'var(--text-secondary)',
              }}
            >
              <span
                style={{
                  width: '6px',
                  height: '6px',
                  borderRadius: '50%',
                  background: '#10b981',
                }}
              />
              System Connected
            </div>
            <div
              style={{
                display: 'inline-flex',
                alignItems: 'center',
                gap: '6px',
                padding: '4px 10px',
                borderRadius: '999px',
                border: '1px solid var(--border-default)',
                background: '#ffffff',
                fontSize: '11px',
                color: 'var(--text-secondary)',
              }}
            >
              <span
                style={{
                  display: 'grid',
                  placeItems: 'center',
                  width: '18px',
                  height: '18px',
                  borderRadius: '50%',
                  background: 'var(--blue-glow)',
                  color: 'var(--blue-600)',
                  fontSize: '9px',
                  fontWeight: 700,
                }}
              >
                CO
              </span>
              Analyst workspace
            </div>
          </div>
        )}
      </div>
    </header>
  );
};

