import React from 'react';
import { NavLink, useLocation } from 'react-router-dom';
import {
  LayoutDashboard,
  ShieldAlert,
  PlusCircle,
  Activity,
  Globe,
  RefreshCw,
  FileText,
  BarChart2,
} from 'lucide-react';

interface NavItem {
  path: string;
  label: string;
  icon: React.ReactNode;
  badge?: string;
  badgeColor?: string;
}

const navItems: NavItem[] = [
  { path: '/',                    label: 'Overview',              icon: <LayoutDashboard size={17} /> },
  { path: '/incidents',           label: 'Investigations',        icon: <ShieldAlert size={17} /> },
  { path: '/incidents/new',       label: 'New Investigation',     icon: <PlusCircle size={17} /> },
  { path: '/agent-monitor',       label: 'Agent Monitor',         icon: <Activity size={17} /> },
  { path: '/threat-intelligence', label: 'Threat Intelligence',   icon: <Globe size={17} /> },
  { path: '/recovery-policy',     label: 'Recovery & Policy',     icon: <RefreshCw size={17} /> },
  { path: '/reports',             label: 'Reports',               icon: <FileText size={17} /> },
  { path: '/evaluation',          label: 'Evaluation',            icon: <BarChart2 size={17} /> },
];

export const Sidebar: React.FC = () => {
  const location = useLocation();

  return (
    <aside
      style={{
        width: 'var(--sidebar-width)',
        height: '100vh',
        background: 'var(--sidebar-bg)',
        borderRight: '1px solid var(--sidebar-border)',
        display: 'flex',
        flexDirection: 'column',
        flexShrink: 0,
        position: 'fixed',
        left: 0,
        top: 0,
        zIndex: 100,
        overflowY: 'auto',
      }}
    >
      {/* ── Logo / Brand ─────────────────────────── */}
      <div
        style={{
          padding: '0 18px',
          height: 'var(--header-height)',
          display: 'flex',
          alignItems: 'center',
          gap: '12px',
          borderBottom: '1px solid var(--sidebar-border)',
          flexShrink: 0,
        }}
      >
        {/* Brand Icon */}
        <div
          style={{
            width: 34,
            height: 34,
            background: 'var(--blue-glow)',
            border: '1px solid var(--blue-border)',
            borderRadius: '9px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            flexShrink: 0,
          }}
        >
          <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="var(--blue-600)" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
            <rect x="9" y="3" width="6" height="6" rx="1.5" />
            <rect x="3" y="15" width="6" height="6" rx="1.5" />
            <rect x="15" y="15" width="6" height="6" rx="1.5" />
            <path d="M12 9v3" />
            <path d="M6 15v-1a2 2 0 0 1 2-2h8a2 2 0 0 1 2 2v1" />
          </svg>
        </div>
        <div>
          <div style={{ fontSize: '14px', fontWeight: 700, color: 'var(--text-primary)', lineHeight: 1.2 }}>
            CyberOrchestra
          </div>
          <div style={{ fontSize: '9px', color: 'var(--text-muted)', letterSpacing: '0.08em', textTransform: 'uppercase', fontWeight: 600 }}>
            Security Operations
          </div>
        </div>
      </div>

      {/* ── Section Label ─────────────────────────── */}
      <div
        style={{
          padding: '20px 20px 8px',
          fontSize: '10px',
          fontWeight: 700,
          color: 'var(--text-muted)',
          letterSpacing: '0.12em',
          textTransform: 'uppercase',
        }}
      >
        Workspace
      </div>

      {/* ── Nav Items ─────────────────────────────── */}
      <nav style={{ flex: 1, padding: '0 12px' }}>
        {navItems.map(item => {
          const isActive =
            item.path === '/'
              ? location.pathname === '/'
              : item.path === '/incidents'
                ? location.pathname === '/incidents'
                : location.pathname.startsWith(item.path);

          return (
            <NavLink
              key={item.path}
              to={item.path}
              style={{ textDecoration: 'none', display: 'block', marginBottom: '4px' }}
            >
              <div
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  padding: '9px 12px',
                  borderRadius: '8px',
                  background: isActive ? '#dbeafe' : 'transparent',
                  border: isActive ? '1px solid rgba(59, 130, 246, 0.22)' : '1px solid transparent',
                  transition: 'all var(--transition-fast)',
                  cursor: 'pointer',
                }}
                onMouseEnter={e => {
                  if (!isActive) {
                    (e.currentTarget as HTMLElement).style.background = 'rgba(219, 234, 254, 0.45)';
                  }
                }}
                onMouseLeave={e => {
                  if (!isActive) {
                    (e.currentTarget as HTMLElement).style.background = 'transparent';
                  }
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: '11px' }}>
                  <span
                    style={{
                      color: isActive ? 'var(--blue-600)' : 'var(--text-muted)',
                      display: 'flex',
                      alignItems: 'center',
                      flexShrink: 0,
                    }}
                  >
                    {item.icon}
                  </span>
                  <span
                    style={{
                      fontSize: '13px',
                      fontWeight: isActive ? 600 : 500,
                      color: isActive ? 'var(--blue-700)' : 'var(--text-secondary)',
                    }}
                  >
                    {item.label}
                  </span>
                </div>

                <div style={{ display: 'flex', alignItems: 'center', gap: '6px' }}>
                  {item.badge && (
                    <span
                      style={{
                        fontSize: '10px',
                        fontWeight: 700,
                        color: item.badgeColor,
                        background: `${item.badgeColor}18`,
                        border: `1px solid ${item.badgeColor}40`,
                        borderRadius: '10px',
                        padding: '1px 6px',
                        minWidth: '18px',
                        textAlign: 'center',
                      }}
                    >
                      {item.badge}
                    </span>
                  )}
                  {isActive && (
                    <div
                      style={{
                        width: 6,
                        height: 6,
                        borderRadius: '50%',
                        background: 'var(--blue-600)',
                        flexShrink: 0,
                      }}
                    />
                  )}
                </div>
              </div>
            </NavLink>
          );
        })}
      </nav>

      {/* ── Footer ─────────────────── */}
      <div
        style={{
          padding: '14px 20px',
          borderTop: '1px solid var(--sidebar-border)',
          color: 'var(--text-muted)',
          fontSize: '11px',
        }}
      >
        Security Operations Center
      </div>
    </aside>
  );
};
