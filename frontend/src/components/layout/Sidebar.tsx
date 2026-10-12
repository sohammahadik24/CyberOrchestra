import React from 'react';
import { NavLink, useLocation } from 'react-router-dom';
import {
  LayoutDashboard,
  ShieldAlert,
  Activity,
  Globe,
  RefreshCw,
  FileText,
  BarChart2,
  ChevronRight,
} from 'lucide-react';

interface NavItem {
  path: string;
  label: string;
  icon: React.ReactNode;
  badge?: string;
  badgeColor?: string;
}

const navItems: NavItem[] = [
  { path: '/',                  label: 'Dashboard',             icon: <LayoutDashboard size={16} /> },
  { path: '/incidents',         label: 'Incidents',             icon: <ShieldAlert size={16} /> },
  { path: '/agent-monitor',     label: 'Agents',                icon: <Activity size={16} /> },
  { path: '/threat-intelligence', label: 'Threat Lookup',       icon: <Globe size={16} /> },
  { path: '/recovery-policy',   label: 'Recovery & Policy',     icon: <RefreshCw size={16} /> },
  { path: '/reports',           label: 'Reports',               icon: <FileText size={16} /> },
  { path: '/evaluation',        label: 'Evaluation',            icon: <BarChart2 size={16} /> },
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
          padding: '0 20px',
          height: 'var(--header-height)',
          display: 'flex',
          alignItems: 'center',
          gap: '10px',
          borderBottom: '1px solid var(--sidebar-border)',
          flexShrink: 0,
        }}
      >
        {/* Hex icon */}
        <div
          style={{
            width: 32,
            height: 32,
            background: 'linear-gradient(135deg, var(--cyan-700), var(--blue-700))',
            borderRadius: '8px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'center',
            flexShrink: 0,
            boxShadow: '0 0 12px rgba(6,182,212,0.3)',
          }}
        >
          <svg width="16" height="16" viewBox="0 0 16 16" fill="none">
            <path
              d="M8 1L14 4.5V11.5L8 15L2 11.5V4.5L8 1Z"
              stroke="white"
              strokeWidth="1.2"
              strokeLinejoin="round"
              fill="none"
            />
            <circle cx="8" cy="8" r="2" fill="white" />
          </svg>
        </div>
        <div>
          <div style={{ fontSize: '13px', fontWeight: 700, color: 'var(--text-primary)', lineHeight: 1.2 }}>
            CyberOrchestra
          </div>
          <div style={{ fontSize: '10px', color: 'var(--text-muted)', letterSpacing: '0.06em', textTransform: 'uppercase' }}>
            SOC Platform
          </div>
        </div>
      </div>

      {/* ── Section Label ─────────────────────────── */}
      <div
        style={{
          padding: '20px 20px 8px',
          fontSize: '10px',
          fontWeight: 600,
          color: 'var(--text-muted)',
          letterSpacing: '0.10em',
          textTransform: 'uppercase',
        }}
      >
        Navigation
      </div>

      {/* ── Nav Items ─────────────────────────────── */}
      <nav style={{ flex: 1, padding: '0 10px' }}>
        {navItems.map(item => {
          const isActive =
            item.path === '/'
              ? location.pathname === '/'
              : location.pathname.startsWith(item.path);

          return (
            <NavLink
              key={item.path}
              to={item.path}
              style={{ textDecoration: 'none', display: 'block', marginBottom: '2px' }}
            >
              <div
                style={{
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'space-between',
                  padding: '9px 10px',
                  borderRadius: 'var(--radius-md)',
                  background: isActive
                    ? 'linear-gradient(90deg, rgba(6,182,212,0.12), rgba(59,130,246,0.08))'
                    : 'transparent',
                  border: isActive ? '1px solid rgba(6,182,212,0.20)' : '1px solid transparent',
                  transition: 'all var(--transition-fast)',
                  cursor: 'pointer',
                }}
                onMouseEnter={e => {
                  if (!isActive) {
                    (e.currentTarget as HTMLElement).style.background = 'var(--bg-hover)';
                  }
                }}
                onMouseLeave={e => {
                  if (!isActive) {
                    (e.currentTarget as HTMLElement).style.background = 'transparent';
                  }
                }}
              >
                <div style={{ display: 'flex', alignItems: 'center', gap: '10px' }}>
                  <span style={{ color: isActive ? 'var(--cyan-400)' : 'var(--text-muted)', flexShrink: 0 }}>
                    {item.icon}
                  </span>
                  <span
                    style={{
                      fontSize: '13px',
                      fontWeight: isActive ? 600 : 400,
                      color: isActive ? 'var(--text-primary)' : 'var(--text-secondary)',
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
                    <ChevronRight size={12} style={{ color: 'var(--cyan-400)' }} />
                  )}
                </div>
              </div>
            </NavLink>
          );
        })}
      </nav>

      {/* ── Footer / Pipeline info ─────────────────── */}
      <div style={{ padding: '16px 20px', borderTop: '1px solid var(--sidebar-border)', color: 'var(--text-muted)', fontSize: '12px' }}>
        College project demonstration
      </div>
      {/*
        {[
          { label: 'Data Normalizer',     active: false },
          { label: 'Threat Detection',    active: true  },
          { label: 'Analysis Agents',     active: true  },
          { label: 'Shared State',        active: true  },
          { label: 'Recovery Planning',   active: true  },
          { label: 'Policy Engine',       active: false },
          { label: 'Report Generation',   active: true  },
        ].map((stage, idx) => (
          <div key={idx} style={{ display: 'flex', alignItems: 'center', gap: '8px', marginBottom: '6px' }}>
            <div
              style={{
                width: 5,
                height: 5,
                borderRadius: '50%',
                background: stage.active ? 'var(--cyan-400)' : 'var(--text-disabled)',
                flexShrink: 0,
                boxShadow: stage.active ? '0 0 4px var(--cyan-400)' : 'none',
              }}
            />
            <span style={{ fontSize: '11px', color: stage.active ? 'var(--text-secondary)' : 'var(--text-muted)' }}>
              {stage.label}
            </span>
          </div>
        ))}
      */}
    </aside>
  );
};
