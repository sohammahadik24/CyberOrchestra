import React, { useEffect, useState, useCallback } from 'react';
import {
  Search,
  RefreshCw,
  AlertTriangle,
  CheckCircle2,
} from 'lucide-react';

import { Header } from '../components/layout/Header';
import { Panel } from '../components/ui/Panel';
import { SeverityBadge } from '../components/ui/Badges';
import { api, ApiError } from '../services/api';
import type { ThreatFeedItem, ThreatSource } from '../types';

export const ThreatIntelligencePage: React.FC = () => {
  const [sources, setSources] = useState<ThreatSource[]>([]);
  const [feed, setFeed] = useState<ThreatFeedItem[]>([]);
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);

  // Interactive Live Query tool state
  const [queryType, setQueryType] = useState<'IP' | 'URL' | 'CVE' | 'MITRE'>('IP');
  const [queryValue, setQueryValue] = useState<string>('1.1.1.1');
  const [queryLoading, setQueryLoading] = useState<boolean>(false);
  const [queryResult, setQueryResult] = useState<any | null>(null);
  const [queryError, setQueryError] = useState<string | null>(null);

  const fetchThreatData = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [srcs, feedData] = await Promise.all([
        api.getThreatSources(),
        api.getThreatFeed(),
      ]);
      setSources(srcs);
      setFeed(feedData);
    } catch (err: any) {
      setError(err instanceof ApiError ? err.message : 'Failed to load threat intelligence.');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    fetchThreatData();
  }, [fetchThreatData]);

  const handleExecuteQuery = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!queryValue.trim()) return;

    setQueryLoading(true);
    setQueryError(null);
    setQueryResult(null);

    try {
      let res;
      if (queryType === 'IP') {
        res = await api.queryIpReputation(queryValue.trim());
      } else if (queryType === 'URL') {
        res = await api.queryUrlReputation(queryValue.trim());
      } else if (queryType === 'CVE') {
        res = await api.queryCveIntelligence(queryValue.trim());
      } else if (queryType === 'MITRE') {
        res = await api.queryMitreTechnique(queryValue.trim());
      }
      setQueryResult(res);
      // Refresh feed in case new indicator was logged
      const updatedFeed = await api.getThreatFeed();
      setFeed(updatedFeed);
    } catch (err: any) {
      setQueryError(err instanceof ApiError ? err.message : `Lookup failed for ${queryValue}`);
    } finally {
      setQueryLoading(false);
    }
  };

  return (
    <>
      <Header
        pageTitle="Threat Intelligence Feeds"
        pageSubtitle="Live queries and normalized evidence from AbuseIPDB · URLhaus · NVD CVE 2.0 · MITRE ATT&CK"
        rightContent={
          <button
            onClick={() => fetchThreatData()}
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
            <RefreshCw size={13} /> Refresh Feeds
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
          gap: '24px',
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
              onClick={() => fetchThreatData()}
              style={{ background: 'transparent', border: 'none', color: 'var(--red-400)', cursor: 'pointer', fontWeight: 600 }}
            >
              Retry
            </button>
          </div>
        )}

        {/* Live Feed Status Cards */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(220px, 1fr))', gap: '16px' }}>
          {sources.map((src) => (
            <div
              key={src.name}
              className="card"
              style={{
                padding: '20px',
                borderColor: src.operational ? 'var(--green-border)' : 'var(--amber-border)',
              }}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: '8px' }}>
                <div>
                  <div style={{ fontSize: '15px', fontWeight: 700, color: 'var(--text-primary)' }}>{src.name}</div>
                  <div style={{ fontSize: '11px', color: 'var(--text-muted)' }}>{src.type}</div>
                </div>
                {src.operational ? (
                  <CheckCircle2 size={16} style={{ color: 'var(--green-400)' }} />
                ) : (
                  <AlertTriangle size={16} style={{ color: 'var(--amber-400)' }} />
                )}
              </div>
              <div style={{ display: 'flex', alignItems: 'center', gap: '6px', marginTop: '10px' }}>
                <div
                  style={{
                    width: 7,
                    height: 7,
                    borderRadius: '50%',
                    background: src.operational ? 'var(--green-400)' : 'var(--amber-400)',
                    boxShadow: `0 0 6px ${src.operational ? 'var(--green-400)' : 'var(--amber-400)'}`,
                  }}
                />
                <span
                  style={{
                    fontSize: '11px',
                    fontWeight: 600,
                    color: src.operational ? 'var(--green-400)' : 'var(--amber-400)',
                  }}
                >
                  {src.status}
                </span>
              </div>
              <div style={{ fontSize: '10px', color: 'var(--text-muted)', marginTop: '8px' }}>
                Rate: {src.rateLimit}
              </div>
            </div>
          ))}
        </div>

        {/* Interactive Live Intelligence Query Console */}
        <Panel
          title="Live Threat Intelligence Lookup"
          subtitle="Query live upstream threat intelligence APIs directly from the backend"
        >
          <form onSubmit={handleExecuteQuery} style={{ display: 'flex', flexDirection: 'column', gap: '14px' }}>
            <div style={{ display: 'flex', gap: '12px', flexWrap: 'wrap' }}>
              <div style={{ display: 'flex', gap: '4px' }}>
                {(['IP', 'URL', 'CVE', 'MITRE'] as const).map((t) => (
                  <button
                    key={t}
                    type="button"
                    onClick={() => {
                      setQueryType(t);
                      if (t === 'IP') setQueryValue('1.1.1.1');
                      if (t === 'URL') setQueryValue('https://example.com/test_resource');
                      if (t === 'CVE') setQueryValue('CVE-2021-44228');
                      if (t === 'MITRE') setQueryValue('T1059.001');
                      setQueryResult(null);
                      setQueryError(null);
                    }}
                    style={{
                      padding: '6px 14px',
                      background: queryType === t ? 'var(--cyan-glow)' : 'var(--bg-elevated)',
                      border: `1px solid ${queryType === t ? 'var(--cyan-border)' : 'var(--border-dim)'}`,
                      borderRadius: 'var(--radius-md)',
                      color: queryType === t ? 'var(--cyan-400)' : 'var(--text-secondary)',
                      fontSize: '12px',
                      fontWeight: 600,
                      cursor: 'pointer',
                    }}
                  >
                    {t === 'IP' ? 'AbuseIPDB (IP)' : t === 'URL' ? 'URLhaus (URL)' : t === 'CVE' ? 'NVD (CVE)' : 'MITRE (Technique)'}
                  </button>
                ))}
              </div>

              <div style={{ display: 'flex', flex: 1, gap: '8px' }}>
                <input
                  type="text"
                  value={queryValue}
                  onChange={(e) => setQueryValue(e.target.value)}
                  placeholder={
                    queryType === 'IP'
                      ? 'e.g. 1.1.1.1'
                      : queryType === 'URL'
                      ? 'e.g. https://domain.test/path'
                      : queryType === 'CVE'
                      ? 'e.g. CVE-2021-44228'
                      : 'e.g. T1059.001'
                  }
                  style={{
                    flex: 1,
                    padding: '8px 12px',
                    background: 'var(--bg-elevated)',
                    border: '1px solid var(--border-dim)',
                    borderRadius: 'var(--radius-md)',
                    color: 'var(--text-primary)',
                    fontFamily: 'var(--font-mono)',
                    fontSize: '12px',
                    outline: 'none',
                  }}
                />
                <button
                  type="submit"
                  disabled={queryLoading}
                  style={{
                    display: 'flex',
                    alignItems: 'center',
                    gap: '6px',
                    padding: '8px 18px',
                    background: 'var(--cyan-glow)',
                    border: '1px solid var(--cyan-border)',
                    borderRadius: 'var(--radius-md)',
                    color: 'var(--cyan-400)',
                    fontSize: '12px',
                    fontWeight: 600,
                    cursor: queryLoading ? 'not-allowed' : 'pointer',
                  }}
                >
                  <Search size={13} className={queryLoading ? 'spin-icon' : ''} />
                  {queryLoading ? 'Querying Upstream...' : 'Query Threat Feed'}
                </button>
              </div>
            </div>

            {queryError && (
              <div
                style={{
                  padding: '10px 14px',
                  background: 'var(--red-glow)',
                  border: '1px solid var(--red-border)',
                  borderRadius: 'var(--radius-md)',
                  color: 'var(--red-400)',
                  fontSize: '12px',
                }}
              >
                {queryError}
              </div>
            )}

            {queryResult && (
              <div
                style={{
                  padding: '16px',
                  background: 'var(--bg-elevated)',
                  border: '1px solid var(--cyan-border)',
                  borderRadius: 'var(--radius-md)',
                }}
              >
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: '8px' }}>
                  <span style={{ fontSize: '13px', fontWeight: 600, color: 'var(--cyan-400)' }}>
                    Live Lookup Result: {queryValue}
                  </span>
                  <span style={{ fontSize: '11px', color: 'var(--text-muted)' }}>
                    Standardized CyberOrchestra Evidence Format
                  </span>
                </div>
                <pre
                  style={{
                    margin: 0,
                    padding: '12px',
                    background: 'var(--bg-surface)',
                    borderRadius: 'var(--radius-sm)',
                    fontFamily: 'var(--font-mono)',
                    fontSize: '11px',
                    color: 'var(--text-secondary)',
                    overflowX: 'auto',
                    maxHeight: '260px',
                  }}
                >
                  {JSON.stringify(queryResult, null, 2)}
                </pre>
              </div>
            )}
          </form>
        </Panel>

        {/* Real Collected Indicators Feed */}
        <Panel
          title="Collected Threat Indicators"
          subtitle={`${feed.length} indicators extracted across ingested incidents and live queries`}
          noPadding
        >
          {loading && feed.length === 0 ? (
            <div style={{ padding: '40px', textAlign: 'center', color: 'var(--text-muted)' }}>
              Loading indicator telemetry...
            </div>
          ) : feed.length === 0 ? (
            <div style={{ padding: '40px', textAlign: 'center', color: 'var(--text-muted)' }}>
              No threat indicators recorded yet. Ingest an incident to see live indicators.
            </div>
          ) : (
            <div style={{ overflowX: 'auto' }}>
              <table style={{ width: '100%', borderCollapse: 'collapse' }}>
                <thead>
                  <tr>
                    {['Indicator', 'Type', 'Source', 'Severity', 'Confidence', 'First Seen', 'Tags'].map((h) => (
                      <th
                        key={h}
                        style={{
                          padding: '10px 14px',
                          textAlign: 'left',
                          fontSize: '10px',
                          fontWeight: 600,
                          color: 'var(--text-muted)',
                          textTransform: 'uppercase',
                          letterSpacing: '0.08em',
                          borderBottom: '1px solid var(--border-subtle)',
                          whiteSpace: 'nowrap',
                        }}
                      >
                        {h}
                      </th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {feed.map((item) => (
                    <tr
                      key={item.id}
                      style={{
                        borderBottom: '1px solid var(--border-subtle)',
                        transition: 'background var(--transition-fast)',
                      }}
                      onMouseEnter={(e) => ((e.currentTarget as HTMLElement).style.background = 'var(--bg-hover)')}
                      onMouseLeave={(e) => ((e.currentTarget as HTMLElement).style.background = 'transparent')}
                    >
                      <td style={{ padding: '12px 14px', fontFamily: 'var(--font-mono)', fontSize: '12px', color: 'var(--cyan-300)' }}>
                        {item.indicator}
                      </td>
                      <td style={{ padding: '12px 14px' }}>
                        <span
                          style={{
                            fontSize: '11px',
                            padding: '2px 8px',
                            background: 'var(--bg-elevated)',
                            border: '1px solid var(--border-dim)',
                            borderRadius: '4px',
                            color: 'var(--text-secondary)',
                            fontWeight: 600,
                          }}
                        >
                          {item.type}
                        </span>
                      </td>
                      <td style={{ padding: '12px 14px', fontSize: '12px', color: 'var(--text-secondary)' }}>
                        {item.source}
                      </td>
                      <td style={{ padding: '12px 14px' }}>
                        <SeverityBadge severity={item.severity} />
                      </td>
                      <td style={{ padding: '12px 14px' }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: '8px' }}>
                          <div style={{ height: '4px', width: '60px', background: 'var(--bg-elevated)', borderRadius: '2px', overflow: 'hidden' }}>
                            <div
                              style={{
                                height: '100%',
                                width: `${item.confidence}%`,
                                background:
                                  item.confidence > 90
                                    ? 'var(--red-500)'
                                    : item.confidence > 75
                                    ? 'var(--amber-400)'
                                    : 'var(--cyan-400)',
                                borderRadius: '2px',
                              }}
                            />
                          </div>
                          <span style={{ fontSize: '11px', fontWeight: 600, color: 'var(--text-primary)' }}>
                            {item.confidence}%
                          </span>
                        </div>
                      </td>
                      <td
                        style={{
                          padding: '12px 14px',
                          fontSize: '11px',
                          color: 'var(--text-muted)',
                          fontFamily: 'var(--font-mono)',
                          whiteSpace: 'nowrap',
                        }}
                      >
                        {new Date(item.firstSeen).toLocaleDateString()}
                      </td>
                      <td style={{ padding: '12px 14px' }}>
                        <div style={{ display: 'flex', gap: '4px', flexWrap: 'wrap' }}>
                          {item.tags.map((tag) => (
                            <span
                              key={tag}
                              style={{
                                fontSize: '10px',
                                padding: '2px 6px',
                                background: 'var(--bg-elevated)',
                                border: '1px solid var(--border-dim)',
                                borderRadius: '4px',
                                color: 'var(--text-muted)',
                                whiteSpace: 'nowrap',
                              }}
                            >
                              {tag}
                            </span>
                          ))}
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </Panel>
      </main>
    </>
  );
};
