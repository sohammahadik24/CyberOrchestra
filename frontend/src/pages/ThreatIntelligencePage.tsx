import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { AlertCircle, ArrowUpRight, CheckCircle2, CircleHelp, LoaderCircle, Search, ShieldAlert } from 'lucide-react';
import { Header } from '../components/layout/Header';
import { api, ApiError } from '../services/api';
import type { ThreatSource } from '../types';
import './ThreatIntelligencePage.css';

type LookupType = 'IP' | 'URL' | 'CVE' | 'MITRE';
type LookupResult = Record<string, unknown>;
type ResultStatus = 'success' | 'no-results' | 'unavailable' | 'error';

const lookupOptions: { value: LookupType; label: string; source: string; example: string }[] = [
  { value: 'IP', label: 'IP address', source: 'AbuseIPDB', example: '198.51.100.25' },
  { value: 'URL', label: 'URL or domain', source: 'URLhaus', example: 'example.org/path or https://example.org/path' },
  { value: 'CVE', label: 'CVE ID', source: 'NVD', example: 'CVE-2024-12345' },
  { value: 'MITRE', label: 'MITRE ATT&CK technique', source: 'MITRE ATT&CK', example: 'T1059.001' },
];
const sourceNames: Record<LookupType, string> = {
  IP: 'AbuseIPDB', URL: 'URLhaus', CVE: 'NVD CVE API 2.0', MITRE: 'MITRE ATT&CK',
};
const asRecord = (value: unknown): LookupResult | null =>
  value !== null && typeof value === 'object' && !Array.isArray(value) ? value as LookupResult : null;
const asList = (value: unknown): unknown[] => Array.isArray(value) ? value : [];
const asText = (value: unknown): string | null => typeof value === 'string' && value.trim() ? value : null;
const display = (value: unknown): string => typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean' ? String(value) : '';

function validIp(value: string): boolean {
  if (value.includes(':')) {
    try { return new URL('http://[' + value + ']').hostname.length > 2; } catch { return false; }
  }
  const parts = value.split('.');
  return parts.length === 4 && parts.every((part) => /^\d{1,3}$/.test(part) && Number(part) >= 0 && Number(part) <= 255);
}
function normalizeUrl(value: string): string | null {
  const withScheme = /^https?:\/\//i.test(value) ? value : 'https://' + value;
  try {
    const parsed = new URL(withScheme);
    return ['http:', 'https:'].includes(parsed.protocol) && parsed.hostname && !/\s/.test(value) ? parsed.toString() : null;
  } catch { return null; }
}
function validValue(type: LookupType, value: string): boolean {
  if (type === 'IP') return validIp(value);
  if (type === 'URL') return normalizeUrl(value) !== null;
  if (type === 'CVE') return /^CVE-\d{4}-\d{4,}$/i.test(value);
  return /^T\d{4,5}(?:\.\d{3})?$/i.test(value);
}

function sourceStatus(type: LookupType, sources: ThreatSource[]): ThreatSource | undefined {
  return sources.find((source) => source.name.toLowerCase() === sourceNames[type].toLowerCase() ||
    (type === 'CVE' && source.name.toLowerCase().startsWith('nvd')));
}

function explainError(error: unknown, type: LookupType): { status: ResultStatus; message: string } {
  if (!(error instanceof ApiError)) return { status: 'error', message: error instanceof Error ? error.message : 'The lookup failed unexpectedly.' };
  if (error.status === 404 && (type === 'CVE' || type === 'MITRE')) return { status: 'no-results', message: error.message };
  if (error.status === 503) return { status: 'unavailable', message: error.message || 'This intelligence source is unavailable or not configured.' };
  return { status: 'error', message: error.message };
}

const Field: React.FC<{ label: string; value: unknown; help?: string }> = ({ label, value, help }) => {
  const rendered = display(value);
  if (!rendered) return null;
  return <div className="ti-field"><span>{label}</span><strong>{rendered}</strong>{help && <small>{help}</small>}</div>;
};

const ListField: React.FC<{ label: string; values: unknown; getText?: (item: unknown) => string }> = ({ label, values, getText }) => {
  const items = asList(values).map((item) => getText ? getText(item) : display(item)).filter(Boolean);
  if (!items.length) return null;
  return <div className="ti-field ti-field-list"><span>{label}</span><ul>{items.map((item, index) => <li key={index}>{item}</li>)}</ul></div>;
};

const ResultEvidence: React.FC<{ result: LookupResult }> = ({ result }) => {
  const indicator = asRecord(result.indicator);
  const evidence = asRecord(result.evidence);
  if (!indicator && !evidence) return null;
  const source = asText(evidence?.source) || asText(indicator?.source);
  const reference = asText(evidence?.raw_reference) || asText(evidence?.reference);
  return <section className="ti-result-section">
    <h3>Evidence and references</h3>
    <p className="ti-help">These details show what the source returned; they do not independently confirm activity on your network.</p>
    <div className="ti-evidence-grid">
      {Boolean(evidence?.evidence_id) && <Field label="Evidence ID" value={evidence?.evidence_id} />}
      {source && <Field label="Evidence source" value={source} />}
      {Boolean(evidence?.description) && <Field label="Source details" value={evidence?.description} />}
      {Boolean(evidence?.timestamp) && <Field label="Evidence timestamp" value={evidence?.timestamp} />}
      {Boolean(indicator?.indicator_type) && <Field label="Indicator type" value={indicator?.indicator_type} />}
      {indicator?.confidence !== null && indicator?.confidence !== undefined && <Field label="Indicator confidence" value={indicator.confidence} help="Displayed only when supplied by the integration." />}
      {reference && <div className="ti-field"><span>Reference</span><a href={reference} target="_blank" rel="noreferrer">{reference}<ArrowUpRight size={13} /></a></div>}
    </div>
  </section>;
};

const Assessment: React.FC<{ type: LookupType; data: LookupResult }> = ({ type, data }) => {
  const status = asText(data.query_status) || asText(asRecord(data.reputation)?.query_status);
  const noUrlMatch = type === 'URL' && status?.toLowerCase().includes('no_results');
  if (noUrlMatch) return <div className="ti-no-match"><CircleHelp size={18} /><div><strong>No matching URL record</strong><p>URLhaus returned a no-results status for this query.</p></div></div>;

  return <>
    <section className="ti-result-section">
      <h3>Assessment</h3>
      {type === 'IP' && (() => {
        const reputation = asRecord(data.reputation) || {};
        return <div className="ti-field-grid">
          <Field label="Abuse confidence score" value={reputation.abuse_confidence_score} help="The source's score based on abuse reports; it is not CyberOrchestra's verdict." />
          <Field label="Abuse reports" value={reputation.total_reports} />
          <Field label="Last reported" value={reputation.last_reported_at} />
          <Field label="Country" value={reputation.country_code} />
          <Field label="Network use" value={reputation.usage_type} />
          <Field label="Whitelisted by source" value={reputation.is_whitelisted} />
        </div>;
      })()}
      {type === 'URL' && (() => {
        const reputation = asRecord(data.reputation) || {};
        return <div className="ti-field-grid">
          <Field label="URL record status" value={reputation.query_status} />
          <Field label="Threat category" value={reputation.threat} />
          <Field label="URL status" value={reputation.url_status} />
          <Field label="Host" value={reputation.host} />
          <Field label="Reporter" value={reputation.reporter} />
          <Field label="Date added" value={reputation.date_added} />
          <ListField label="Tags" values={reputation.tags} />
          <ListField label="Payload references" values={reputation.payloads} getText={(item) => {
            const payload = asRecord(item);
            return [payload?.signature, payload?.file_type, payload?.response_sha256].filter(Boolean).join(' / ');
          }} />
          <Field label="URLhaus ID" value={reputation.urlhaus_id} />
          {asText(reputation.urlhaus_reference) && <div className="ti-field"><span>URLhaus record</span><a href={String(reputation.urlhaus_reference)} target="_blank" rel="noreferrer">{String(reputation.urlhaus_reference)}<ArrowUpRight size={13} /></a></div>}
        </div>;
      })()}
      {type === 'CVE' && (() => {
        const cve = asRecord(data.cve_data) || {};
        const metrics = [asRecord(cve.cvss_v4), asRecord(cve.cvss_v3), asRecord(cve.cvss_v2)].filter((item): item is LookupResult => item !== null);
        return <div className="ti-field-grid">
          <Field label="Vulnerability" value={cve.description} />
          <Field label="NVD status" value={cve.vuln_status} />
          <Field label="Published" value={cve.published} />
          <Field label="Last modified" value={cve.last_modified} />
          {metrics.map((value, index) => <React.Fragment key={index}>
            <Field label={'CVSS v' + value.cvss_version + ' score'} value={value.base_score} help="Severity score published by NVD." />
            <Field label="CVSS severity" value={value.base_severity} />
            <Field label="CVSS vector" value={value.vector_string} />
          </React.Fragment>)}
          <ListField label="Weaknesses (CWE)" values={cve.cwes} getText={(item) => {
            const cwe = asRecord(item); return [cwe?.cwe_id, cwe?.description].filter(Boolean).join(' / ');
          }} />
          <ListField label="Affected products" values={cve.affected_products} getText={(item) => {
            const product = asRecord(item); return [product?.vendor, product?.product, product?.version_start_including, product?.version_end_including].filter(Boolean).join(' / ');
          }} />
          <ListField label="References" values={cve.references} getText={(item) => {
            const ref = asRecord(item); return [ref?.source, ref?.url].filter(Boolean).join(' / ');
          }} />
        </div>;
      })()}
      {type === 'MITRE' && (() => {
        const technique = asRecord(data.technique) || {};
        return <div className="ti-field-grid">
          <Field label="Technique" value={technique.technique_id} />
          <Field label="Name" value={technique.name} />
          <Field label="Description" value={technique.description} />
          <ListField label="Tactics" values={technique.tactics} />
          <ListField label="Platforms" values={technique.platforms} />
          <Field label="Sub-technique" value={technique.is_subtechnique} />
          <Field label="Parent technique" value={technique.parent_technique_id} />
          <Field label="Knowledge base provenance" value={technique.provenance} />
          <ListField label="References" values={technique.references} getText={(item) => {
            const ref = asRecord(item); return [ref?.source_name, ref?.external_id, ref?.url].filter(Boolean).join(' / ');
          }} />
        </div>;
      })()}
      {type === 'URL' && <p className="ti-help">A URLhaus match is external intelligence, not proof the URL affected your environment.</p>}
      {type === 'MITRE' && <p className="ti-help">A technique description explains known behavior; it does not mean the behavior occurred in this incident.</p>}
    </section>
    <ResultEvidence result={data} />
    <details className="ti-raw"><summary>Show complete response data</summary><pre>{JSON.stringify(data, null, 2)}</pre></details>
  </>;
};

export const ThreatIntelligencePage: React.FC = () => {
  const [sources, setSources] = useState<ThreatSource[]>([]);
  const [sourcesLoading, setSourcesLoading] = useState(true);
  const [sourceError, setSourceError] = useState<string | null>(null);
  const [type, setType] = useState<LookupType>('CVE');
  const [value, setValue] = useState('');
  const [validation, setValidation] = useState<string | null>(null);
  const [lookupLoading, setLookupLoading] = useState(false);
  const [result, setResult] = useState<LookupResult | null>(null);
  const [resultStatus, setResultStatus] = useState<ResultStatus | null>(null);
  const [resultMessage, setResultMessage] = useState<string | null>(null);
  const [searchedValue, setSearchedValue] = useState('');

  const loadSources = useCallback(async () => {
    setSourcesLoading(true); setSourceError(null);
    try { setSources(await api.getThreatSources()); }
    catch (err) { setSourceError(err instanceof ApiError ? err.message : 'Integration configuration could not be loaded.'); }
    finally { setSourcesLoading(false); }
  }, []);
  useEffect(() => { void loadSources(); }, [loadSources]);

  const source = sourceStatus(type, sources);
  const sourceUnavailable = Boolean(source?.authRequired && !source.operational);
  const selectedOption = lookupOptions.find((option) => option.value === type)!;

  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    const cleaned = value.trim();
    if (!cleaned) { setValidation('Enter a value to search.'); return; }
    if (!validValue(type, cleaned)) {
      setValidation('Enter a valid ' + selectedOption.label.toLowerCase() + '. Example: ' + selectedOption.example);
      return;
    }
    setValidation(null); setResult(null); setResultMessage(null); setResultStatus(null);
    setSearchedValue(cleaned);
    if (sourceUnavailable) {
      setResultStatus('unavailable');
      setResultMessage(source?.status || selectedOption.source + ' is not configured on the backend.');
      return;
    }
    setLookupLoading(true);
    try {
      let response: unknown;
      if (type === 'IP') response = await api.queryIpReputation(cleaned);
      else if (type === 'URL') response = await api.queryUrlReputation(normalizeUrl(cleaned)!);
      else if (type === 'CVE') response = await api.queryCveIntelligence(cleaned.toUpperCase());
      else response = await api.queryMitreTechnique(cleaned.toUpperCase());
      const data = asRecord(response);
      if (!data) throw new Error('The source returned an unreadable response.');
      setResult(data);
      const reputation = asRecord(data.reputation);
      const queryStatus = asText(reputation?.query_status);
      if (type === 'URL' && queryStatus?.toLowerCase().includes('no_results')) {
        setResultStatus('no-results'); setResultMessage('URLhaus found no record for this URL.');
      } else {
        setResultStatus('success'); setResultMessage('The source returned a result.');
      }
    } catch (err) {
      const failure = explainError(err, type);
      setResultStatus(failure.status); setResultMessage(failure.message);
    } finally { setLookupLoading(false); }
  };

  const canSubmit = useMemo(() => !lookupLoading && !sourcesLoading, [lookupLoading, sourcesLoading]);

  return <>
    <Header pageTitle="Threat Intelligence" pageSubtitle="Look up external reputation, vulnerability, and ATT&CK reference information." />
    <main className="threat-intel-page page-enter">
      <section className="ti-intro">
        <span className="ti-live-label"><span /> LIVE EXTERNAL LOOKUPS</span>
        <h2>Check an indicator with its source</h2>
        <p>Search supported IP addresses, URLs or domains, CVEs, and MITRE ATT&CK techniques. Results come directly from the configured backend integrations.</p>
      </section>

      <section className="ti-lookup-panel">
        <div className="ti-panel-heading"><div><h3>Intelligence lookup</h3><p>Choose the kind of value you want to check, then enter it below.</p></div></div>
        {sourceError && <div className="ti-source-warning" role="status"><AlertCircle size={15} /><span>Integration availability could not be checked. The lookup will report its actual backend result.</span><button type="button" onClick={() => void loadSources()}>Retry</button></div>}
        <form onSubmit={(event) => void submit(event)} noValidate>
          <label className="ti-type-label" htmlFor="ti-type">Search type</label>
          <select id="ti-type" value={type} onChange={(event) => {
            setType(event.target.value as LookupType); setValidation(null); setResult(null); setResultStatus(null); setResultMessage(null);
          }}>
            {lookupOptions.map((option) => {
              const status = sourceStatus(option.value, sources);
              const disabled = Boolean(status?.authRequired && !status.operational);
              return <option value={option.value} key={option.value} disabled={disabled}>
                {option.label} - {option.source}{disabled ? ' (not configured)' : ''}
              </option>;
            })}
          </select>
          <p className="ti-source-state">{sourcesLoading ? 'Checking backend integration configuration...' :
            sourceUnavailable ? selectedOption.source + ' is not configured. Add its key to backend/.env and restart the API.' :
              source ? selectedOption.source + ': ' + source.status : 'Integration configuration is unknown; the backend will return an honest status.'}</p>
          <label className="ti-type-label" htmlFor="ti-value">Value to look up</label>
          <div className="ti-input-row">
            <input id="ti-value" value={value} onChange={(event) => { setValue(event.target.value); setValidation(null); }}
              placeholder={selectedOption.example} autoComplete="off" spellCheck={false} aria-invalid={Boolean(validation)} aria-describedby={validation ? 'ti-validation' : 'ti-input-help'} />
            <button type="submit" disabled={!canSubmit || sourceUnavailable}>
              {lookupLoading ? <><LoaderCircle size={16} className="ti-spin" /> Searching...</> : <><Search size={16} /> Search source</>}
            </button>
          </div>
          {validation ? <p id="ti-validation" className="ti-validation" role="alert">{validation}</p> :
            <p id="ti-input-help" className="ti-help">{type === 'URL' ? 'Enter a full HTTP(S) URL or a domain. A bare domain is queried as https://domain/.' :
              type === 'MITRE' ? 'Use a technique ID such as T1059 or a sub-technique such as T1059.001.' :
                type === 'CVE' ? 'Use the standard CVE-YYYY-NNNN identifier format.' : 'Enter a valid IPv4 or IPv6 address.'}</p>}
        </form>
      </section>

      <aside className="ti-simulation-note"><ShieldAlert size={16} /><p><strong>Live lookups are separate from simulations.</strong> Synthetic benchmark scenarios and incident indicators are not displayed as live threat-intelligence results.</p></aside>

      {lookupLoading && <div className="ti-state"><LoaderCircle size={19} className="ti-spin" /><div><strong>Contacting {selectedOption.source}</strong><span>Waiting for the backend integration response...</span></div></div>}

      {resultStatus && !lookupLoading && <section className={'ti-result ti-status-' + resultStatus}>
        <div className="ti-result-heading">
          <div><span className={'ti-status-badge ti-badge-' + resultStatus}>{resultStatus === 'success' ? <CheckCircle2 size={14} /> : resultStatus === 'no-results' ? <CircleHelp size={14} /> : <AlertCircle size={14} />}{resultStatus === 'success' ? 'Result returned' : resultStatus === 'no-results' ? 'No results' : resultStatus === 'unavailable' ? 'Unavailable / not configured' : 'Lookup error'}</span>
            <h3>Lookup result</h3><p>{resultMessage}</p></div>
        </div>
        <div className="ti-indicator"><span>Indicator</span><strong>{searchedValue}</strong><small>{selectedOption.label} / {sourceNames[type]}</small></div>
        {result && <Assessment key={type + searchedValue} type={type} data={result} />}
      </section>}

      {!resultStatus && !lookupLoading && <div className="ti-empty"><Search size={22} /><strong>Ready for a lookup</strong><p>Choose a supported type and enter a value. The result will include the source attribution and only fields returned by that source.</p></div>}

      <p className="ti-key-note">Provider credentials stay in the FastAPI backend. No API keys are sent to the browser.</p>
    </main>
  </>;
};
