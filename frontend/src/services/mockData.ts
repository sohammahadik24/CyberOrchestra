// ============================================================
// CyberOrchestra — Mock Data Service Layer
// Replace these with real API calls in future phases
// ============================================================

export type Severity = 'Critical' | 'High' | 'Medium' | 'Low' | 'Info';
export type IncidentStatus =
  | 'New'
  | 'Investigating'
  | 'Containment'
  | 'Eradication'
  | 'Recovery'
  | 'Policy Review'
  | 'Reporting'
  | 'Resolved';

export type AgentStatus = 'idle' | 'running' | 'completed' | 'error' | 'waiting';

// ── Incident ────────────────────────────────────────────────
export interface Incident {
  id: string;
  title: string;
  severity: Severity;
  status: IncidentStatus;
  assignee: string;
  source: string;
  affectedAssets: number;
  createdAt: string;
  updatedAt: string;
  pipelineStage: string;
  iocs: string[];
  tags: string[];
}

// ── Agent Pipeline Stage ────────────────────────────────────
export interface AgentStage {
  id: string;
  name: string;
  role: string;
  status: AgentStatus;
  progress: number;          // 0-100
  incidentId: string | null;
  lastAction: string;
  processingTime: string;
  confidence: number | null; // 0-100 or null if not applicable
  tokensUsed: number | null;
}

// ── Threat Intelligence Feed Item ──────────────────────────
export interface ThreatFeedItem {
  id: string;
  indicator: string;
  type: 'IP' | 'URL' | 'Hash' | 'CVE' | 'MITRE';
  source: string;
  severity: Severity;
  confidence: number;
  firstSeen: string;
  tags: string[];
}

// ── System Health ───────────────────────────────────────────
export interface SystemHealth {
  component: string;
  status: 'operational' | 'degraded' | 'down';
  latency: string;
  uptime: string;
}

// ══════════════════════════════════════════════════════════════
// MOCK DATA
// ══════════════════════════════════════════════════════════════

export const mockIncidents: Incident[] = [
  {
    id: 'INC-2026-0047',
    title: 'APT-29 Lateral Movement — Domain Controller Compromise',
    severity: 'Critical',
    status: 'Investigating',
    assignee: 'A. Sharma',
    source: 'SIEM / EDR',
    affectedAssets: 14,
    createdAt: '2026-10-08T21:14:00Z',
    updatedAt: '2026-10-08T23:58:00Z',
    pipelineStage: 'Malware Analysis',
    iocs: ['192.168.4.22', 'a3f9c1d2e5b84...', 'CVE-2024-21410'],
    tags: ['APT', 'Lateral Movement', 'Kerberos', 'Pass-the-Hash'],
  },
  {
    id: 'INC-2026-0046',
    title: 'Ransomware Deployment — Finance VLAN Encryption Event',
    severity: 'Critical',
    status: 'Containment',
    assignee: 'M. Chen',
    source: 'EDR Alert',
    affectedAssets: 8,
    createdAt: '2026-10-08T18:02:00Z',
    updatedAt: '2026-10-08T22:15:00Z',
    pipelineStage: 'Recovery Planning',
    iocs: ['ransom.exe', 'fe4a9c8b...', '10.20.4.101'],
    tags: ['Ransomware', 'Encryption', 'LockBit', 'Finance'],
  },
  {
    id: 'INC-2026-0045',
    title: 'SQL Injection — Customer-Facing Web API',
    severity: 'High',
    status: 'Policy Review',
    assignee: 'J. Okafor',
    source: 'WAF / DAST',
    affectedAssets: 2,
    createdAt: '2026-10-08T14:30:00Z',
    updatedAt: '2026-10-08T21:45:00Z',
    pipelineStage: 'Policy Engine',
    iocs: ["'; DROP TABLE users;--", 'CVE-2024-28752'],
    tags: ['SQLi', 'Web', 'Data Breach Risk'],
  },
  {
    id: 'INC-2026-0044',
    title: 'Credential Stuffing Attack — Auth Service',
    severity: 'High',
    status: 'Eradication',
    assignee: 'A. Sharma',
    source: 'Auth Logs',
    affectedAssets: 1,
    createdAt: '2026-10-08T09:10:00Z',
    updatedAt: '2026-10-08T20:30:00Z',
    pipelineStage: 'Recovery Planning',
    iocs: ['45.32.187.12', '185.220.101.9'],
    tags: ['Credential Stuffing', 'Brute Force', 'IAM'],
  },
  {
    id: 'INC-2026-0043',
    title: 'Malicious PowerShell — Fileless Execution via WMI',
    severity: 'High',
    status: 'Reporting',
    assignee: 'R. Patel',
    source: 'EDR / Sysmon',
    affectedAssets: 3,
    createdAt: '2026-10-07T22:00:00Z',
    updatedAt: '2026-10-08T16:20:00Z',
    pipelineStage: 'Report Generation',
    iocs: ['powershell.exe -enc ...', 'T1059.001', 'T1047'],
    tags: ['Fileless', 'PowerShell', 'WMI', 'Living-off-the-Land'],
  },
  {
    id: 'INC-2026-0042',
    title: 'Phishing Campaign — Executive Impersonation',
    severity: 'Medium',
    status: 'Resolved',
    assignee: 'M. Chen',
    source: 'Email Gateway',
    affectedAssets: 0,
    createdAt: '2026-10-07T08:30:00Z',
    updatedAt: '2026-10-08T10:00:00Z',
    pipelineStage: 'Resolved',
    iocs: ['malicious-link.net/exec', 'spoofed@domain.com'],
    tags: ['Phishing', 'BEC', 'Social Engineering'],
  },
  {
    id: 'INC-2026-0041',
    title: 'Exposed S3 Bucket — Sensitive PII Data',
    severity: 'Medium',
    status: 'Resolved',
    assignee: 'J. Okafor',
    source: 'CSPM',
    affectedAssets: 1,
    createdAt: '2026-10-06T16:00:00Z',
    updatedAt: '2026-10-07T14:00:00Z',
    pipelineStage: 'Resolved',
    iocs: ['s3://company-backup-prod'],
    tags: ['Misconfiguration', 'Cloud', 'PII', 'S3'],
  },
  {
    id: 'INC-2026-0040',
    title: 'Log4Shell Exploitation Attempt — Prod Servers',
    severity: 'High',
    status: 'Resolved',
    assignee: 'R. Patel',
    source: 'IDS / SIEM',
    affectedAssets: 6,
    createdAt: '2026-10-05T12:00:00Z',
    updatedAt: '2026-10-06T18:00:00Z',
    pipelineStage: 'Resolved',
    iocs: ['CVE-2021-44228', '${jndi:ldap://...}'],
    tags: ['Log4Shell', 'RCE', 'Java', 'Critical Patch'],
  },
];

export const mockAgentStages: AgentStage[] = [
  {
    id: 'data-normalizer',
    name: 'Data Normalizer',
    role: 'Ingestion & Schema Validation',
    status: 'idle',
    progress: 100,
    incidentId: null,
    lastAction: 'Normalized 847 telemetry events, 3 CVEs, 12 IPs',
    processingTime: '1.2s',
    confidence: null,
    tokensUsed: null,
  },
  {
    id: 'threat-detection',
    name: 'Threat Detection Agent',
    role: 'IOC Classification & Triage',
    status: 'running',
    progress: 68,
    incidentId: 'INC-2026-0047',
    lastAction: 'Correlating Kerberoasting indicators with baseline',
    processingTime: '14.3s',
    confidence: 91,
    tokensUsed: 2840,
  },
  {
    id: 'malware-analysis',
    name: 'Malware Analysis Agent',
    role: 'Binary & Behavioral Analysis',
    status: 'running',
    progress: 42,
    incidentId: 'INC-2026-0047',
    lastAction: 'Disassembling PE section — suspicious entropy detected',
    processingTime: '38.7s',
    confidence: 78,
    tokensUsed: 5210,
  },
  {
    id: 'log-analysis',
    name: 'Log Analysis Agent',
    role: 'Auth / Network Log Forensics',
    status: 'waiting',
    progress: 0,
    incidentId: 'INC-2026-0047',
    lastAction: 'Awaiting Threat Detection output',
    processingTime: '--',
    confidence: null,
    tokensUsed: null,
  },
  {
    id: 'vuln-assessment',
    name: 'Vulnerability Assessment Agent',
    role: 'CVE Correlation & CVSS Scoring',
    status: 'completed',
    progress: 100,
    incidentId: 'INC-2026-0046',
    lastAction: 'Identified CVE-2024-21410 (CVSS 9.8) as exploit vector',
    processingTime: '8.1s',
    confidence: 96,
    tokensUsed: 3450,
  },
  {
    id: 'recovery-planning',
    name: 'Recovery Planning Agent',
    role: 'Containment & Remediation Strategy',
    status: 'running',
    progress: 85,
    incidentId: 'INC-2026-0046',
    lastAction: 'Generating step-by-step eradication playbook',
    processingTime: '22.4s',
    confidence: 87,
    tokensUsed: 6720,
  },
  {
    id: 'policy-engine',
    name: 'Deterministic Policy Engine',
    role: 'Compliance & Action Validation',
    status: 'completed',
    progress: 100,
    incidentId: 'INC-2026-0045',
    lastAction: 'WAF rule proposed — pending human approval (3 flags)',
    processingTime: '0.3s',
    confidence: null,
    tokensUsed: null,
  },
  {
    id: 'report-generation',
    name: 'Report Generation Agent',
    role: 'Executive & Technical Reporting',
    status: 'running',
    progress: 60,
    incidentId: 'INC-2026-0043',
    lastAction: 'Drafting technical timeline and MITRE ATT&CK mapping',
    processingTime: '11.6s',
    confidence: 94,
    tokensUsed: 4180,
  },
];

export const mockThreatFeed: ThreatFeedItem[] = [
  { id: 'tf-001', indicator: '192.168.4.22', type: 'IP', source: 'AbuseIPDB', severity: 'Critical', confidence: 97, firstSeen: '2026-10-08T21:10:00Z', tags: ['C2', 'APT-29'] },
  { id: 'tf-002', indicator: 'CVE-2024-21410', type: 'CVE', source: 'NVD', severity: 'Critical', confidence: 100, firstSeen: '2026-10-07T00:00:00Z', tags: ['Exchange', 'CVSS 9.8', 'RCE'] },
  { id: 'tf-003', indicator: 'malicious-link.net', type: 'URL', source: 'URLhaus', severity: 'High', confidence: 88, firstSeen: '2026-10-08T14:00:00Z', tags: ['Phishing', 'Malware Distribution'] },
  { id: 'tf-004', indicator: 'T1059.001', type: 'MITRE', source: 'MITRE ATT&CK', severity: 'High', confidence: 95, firstSeen: '2026-10-07T22:00:00Z', tags: ['PowerShell', 'Execution'] },
  { id: 'tf-005', indicator: 'fe4a9c8b2d1a...', type: 'Hash', source: 'Internal EDR', severity: 'Critical', confidence: 99, firstSeen: '2026-10-08T18:00:00Z', tags: ['LockBit 3.0', 'Ransomware'] },
  { id: 'tf-006', indicator: '45.32.187.12', type: 'IP', source: 'AbuseIPDB', severity: 'High', confidence: 82, firstSeen: '2026-10-08T09:00:00Z', tags: ['Credential Stuffing', 'TOR Exit'] },
];

export const mockSystemHealth: SystemHealth[] = [
  { component: 'LLM Service (Gemini)', status: 'operational', latency: '420ms', uptime: '99.97%' },
  { component: 'AbuseIPDB Feed', status: 'operational', latency: '210ms', uptime: '100%' },
  { component: 'URLhaus Feed', status: 'operational', latency: '180ms', uptime: '99.85%' },
  { component: 'NVD / CVE API', status: 'degraded', latency: '1820ms', uptime: '98.2%' },
  { component: 'MITRE ATT&CK Client', status: 'operational', latency: '310ms', uptime: '100%' },
  { component: 'Policy Engine', status: 'operational', latency: '12ms', uptime: '100%' },
  { component: 'Shared Incident State', status: 'operational', latency: '8ms', uptime: '100%' },
  { component: 'FastAPI Backend', status: 'operational', latency: '45ms', uptime: '99.99%' },
];

// ── Dashboard KPIs ──────────────────────────────────────────
export const mockDashboardKPIs = {
  totalIncidents: 47,
  criticalIncidents: 2,
  activeInvestigations: 4,
  policyReviews: 1,
  resolvedLast24h: 3,
  meanTimeToDetect: '4m 12s',
  meanTimeToContain: '47m 33s',
  agentsActive: 4,
};

// ── Severity Distribution (for chart) ──────────────────────
export const mockSeverityDistribution = [
  { name: 'Critical', value: 2,  fill: '#e53e3e' },
  { name: 'High',     value: 8,  fill: '#f59e0b' },
  { name: 'Medium',   value: 21, fill: '#eab308' },
  { name: 'Low',      value: 12, fill: '#48bb78' },
  { name: 'Info',     value: 4,  fill: '#22d3ee' },
];

// ── Incident trend over past 7 days ────────────────────────
export const mockIncidentTrend = [
  { day: 'Oct 02', incidents: 4, resolved: 4 },
  { day: 'Oct 03', incidents: 7, resolved: 5 },
  { day: 'Oct 04', incidents: 3, resolved: 6 },
  { day: 'Oct 05', incidents: 9, resolved: 7 },
  { day: 'Oct 06', incidents: 5, resolved: 4 },
  { day: 'Oct 07', incidents: 11, resolved: 8 },
  { day: 'Oct 08', incidents: 8, resolved: 3 },
];

// ── Pipeline throughput ────────────────────────────────────
export const mockPipelineThroughput = [
  { stage: 'Normalize', count: 847 },
  { stage: 'Detect', count: 62 },
  { stage: 'Analyze', count: 18 },
  { stage: 'Plan', count: 6 },
  { stage: 'Policy', count: 5 },
  { stage: 'Report', count: 3 },
];

// ── Recent Activity Log ─────────────────────────────────────
export interface ActivityLogEntry {
  id: string;
  timestamp: string;
  agent: string;
  action: string;
  incidentId: string | null;
  severity: Severity | 'System';
}

export const mockActivityLog: ActivityLogEntry[] = [
  { id: 'al-001', timestamp: '2026-10-09T00:02:00Z', agent: 'Malware Analysis Agent', action: 'Suspicious PE entropy detected in ransom.exe — escalating confidence to 78%', incidentId: 'INC-2026-0047', severity: 'Critical' },
  { id: 'al-002', timestamp: '2026-10-08T23:58:00Z', agent: 'Threat Detection Agent', action: 'Kerberoasting pattern correlated with 3 lateral movement events', incidentId: 'INC-2026-0047', severity: 'Critical' },
  { id: 'al-003', timestamp: '2026-10-08T23:44:00Z', agent: 'Recovery Planning Agent', action: 'Containment playbook step 4/7 approved by Policy Engine', incidentId: 'INC-2026-0046', severity: 'High' },
  { id: 'al-004', timestamp: '2026-10-08T23:30:00Z', agent: 'Policy Engine', action: 'WAF rule INC-0045-WAF-R3 flagged for human review — action blocked', incidentId: 'INC-2026-0045', severity: 'High' },
  { id: 'al-005', timestamp: '2026-10-08T22:15:00Z', agent: 'Data Normalizer', action: 'Ingested 214 new telemetry events from SIEM webhook', incidentId: null, severity: 'System' },
  { id: 'al-006', timestamp: '2026-10-08T21:14:00Z', agent: 'Threat Detection Agent', action: 'New critical incident INC-2026-0047 created — pipeline initialized', incidentId: 'INC-2026-0047', severity: 'Critical' },
];
