/**
 * CyberOrchestra Centralized API Service Layer
 *
 * Connects the React frontend directly to the FastAPI backend.
 * Provides typed methods, error handling, and request lifecycle management.
 */

import type {
  AgentStage,
  DashboardStats,
  EvaluationResponse,
  Incident,
  IncidentDetail,
  PolicyReview,
  ReportDetail,
  ReportSummary,
  ScenarioItem,
  SystemHealthResponse,
  ThreatFeedItem,
  ThreatSource,
} from '../types';

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || '/api/v1';

export class ApiError extends Error {
  status: number;
  data: any;

  constructor(message: string, status: number, data?: any) {
    super(message);
    this.name = 'ApiError';
    this.status = status;
    this.data = data;
  }
}

async function fetchJson<T>(endpoint: string, options: RequestInit = {}): Promise<T> {
  const url = `${API_BASE_URL}${endpoint}`;
  const headers = {
    'Content-Type': 'application/json',
    ...(options.headers || {}),
  };

  try {
    const response = await fetch(url, { ...options, headers });

    if (!response.ok) {
      let errorDetail = `HTTP ${response.status} ${response.statusText}`;
      try {
        const errorBody = await response.json();
        if (errorBody.detail) {
          errorDetail = typeof errorBody.detail === 'string' ? errorBody.detail : JSON.stringify(errorBody.detail);
        }
      } catch {
        // use default error message
      }
      throw new ApiError(errorDetail, response.status);
    }

    return (await response.json()) as T;
  } catch (err: any) {
    if (err instanceof ApiError) {
      throw err;
    }
    throw new ApiError(err.message || 'Network request failed. Is the backend server running on port 8000?', 0);
  }
}

export const api = {
  // ── Dashboard & System Health ──────────────────────────────
  getDashboardStats: () => fetchJson<DashboardStats>('/dashboard/stats'),
  getSystemHealth: () => fetchJson<SystemHealthResponse>('/system/health'),
  getAgentsStatus: () => fetchJson<AgentStage[]>('/system/agents'),

  // ── Incidents ──────────────────────────────────────────────
  getIncidents: (params?: { severity?: string; status?: string; search?: string }) => {
    const query = new URLSearchParams();
    if (params?.severity) query.append('severity', params.severity);
    if (params?.status) query.append('status', params.status);
    if (params?.search) query.append('search', params.search);
    const qs = query.toString();
    return fetchJson<Incident[]>(`/incidents${qs ? `?${qs}` : ''}`);
  },

  getScenarios: () => fetchJson<ScenarioItem[]>('/incidents/scenarios'),
  getIncident: (incidentId: string) => fetchJson<IncidentDetail>(`/incidents/${encodeURIComponent(incidentId)}`),

  createIncident: (payload: Record<string, any>) =>
    fetchJson<Incident>('/incidents', {
      method: 'POST',
      body: JSON.stringify(payload),
    }),

  loadScenario: (scenarioFilename: string) =>
    fetchJson<Incident>(`/incidents/load-scenario/${encodeURIComponent(scenarioFilename)}`, {
      method: 'POST',
    }),

  runPipeline: (incidentId: string) =>
    fetchJson<{
      incident_id: string;
      status: string;
      pipeline_stage: string;
      duration: string;
      stages: any[];
      policy_decisions_count: number;
      report_generated: boolean;
    }>(`/incidents/${encodeURIComponent(incidentId)}/run-pipeline`, {
      method: 'POST',
    }),

  enrichIncident: (incidentId: string) =>
    fetchJson<any>(`/incidents/${encodeURIComponent(incidentId)}/enrich`, {
      method: 'POST',
    }),

  // ── Threat Intelligence ────────────────────────────────────
  getThreatFeed: () => fetchJson<ThreatFeedItem[]>('/intelligence/feed'),
  getThreatSources: () => fetchJson<ThreatSource[]>('/intelligence/sources'),

  queryIpReputation: (ip: string, maxAge: number = 30) =>
    fetchJson<any>(`/intelligence/ip/${encodeURIComponent(ip)}?max_age_in_days=${maxAge}`),

  queryUrlReputation: (url: string) =>
    fetchJson<any>(`/intelligence/url?url=${encodeURIComponent(url)}`),

  queryCveIntelligence: (cveId: string) =>
    fetchJson<any>(`/intelligence/cve/${encodeURIComponent(cveId)}`),

  queryMitreTechnique: (techniqueId: string) =>
    fetchJson<any>(`/intelligence/mitre/${encodeURIComponent(techniqueId)}`),

  // ── Recovery & Policy ──────────────────────────────────────
  getPolicyReviews: (statusFilter?: string) => {
    const qs = statusFilter ? `?status=${encodeURIComponent(statusFilter)}` : '';
    return fetchJson<PolicyReview[]>(`/policy/reviews${qs}`);
  },

  approvePolicyReview: (decisionId: string, notes?: string) =>
    fetchJson<{ status: string; decision_id: string; human_status: string; message: string }>(
      `/policy/reviews/${encodeURIComponent(decisionId)}/approve`,
      {
        method: 'POST',
        body: JSON.stringify({ notes }),
      }
    ),

  rejectPolicyReview: (decisionId: string, notes?: string) =>
    fetchJson<{ status: string; decision_id: string; human_status: string; message: string }>(
      `/policy/reviews/${encodeURIComponent(decisionId)}/reject`,
      {
        method: 'POST',
        body: JSON.stringify({ notes }),
      }
    ),

  // ── Reports ────────────────────────────────────────────────
  getReports: () => fetchJson<ReportSummary[]>('/reports'),
  getReport: (reportId: string) => fetchJson<ReportDetail>(`/reports/${encodeURIComponent(reportId)}`),
  generateReport: (incidentId: string) =>
    fetchJson<ReportDetail>(`/reports/generate/${encodeURIComponent(incidentId)}`, {
      method: 'POST',
    }),

  // ── Evaluation ─────────────────────────────────────────────
  getEvaluationResults: () => fetchJson<EvaluationResponse>('/evaluation/results'),
  runEvaluation: () =>
    fetchJson<EvaluationResponse>('/evaluation/run', {
      method: 'POST',
    }),
};
