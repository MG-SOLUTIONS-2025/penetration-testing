const API_BASE = import.meta.env.VITE_API_URL || "http://localhost:8000";

async function request<T>(
  path: string,
  options: RequestInit = {}
): Promise<T> {
  const token = localStorage.getItem("token");
  const headers: Record<string, string> = {
    "Content-Type": "application/json",
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
    ...(options.headers as Record<string, string> || {}),
  };

  const res = await fetch(`${API_BASE}${path}`, { ...options, headers });

  if (res.status === 401) {
    localStorage.removeItem("token");
    window.location.href = "/login";
    throw new Error("Unauthorized");
  }

  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new Error(body.detail || `HTTP ${res.status}`);
  }

  if (res.status === 204) return undefined as T;
  return res.json();
}

// Auth
export const login = (email: string, password: string) =>
  request<{ access_token: string }>("/api/v1/auth/login", {
    method: "POST",
    body: JSON.stringify({ email, password }),
  });

export const register = (email: string, password: string, full_name: string) =>
  request<{ id: string }>("/api/v1/auth/register", {
    method: "POST",
    body: JSON.stringify({ email, password, full_name }),
  });

export const getMe = () => request<User>("/api/v1/auth/me");

// Engagements
export const getEngagements = () =>
  request<Engagement[]>("/api/v1/engagements/");

export const createEngagement = (data: CreateEngagement) =>
  request<Engagement>("/api/v1/engagements/", {
    method: "POST",
    body: JSON.stringify(data),
  });

// Targets
export const getTargets = (engagementId: string) =>
  request<Target[]>(`/api/v1/engagements/${engagementId}/targets/`);

export const createTarget = (engagementId: string, data: CreateTarget) =>
  request<Target>(`/api/v1/engagements/${engagementId}/targets/`, {
    method: "POST",
    body: JSON.stringify(data),
  });

export const deleteTarget = (engagementId: string, targetId: string) =>
  request<void>(`/api/v1/engagements/${engagementId}/targets/${targetId}`, {
    method: "DELETE",
  });

// Scans
export const getScans = (params?: { engagement_id?: string; status?: string }) => {
  const query = new URLSearchParams();
  if (params?.engagement_id) query.set("engagement_id", params.engagement_id);
  if (params?.status) query.set("status", params.status);
  const qs = query.toString();
  return request<Scan[]>(`/api/v1/scans/${qs ? `?${qs}` : ""}`);
};

export const getScan = (id: string) => request<Scan>(`/api/v1/scans/${id}`);

export const createScan = (data: CreateScan) =>
  request<Scan>("/api/v1/scans/", {
    method: "POST",
    body: JSON.stringify(data),
  });

export const cancelScan = (id: string) =>
  request<{ status: string }>(`/api/v1/scans/${id}/cancel`, { method: "POST" });

// Findings
export const getFindings = (params?: {
  engagement_id?: string;
  scan_id?: string;
  severity?: string;
  page?: number;
}) => {
  const query = new URLSearchParams();
  if (params?.engagement_id) query.set("engagement_id", params.engagement_id);
  if (params?.scan_id) query.set("scan_id", params.scan_id);
  if (params?.severity) query.set("severity", params.severity);
  if (params?.page) query.set("page", String(params.page));
  const qs = query.toString();
  return request<PaginatedResponse<Finding>>(
    `/api/v1/findings/${qs ? `?${qs}` : ""}`
  );
};

// WebSocket
export const connectScanWS = (taskId: string): WebSocket => {
  const wsBase = API_BASE.replace("http", "ws");
  const token = localStorage.getItem("token");
  return new WebSocket(`${wsBase}/ws/scans/${taskId}?token=${token || ""}`);
};

// Types
export interface User {
  id: string;
  email: string;
  full_name: string;
  is_active: boolean;
  is_admin: boolean;
  created_at: string;
}

export interface Engagement {
  id: string;
  name: string;
  client_name: string;
  authorized_by: string;
  auth_document_hash: string | null;
  starts_at: string;
  ends_at: string;
  notes: string | null;
  created_by: string;
  created_at: string;
}

export interface CreateEngagement {
  name: string;
  client_name: string;
  authorized_by: string;
  starts_at: string;
  ends_at: string;
  notes?: string;
}

export interface Target {
  id: string;
  engagement_id: string;
  target_type: string;
  value: string;
  is_in_scope: boolean;
  created_at: string;
}

export interface CreateTarget {
  target_type: string;
  value: string;
  is_in_scope?: boolean;
}

export interface Scan {
  id: string;
  engagement_id: string;
  target_id: string | null;
  scan_type: string;
  status: string;
  celery_task_id: string | null;
  config: Record<string, unknown> | null;
  started_at: string | null;
  completed_at: string | null;
  error_message: string | null;
  created_by: string;
  created_at: string;
}

export interface CreateScan {
  engagement_id: string;
  target_id?: string;
  scan_type: string;
  config?: Record<string, unknown>;
}

export interface Finding {
  id: string;
  scan_id: string;
  engagement_id: string;
  title: string;
  severity: string;
  finding_type: string;
  target_value: string;
  detail: Record<string, unknown> | null;
  raw_output: string | null;
  fingerprint: string;
  defectdojo_finding_id: number | null;
  created_at: string;
}

export interface PaginatedResponse<T> {
  items: T[];
  total: number;
  page: number;
  page_size: number;
}
