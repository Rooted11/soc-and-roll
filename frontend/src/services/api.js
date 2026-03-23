/*
 * Central API client for the AI-SOC frontend.
 *
 * Defaults to relative /api requests so the app works with the Vite proxy
 * in development and with nginx in a production image. An absolute browser-
 * reachable base URL can still be supplied via VITE_API_URL when needed.
 */

const RAW_BASE = import.meta.env.VITE_API_URL || "/api";

const BASE = RAW_BASE.replace(/\/+$/, "");

function buildUrl(path) {
  const normalizedPath = path.startsWith("/") ? path : `/${path}`;
  return BASE === "/api" && normalizedPath.startsWith("/api")
    ? normalizedPath
    : `${BASE}${normalizedPath}`;
}

async function request(path, options = {}) {
  const res = await fetch(buildUrl(path), {
    headers: { "Content-Type": "application/json", ...options.headers },
    ...options,
  });

  if (!res.ok) {
    const text = await res.text();
    throw new Error(`API ${res.status}: ${text}`);
  }

  return res.json();
}

export const api = {
  getOverview: () => request("/api/overview"),

  getIncidents: (params = {}) => {
    const qs = new URLSearchParams(
      Object.fromEntries(Object.entries(params).filter(([, value]) => value != null))
    ).toString();
    return request(`/api/incidents${qs ? `?${qs}` : ""}`);
  },

  getIncidentStats: () => request("/api/incidents/stats"),
  getIncident: (id) => request(`/api/incidents/${id}`),

  updateIncident: (id, payload) =>
    request(`/api/incidents/${id}`, {
      method: "PATCH",
      body: JSON.stringify(payload),
    }),

  triggerPlaybook: (id, payload = {}) =>
    request(`/api/incidents/${id}/respond`, {
      method: "POST",
      body: JSON.stringify(payload),
    }),

  getPlaybookActions: (id) => request(`/api/incidents/${id}/actions`),

  getLogs: (params = {}) => {
    const qs = new URLSearchParams(
      Object.fromEntries(Object.entries(params).filter(([, value]) => value != null))
    ).toString();
    return request(`/api/logs${qs ? `?${qs}` : ""}`);
  },

  getLogStats: () => request("/api/logs/stats"),

  ingestLogs: (logs) =>
    request("/api/logs/ingest", {
      method: "POST",
      body: JSON.stringify({ logs }),
    }),

  getThreatIntel: (params = {}) => {
    const qs = new URLSearchParams(
      Object.fromEntries(Object.entries(params).filter(([, value]) => value != null))
    ).toString();
    return request(`/api/threat-intel${qs ? `?${qs}` : ""}`);
  },

  refreshThreatFeed: () =>
    request("/api/threat-intel/refresh", { method: "POST" }),

  getAssets: () => request("/api/assets"),

  // ── AI (Claude) ──────────────────────────────────────────────────────────
  aiQuery: (incident_id, query) =>
    request("/api/ai/query", {
      method: "POST",
      body: JSON.stringify({ incident_id, query }),
    }),

  aiReport: (incident_id) =>
    request(`/api/ai/report/${incident_id}`, { method: "POST" }),
};
