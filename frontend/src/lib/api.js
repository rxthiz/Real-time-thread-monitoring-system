export class ApiError extends Error {
  constructor(message, status, payload = null) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.payload = payload;
  }
}

const configuredApiBase = String(import.meta.env.VITE_API_BASE_URL || "").trim().replace(/\/$/, "");
const configuredWsBase = String(import.meta.env.VITE_WS_BASE_URL || "").trim().replace(/\/$/, "");

function isAbsoluteHttpUrl(value) {
  return /^https?:\/\//i.test(String(value || ""));
}

function isAbsoluteWsUrl(value) {
  return /^wss?:\/\//i.test(String(value || ""));
}

async function parsePayload(response) {
  const contentType = response.headers.get("content-type") || "";
  if (contentType.includes("application/json")) {
    return response.json();
  }

  const text = await response.text();
  if (!text) {
    return null;
  }
  try {
    return JSON.parse(text);
  } catch (_error) {
    return text;
  }
}

export function buildApiUrl(path) {
  if (isAbsoluteHttpUrl(path)) {
    return path;
  }
  return configuredApiBase ? `${configuredApiBase}${path}` : path;
}

export function buildWebSocketUrl(path) {
  if (isAbsoluteWsUrl(path)) {
    return path;
  }
  if (configuredWsBase) {
    return `${configuredWsBase}${path}`;
  }
  if (configuredApiBase) {
    const url = new URL(configuredApiBase);
    url.protocol = url.protocol === "https:" ? "wss:" : "ws:";
    url.pathname = path;
    url.search = "";
    url.hash = "";
    return url.toString();
  }
  const protocol = window.location.protocol === "https:" ? "wss" : "ws";
  return `${protocol}://${window.location.host}${path}`;
}

export async function apiRequest(path, options = {}) {
  const isJsonBody = options.body && !(options.body instanceof FormData);
  const response = await fetch(buildApiUrl(path), {
    credentials: "include",
    cache: "no-store",
    ...options,
    headers: {
      Accept: "application/json",
      ...(isJsonBody ? { "Content-Type": "application/json" } : {}),
      ...(options.headers || {}),
    },
  });

  if (response.status === 401) {
    window.location.assign(buildApiUrl("/login"));
    throw new ApiError("Authentication required", 401);
  }

  if (!response.ok) {
    const payload = await parsePayload(response);
    const message =
      payload && typeof payload === "object" && "detail" in payload
        ? String(payload.detail)
        : response.statusText || "Request failed";
    throw new ApiError(message, response.status, payload);
  }

  return response;
}

export async function getJson(path, options = {}) {
  const response = await apiRequest(path, { method: "GET", ...options });
  return parsePayload(response);
}

export async function postJson(path, payload, options = {}) {
  const body = payload instanceof FormData ? payload : JSON.stringify(payload);
  const response = await apiRequest(path, {
    method: "POST",
    body,
    ...options,
  });
  return parsePayload(response);
}

export function fetchLiveZoneStatus() {
  return getJson("/api/zones/live-status?limit=500");
}

export function fetchZoneLayout() {
  return getJson("/api/zones/layout?limit=500");
}

export function fetchZonePolicies() {
  return getJson("/api/zones/policies?limit=500");
}

export function fetchAnalyticsOverview() {
  return getJson("/api/analytics/overview?days=30");
}

export function fetchAnalyticsHeatmap() {
  return getJson("/api/analytics/heatmap?days=30");
}

export function fetchDetectionHistory() {
  return getJson("/api/detections/history?limit=160");
}

export function fetchAlertHistory() {
  return getJson("/api/alerts/history?limit=160");
}

export function fetchAlertEvidence(alertId) {
  return getJson(`/api/alerts/${encodeURIComponent(alertId)}/evidence`);
}

export function fetchAlertExplanation(alertId) {
  return getJson(`/api/alerts/${encodeURIComponent(alertId)}/explanation`);
}

export function submitFalsePositiveFeedback(payload) {
  return postJson("/api/feedback", payload);
}

export function fetchFalsePositiveModelStatus() {
  return getJson("/api/model/status");
}

export function fetchPredictiveTracks({ limit = 120, withinSeconds = 1800 } = {}) {
  return getJson(`/api/predictive/tracks?limit=${encodeURIComponent(limit)}&within_seconds=${encodeURIComponent(withinSeconds)}`);
}

export function fetchPredictiveHighRisk({ limit = 60, withinSeconds = 1800 } = {}) {
  return getJson(`/api/predictive/high-risk?limit=${encodeURIComponent(limit)}&within_seconds=${encodeURIComponent(withinSeconds)}`);
}

export function fetchReidTracks({ limit = 120, withinSeconds = 1800 } = {}) {
  return getJson(`/api/reid/tracks?limit=${encodeURIComponent(limit)}&within_seconds=${encodeURIComponent(withinSeconds)}`);
}

export function fetchReidTrackPath(trackId) {
  return getJson(`/api/reid/tracks/${encodeURIComponent(trackId)}/path`);
}

export function fetchTrackProfile(trackId) {
  return getJson(`/api/tracks/${encodeURIComponent(trackId)}/profile`);
}

export function saveZonePolicy(zoneKey, payload) {
  return postJson(`/api/zones/${encodeURIComponent(zoneKey)}/policy`, payload);
}

export function fetchServices() {
  return getJson("/api/services");
}

export function triggerManualSos(payload) {
  return postJson("/api/sos/manual", payload);
}

export function dispatchSos(payload) {
  return postJson("/api/sos/dispatch", payload);
}

export function fetchIncidentResponse(incidentId) {
  return getJson(`/api/incidents/${encodeURIComponent(incidentId)}/response`);
}

export function acknowledgeIncident(incidentId, payload) {
  return postJson(`/api/incidents/${encodeURIComponent(incidentId)}/ack`, payload);
}
