const MAX_DETECTION_ROWS = 120;
const MAX_ACTIVITY_ITEMS = 80;
const OVERLAY_TTL_MS = 1200;
const MAP_REFRESH_INTERVAL_MS = 45000;
const MAP_ALLOWED_RADII = new Set([2, 5, 10]);
const INCIDENT_TIMELINE_LIMIT = 3000;

const state = {
  frameSocket: null,
  detectionSocket: null,
  frameReconnectTimer: null,
  detectionReconnectTimer: null,
  redirectedToLogin: false,
  connected: false,
  liveCameraActive: false,
  role: null,
  username: null,
  currentSource: null,
  zonePolicy: null,
  lastZonePolicyFetchAt: 0,
  detections: [],
  alerts: [],
  counts: { HIGH: 0, MEDIUM: 0, LOW: 0 },
  overlayDetections: [],
  overlaySeenAt: 0,
  frameWidth: 0,
  frameHeight: 0,
  activeTab: "monitor",
  map: null,
  mapLayers: null,
  mapInitialized: false,
  cameraLocation: null,
  mapRadiusKm: 5,
  mapLoading: false,
  incidentTimeline: null,
  incidentEscalation: null,
  analyticsOverview: null,
  analyticsHeatmap: null,
};

const el = {
  feedWrap: document.getElementById("feedWrap"),
  feedImage: document.getElementById("feedImage"),
  overlayCanvas: document.getElementById("overlayCanvas"),
  frameMeta: document.getElementById("frameMeta"),
  connectionBadge: document.getElementById("connectionBadge"),
  authRoleBadge: document.getElementById("authRoleBadge"),
  authUserBadge: document.getElementById("authUserBadge"),
  logoutBtn: document.getElementById("logoutBtn"),
  liveCameraBtn: document.getElementById("liveCameraBtn"),
  reconnectBtn: document.getElementById("reconnectBtn"),
  clearDetectionsBtn: document.getElementById("clearDetectionsBtn"),
  clearAlertsBtn: document.getElementById("clearAlertsBtn"),
  statusSource: document.getElementById("statusSource"),
  statusFps: document.getElementById("statusFps"),
  statusResolution: document.getElementById("statusResolution"),
  statusAction: document.getElementById("statusAction"),
  zonePolicyMeta: document.getElementById("zonePolicyMeta"),
  zonePolicyCurrent: document.getElementById("zonePolicyCurrent"),
  zoneThresholdInput: document.getElementById("zoneThresholdInput"),
  zoneSnoozeInput: document.getElementById("zoneSnoozeInput"),
  zonePolicyApplyBtn: document.getElementById("zonePolicyApplyBtn"),
  detectionCount: document.getElementById("detectionCount"),
  alertCount: document.getElementById("alertCount"),
  detectionsBody: document.getElementById("detectionsBody"),
  alertsBody: document.getElementById("alertsBody"),
  countHigh: document.getElementById("countHigh"),
  countMedium: document.getElementById("countMedium"),
  countLow: document.getElementById("countLow"),
  activityLog: document.getElementById("activityLog"),
  tabMonitorBtn: document.getElementById("tabMonitorBtn"),
  tabMapBtn: document.getElementById("tabMapBtn"),
  tabIncidentBtn: document.getElementById("tabIncidentBtn"),
  tabAnalyticsBtn: document.getElementById("tabAnalyticsBtn"),
  monitorTab: document.getElementById("monitorTab"),
  mapTab: document.getElementById("mapTab"),
  incidentTab: document.getElementById("incidentTab"),
  analyticsTab: document.getElementById("analyticsTab"),
  mapStatus: document.getElementById("mapStatus"),
  mapRadiusSelect: document.getElementById("mapRadiusSelect"),
  useMyLocationBtn: document.getElementById("useMyLocationBtn"),
  refreshMapBtn: document.getElementById("refreshMapBtn"),
  applyCoordinatesBtn: document.getElementById("applyCoordinatesBtn"),
  cameraLatInput: document.getElementById("cameraLatInput"),
  cameraLonInput: document.getElementById("cameraLonInput"),
  cameraLocationText: document.getElementById("cameraLocationText"),
  mapView: document.getElementById("mapView"),
  mapTotalCount: document.getElementById("mapTotalCount"),
  hospitalCount: document.getElementById("hospitalCount"),
  policeCount: document.getElementById("policeCount"),
  fireCount: document.getElementById("fireCount"),
  hospitalList: document.getElementById("hospitalList"),
  policeList: document.getElementById("policeList"),
  fireList: document.getElementById("fireList"),
  incidentSummaryText: document.getElementById("incidentSummaryText"),
  incidentIdInput: document.getElementById("incidentIdInput"),
  loadIncidentBtn: document.getElementById("loadIncidentBtn"),
  exportIncidentPdfBtn: document.getElementById("exportIncidentPdfBtn"),
  incidentTimelineBody: document.getElementById("incidentTimelineBody"),
  incidentEventForm: document.getElementById("incidentEventForm"),
  incidentEventTypeSelect: document.getElementById("incidentEventTypeSelect"),
  incidentEventSourceInput: document.getElementById("incidentEventSourceInput"),
  incidentUnitInput: document.getElementById("incidentUnitInput"),
  incidentOfficerInput: document.getElementById("incidentOfficerInput"),
  incidentEtaInput: document.getElementById("incidentEtaInput"),
  incidentNoteInput: document.getElementById("incidentNoteInput"),
  incidentEventSubmitBtn: document.getElementById("incidentEventSubmitBtn"),
  escalationStatusText: document.getElementById("escalationStatusText"),
  escalationStatusBody: document.getElementById("escalationStatusBody"),
  startEscalationBtn: document.getElementById("startEscalationBtn"),
  ackEscalationBtn: document.getElementById("ackEscalationBtn"),
  refreshEscalationBtn: document.getElementById("refreshEscalationBtn"),
  analyticsSummaryText: document.getElementById("analyticsSummaryText"),
  analyticsFromInput: document.getElementById("analyticsFromInput"),
  analyticsToInput: document.getElementById("analyticsToInput"),
  analyticsZoneInput: document.getElementById("analyticsZoneInput"),
  analyticsHourStartInput: document.getElementById("analyticsHourStartInput"),
  analyticsHourEndInput: document.getElementById("analyticsHourEndInput"),
  loadAnalyticsBtn: document.getElementById("loadAnalyticsBtn"),
  shiftAnalyticsBody: document.getElementById("shiftAnalyticsBody"),
  operatorAnalyticsBody: document.getElementById("operatorAnalyticsBody"),
  zoneRiskBody: document.getElementById("zoneRiskBody"),
  heatmapZoneSelect: document.getElementById("heatmapZoneSelect"),
  refreshHeatmapBtn: document.getElementById("refreshHeatmapBtn"),
  heatmapGrid: document.getElementById("heatmapGrid"),
  shiftWindowBody: document.getElementById("shiftWindowBody"),
  saveShiftWindowsBtn: document.getElementById("saveShiftWindowsBtn"),
};

function wsBase() {
  const proto = window.location.protocol === "https:" ? "wss" : "ws";
  return `${proto}://${window.location.host}`;
}

function redirectToLogin() {
  if (state.redirectedToLogin) return;
  state.redirectedToLogin = true;
  window.location.replace("/login");
}

async function apiFetch(url, options) {
  const response = await fetch(url, options);
  if (response.status === 401) {
    redirectToLogin();
    throw new Error("Authentication required");
  }
  return response;
}

function applyRolePermissions() {
  const isAdmin = state.role === "admin";
  for (const button of document.querySelectorAll('[data-admin-only="true"]')) {
    button.disabled = !isAdmin;
    button.title = isAdmin ? "" : "Admin access required";
  }
}

function setAuthBadge() {
  const roleLabel = state.role ? String(state.role).toUpperCase() : "-";
  const userLabel = state.username || "-";
  el.authRoleBadge.textContent = `Role: ${roleLabel}`;
  el.authUserBadge.textContent = `User: ${userLabel}`;
}

async function loadAuthContext() {
  const r = await apiFetch("/api/auth/me", { cache: "no-store" });
  if (!r.ok) {
    throw new Error(`auth ${r.status}`);
  }
  const info = await r.json();
  state.role = String(info.role || "").toLowerCase();
  state.username = String(info.username || "");
  setAuthBadge();
  applyRolePermissions();
}

function zoneKeyFromSource(source) {
  const safe = String(source || "").trim().toLowerCase();
  if (safe.startsWith("camera:")) return safe;
  return "zone:default";
}

function currentHourLocal() {
  return new Date().getHours();
}

function renderZonePolicy(policy, zoneKey, hourOfDay) {
  el.zonePolicyMeta.textContent = `Zone: ${zoneKey} | Hour: ${hourOfDay}:00`;
  if (!policy) {
    el.zonePolicyCurrent.textContent = "Threshold: - | Snooze: -";
    return;
  }
  const threshold = Number(policy.effective_threshold ?? policy.adaptive_threshold ?? 0).toFixed(3);
  const snooze = policy.snooze_until ? toLocalTime(policy.snooze_until) : "none";
  const status = policy.is_snoozed ? "active" : "inactive";
  el.zonePolicyCurrent.textContent = `Threshold: ${threshold} | Snooze: ${snooze} (${status})`;
}

async function fetchZonePolicy(force = false) {
  const zoneKey = zoneKeyFromSource(state.currentSource);
  const hourOfDay = currentHourLocal();
  if (state.role !== "admin") {
    renderZonePolicy(null, zoneKey, hourOfDay);
    el.zonePolicyCurrent.textContent = "Threshold: admin-only view";
    return;
  }

  const now = Date.now();
  if (!force && now - state.lastZonePolicyFetchAt < 12000) return;
  state.lastZonePolicyFetchAt = now;

  const query = new URLSearchParams({ hour_of_day: String(hourOfDay) });
  const r = await apiFetch(`/api/zones/${encodeURIComponent(zoneKey)}/policy?${query.toString()}`, {
    cache: "no-store",
  });
  if (!r.ok) {
    throw new Error(await getErrorDetail(r, `zone policy ${r.status}`));
  }
  const policy = await r.json();
  state.zonePolicy = policy;
  renderZonePolicy(policy, zoneKey, hourOfDay);
  if (!el.zoneThresholdInput.value) {
    el.zoneThresholdInput.value = Number(policy.adaptive_threshold ?? 0).toFixed(2);
  }
}

async function applyZonePolicy() {
  const zoneKey = zoneKeyFromSource(state.currentSource);
  const hourOfDay = currentHourLocal();
  const rawThreshold = String(el.zoneThresholdInput.value || "").trim();
  const rawSnooze = String(el.zoneSnoozeInput.value || "").trim();

  const payload = { hour_of_day: hourOfDay };
  if (rawThreshold) {
    const value = Number(rawThreshold);
    if (!Number.isFinite(value) || value < 0 || value > 1) {
      throw new Error("Threshold must be between 0 and 1");
    }
    payload.adaptive_threshold = value;
  }
  if (rawSnooze) {
    const value = Number(rawSnooze);
    if (!Number.isFinite(value) || value < 0) {
      throw new Error("Snooze minutes must be a non-negative number");
    }
    payload.snooze_minutes = Math.floor(value);
  }

  const r = await apiFetch(`/api/zones/${encodeURIComponent(zoneKey)}/policy`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  if (!r.ok) {
    throw new Error(await getErrorDetail(r, `apply zone policy ${r.status}`));
  }
  const result = await r.json();
  state.zonePolicy = result.policy || null;
  renderZonePolicy(state.zonePolicy, zoneKey, hourOfDay);
  addActivity(`Zone policy updated for ${zoneKey} hour ${hourOfDay}`);
}

async function logout() {
  try {
    await apiFetch("/api/auth/logout", { method: "POST" });
  } catch (_err) {
    // Logout should still redirect even if request fails.
  }
  redirectToLogin();
}

function setConnected(flag) {
  state.connected = flag;
  if (flag) {
    el.connectionBadge.textContent = "Connected";
    el.connectionBadge.classList.remove("badge-offline");
    el.connectionBadge.classList.add("badge-online");
  } else {
    el.connectionBadge.textContent = "Disconnected";
    el.connectionBadge.classList.remove("badge-online");
    el.connectionBadge.classList.add("badge-offline");
  }
}

function setLiveCameraButton() {
  if (state.liveCameraActive) {
    el.liveCameraBtn.textContent = "Close Live Camera";
    el.liveCameraBtn.classList.add("subtle");
  } else {
    el.liveCameraBtn.textContent = "Open Live Camera";
    el.liveCameraBtn.classList.remove("subtle");
  }
}

function toLocalTime(value) {
  if (!value) return "-";
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return String(value);
  return d.toLocaleTimeString();
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

async function getErrorDetail(response, fallback) {
  let reason = fallback;
  try {
    const body = await response.json();
    if (body?.detail) {
      reason = String(body.detail);
    }
  } catch (_err) {
    // Ignore parse failures.
  }
  return reason;
}

function dispositionActionTag(action) {
  const normalized = String(action || "").toUpperCase();
  if (normalized === "ACKNOWLEDGED") return '<span class="tag tag-low">ACKNOWLEDGED</span>';
  if (normalized === "ESCALATED") return '<span class="tag tag-high">ESCALATED</span>';
  if (normalized === "DISMISSED") return '<span class="tag tag-medium">DISMISSED</span>';
  return '<span class="muted">Pending</span>';
}

function renderDispositionCell(alertItem) {
  const alertId = String(alertItem?.alert_id || "");
  if (!alertId) {
    return '<span class="muted">-</span>';
  }
  const latest = alertItem?.latest_disposition || null;
  const dispositionLabel = latest
    ? `${dispositionActionTag(latest.action)}<span class="service-meta">by ${escapeHtml(latest.operator_id || "-")} at ${escapeHtml(toLocalTime(latest.event_timestamp))}</span>`
    : '<span class="service-meta">No operator action yet</span>';
  return `
    <div class="alert-disposition-cell">
      ${dispositionLabel}
      <div class="alert-disposition-actions">
        <button class="btn subtle tiny" type="button" data-alert-id="${escapeHtml(alertId)}" data-disposition="acknowledged">Acknowledge</button>
        <button class="btn subtle tiny" type="button" data-alert-id="${escapeHtml(alertId)}" data-disposition="escalated">Escalate</button>
        <button class="btn subtle tiny" type="button" data-alert-id="${escapeHtml(alertId)}" data-disposition="dismissed">Dismiss</button>
      </div>
    </div>
  `;
}

function addActivity(message) {
  const item = document.createElement("li");
  item.innerHTML = `<span class="mono muted">${new Date().toLocaleTimeString()}</span> ${escapeHtml(message)}`;
  el.activityLog.prepend(item);
  while (el.activityLog.childElementCount > MAX_ACTIVITY_ITEMS) {
    el.activityLog.removeChild(el.activityLog.lastChild);
  }
}

function severityTag(level) {
  const norm = (level || "LOW").toUpperCase();
  if (norm === "HIGH") return '<span class="tag tag-high">HIGH</span>';
  if (norm === "MEDIUM") return '<span class="tag tag-medium">MEDIUM</span>';
  return '<span class="tag tag-low">LOW</span>';
}

function getOverlayContext() {
  const ctx = el.overlayCanvas.getContext("2d");
  if (!ctx) return null;

  const rect = el.feedWrap.getBoundingClientRect();
  const width = Math.max(1, Math.round(rect.width));
  const height = Math.max(1, Math.round(rect.height));
  const dpr = window.devicePixelRatio || 1;
  const targetWidth = Math.max(1, Math.round(width * dpr));
  const targetHeight = Math.max(1, Math.round(height * dpr));

  if (el.overlayCanvas.width !== targetWidth || el.overlayCanvas.height !== targetHeight) {
    el.overlayCanvas.width = targetWidth;
    el.overlayCanvas.height = targetHeight;
    el.overlayCanvas.style.width = `${width}px`;
    el.overlayCanvas.style.height = `${height}px`;
  }

  ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
  return { ctx, width, height };
}

function clearOverlay() {
  const canvas = getOverlayContext();
  if (!canvas) return;
  canvas.ctx.clearRect(0, 0, canvas.width, canvas.height);
}

function drawOverlay() {
  const canvas = getOverlayContext();
  if (!canvas) return;

  const { ctx, width, height } = canvas;
  ctx.clearRect(0, 0, width, height);

  if (Date.now() - state.overlaySeenAt > OVERLAY_TTL_MS) return;
  if (!Array.isArray(state.overlayDetections) || state.overlayDetections.length === 0) return;

  const sourceWidth = state.frameWidth || el.feedImage.naturalWidth;
  const sourceHeight = state.frameHeight || el.feedImage.naturalHeight;
  if (!sourceWidth || !sourceHeight) return;

  const scale = Math.min(width / sourceWidth, height / sourceHeight);
  const drawWidth = sourceWidth * scale;
  const drawHeight = sourceHeight * scale;
  const offsetX = (width - drawWidth) / 2;
  const offsetY = (height - drawHeight) / 2;

  ctx.lineWidth = 2;
  ctx.strokeStyle = "#ff4747";
  ctx.font = "600 13px Trebuchet MS";
  ctx.textBaseline = "top";

  for (const det of state.overlayDetections) {
    if (!Array.isArray(det.bbox) || det.bbox.length !== 4) continue;
    const [x1, y1, x2, y2] = det.bbox;
    if ([x1, y1, x2, y2].some((v) => !Number.isFinite(v))) continue;

    const rectX = offsetX + (x1 / sourceWidth) * drawWidth;
    const rectY = offsetY + (y1 / sourceHeight) * drawHeight;
    const rectW = ((x2 - x1) / sourceWidth) * drawWidth;
    const rectH = ((y2 - y1) / sourceHeight) * drawHeight;
    if (rectW <= 1 || rectH <= 1) continue;

    ctx.strokeRect(rectX, rectY, rectW, rectH);

    const label = `${det.label} ${(det.confidence * 100).toFixed(1)}%`;
    const padX = 6;
    const tagHeight = 18;
    const tagWidth = ctx.measureText(label).width + padX * 2;
    const tagY = Math.max(0, rectY - tagHeight);

    ctx.fillStyle = "rgba(255, 71, 71, 0.9)";
    ctx.fillRect(rectX, tagY, tagWidth, tagHeight);
    ctx.fillStyle = "#ffffff";
    ctx.fillText(label, rectX + padX, tagY + 2);
  }
}

function updateOverlayDetections(packet) {
  const detections = Array.isArray(packet?.detections) ? packet.detections : [];
  state.overlayDetections = detections
    .map((det) => {
      const bbox = Array.isArray(det?.bbox_xyxy) && det.bbox_xyxy.length === 4 ? det.bbox_xyxy.map((v) => Number(v)) : null;
      return {
        label: det?.label || "weapon",
        confidence: Number(det?.confidence || 0),
        bbox,
      };
    })
    .filter((det) => Array.isArray(det.bbox) && det.bbox.every((v) => Number.isFinite(v)));
  state.overlaySeenAt = Date.now();
  drawOverlay();
}

function updateSeverityCounters() {
  el.countHigh.textContent = String(state.counts.HIGH);
  el.countMedium.textContent = String(state.counts.MEDIUM);
  el.countLow.textContent = String(state.counts.LOW);
}

function pushDetection(packet) {
  if (!packet || !Array.isArray(packet.detections) || packet.detections.length === 0) return;
  updateOverlayDetections(packet);

  const first = packet.detections[0];
  const row = {
    time: packet.timestamp,
    weapon: first.label || "-",
    threatId: first?.reid?.threat_id || "-",
    confidence: Number(first.confidence || 0),
    severity: packet.severity?.level || "LOW",
    action: packet.action?.label || "unknown",
  };
  state.detections.unshift(row);
  if (state.detections.length > MAX_DETECTION_ROWS) {
    state.detections.length = MAX_DETECTION_ROWS;
  }

  const sev = row.severity.toUpperCase();
  if (state.counts[sev] !== undefined) {
    state.counts[sev] += 1;
    updateSeverityCounters();
  }

  renderDetections();
}

function renderDetections() {
  el.detectionCount.textContent = `${state.detections.length} records`;
  const rows = state.detections
    .map(
      (d) => `
      <tr>
        <td>${escapeHtml(toLocalTime(d.time))}</td>
        <td>${escapeHtml(d.weapon)}</td>
        <td><span class="mono">${escapeHtml(d.threatId || "-")}</span></td>
        <td>${d.confidence.toFixed(3)}</td>
        <td>${severityTag(d.severity)}</td>
        <td>${escapeHtml(d.action)}</td>
      </tr>
    `,
    )
    .join("");
  el.detectionsBody.innerHTML = rows || '<tr><td colspan="6" class="muted">No detections yet</td></tr>';
}

function renderAlerts() {
  el.alertCount.textContent = `${state.alerts.length} alerts`;
  const rows = state.alerts
    .map((a) => {
      const event = a.event || {};
      const alertId = a.alert_id ? String(a.alert_id) : "-";
      const threatId = a.threat_id ? String(a.threat_id) : "-";
      return `
      <tr>
        <td><span class="mono">${escapeHtml(alertId)}</span></td>
        <td><span class="mono">${escapeHtml(threatId)}</span></td>
        <td>${escapeHtml(toLocalTime(a.timestamp))}</td>
        <td>${severityTag(event.level || "LOW")}</td>
        <td>${escapeHtml(event.weapon || "-")}</td>
        <td>${Number(event.score || 0).toFixed(3)}</td>
        <td>${escapeHtml(event.reason || "-")}</td>
        <td>${renderDispositionCell(a)}</td>
      </tr>
    `;
    })
    .join("");
  el.alertsBody.innerHTML = rows || '<tr><td colspan="8" class="muted">No alerts yet</td></tr>';
}

function toLocalDateTime(value) {
  if (!value) return "-";
  const d = new Date(value);
  if (Number.isNaN(d.getTime())) return String(value);
  return d.toLocaleString();
}

function incidentCategoryTag(category) {
  const norm = String(category || "").toUpperCase();
  if (norm === "ALERT") return '<span class="tag tag-high">ALERT</span>';
  if (norm === "DETECTION") return '<span class="tag tag-medium">DETECTION</span>';
  if (norm === "DISPATCH") return '<span class="tag tag-low">DISPATCH</span>';
  if (norm === "ESCALATION") return '<span class="tag tag-high">ESCALATION</span>';
  if (norm === "OPERATOR_ACTION") return '<span class="tag tag-medium">OPERATOR</span>';
  return `<span class="tag tag-low">${escapeHtml(norm || "EVENT")}</span>`;
}

function defaultIncidentId() {
  for (const item of state.alerts) {
    const threatId = String(item?.threat_id || "").trim();
    if (threatId) return threatId;
    const alertId = String(item?.alert_id || "").trim();
    if (alertId) return alertId;
  }
  for (const item of state.detections) {
    const threatId = String(item?.threatId || "").trim();
    if (threatId && threatId !== "-") return threatId;
  }
  return "";
}

function getIncidentIdOrThrow() {
  const typed = String(el.incidentIdInput.value || "").trim();
  if (typed) return typed;
  const fallback = defaultIncidentId();
  if (fallback) {
    el.incidentIdInput.value = fallback;
    return fallback;
  }
  throw new Error("Enter Incident ID (THR-... or ALT-...)");
}

function renderIncidentTimeline(payload) {
  state.incidentTimeline = payload || null;
  if (!payload) {
    el.incidentSummaryText.textContent = "Load an incident to reconstruct timeline";
    el.incidentTimelineBody.innerHTML = '<tr><td colspan="6" class="muted">No timeline loaded</td></tr>';
    return;
  }

  const summary = payload.summary || {};
  const incidentId = payload.incident_id || "-";
  const threatId = payload.threat_id || "-";
  el.incidentSummaryText.textContent =
    `Incident=${incidentId} | Threat=${threatId} | Events=${summary.total_events ?? 0} | ` +
    `Alerts=${summary.alerts ?? 0} | Detections=${summary.detections ?? 0} | Dispatch=${summary.dispatch_events ?? 0} | Escalation=${summary.escalation_events ?? 0}`;

  const events = Array.isArray(payload.events) ? payload.events : [];
  const rows = events
    .map((event) => {
      return `
        <tr>
          <td>${escapeHtml(toLocalDateTime(event.timestamp))}</td>
          <td>${incidentCategoryTag(event.category)}</td>
          <td>${escapeHtml(event.source || "-")}</td>
          <td>${escapeHtml(event.operator_id || "-")}</td>
          <td>${escapeHtml(event.title || "-")}</td>
          <td>${escapeHtml(event.details || "-")}</td>
        </tr>
      `;
    })
    .join("");
  el.incidentTimelineBody.innerHTML = rows || '<tr><td colspan="6" class="muted">No timeline events</td></tr>';
}

function renderEscalationStatus(payload) {
  state.incidentEscalation = payload || null;
  if (!payload) {
    el.escalationStatusText.textContent = "No escalation loaded";
    el.escalationStatusBody.innerHTML = '<tr><td colspan="4" class="muted">No escalation events</td></tr>';
    el.startEscalationBtn.disabled = false;
    el.ackEscalationBtn.disabled = true;
    return;
  }

  const status = payload.active
    ? "ACTIVE"
    : payload.acknowledged
      ? "ACKNOWLEDGED"
      : payload.resolved
        ? "RESOLVED"
        : payload.exhausted
          ? "EXHAUSTED"
          : "INACTIVE";
  const startedAt = payload.started_at ? toLocalDateTime(payload.started_at) : "-";
  const resolution = payload.resolution ? ` | Resolution=${payload.resolution}` : "";
  el.escalationStatusText.textContent = `${status} | Started=${startedAt}${resolution}`;

  const steps = Array.isArray(payload.steps) ? payload.steps : [];
  const rows = steps
    .map((step) => {
      const triggered = step.triggered_at ? toLocalDateTime(step.triggered_at) : "Pending";
      const deliveries = Array.isArray(step.deliveries) ? step.deliveries : [];
      const confirmed = deliveries.filter((item) => item.delivery_confirmed).length;
      const failed = deliveries.filter((item) => String(item.delivery_status || "").toUpperCase() === "FAILED").length;
      const unconfigured = deliveries.filter(
        (item) => String(item.delivery_status || "").toUpperCase() === "UNCONFIGURED",
      ).length;
      let deliveryLabel = "Pending";
      if (deliveries.length > 0) {
        const parts = [`${confirmed} confirmed`];
        if (failed > 0) parts.push(`${failed} failed`);
        if (unconfigured > 0) parts.push(`${unconfigured} unconfigured`);
        deliveryLabel = parts.join(" | ");
      }
      return `
        <tr>
          <td>${escapeHtml(step.name || `Step ${Number(step.step_index || 0) + 1}`)}</td>
          <td>${Number(step.delay_seconds || 0)}s</td>
          <td>${escapeHtml(triggered)}</td>
          <td>${escapeHtml(deliveryLabel)}</td>
        </tr>
      `;
    })
    .join("");
  el.escalationStatusBody.innerHTML = rows || '<tr><td colspan="4" class="muted">No escalation steps configured</td></tr>';
  el.startEscalationBtn.disabled = Boolean(payload.active);
  el.ackEscalationBtn.disabled = !Boolean(payload.active);
}

async function loadIncidentEscalationStatus(explicitIncidentId = "") {
  const incidentId = String(explicitIncidentId || "").trim() || getIncidentIdOrThrow();
  const r = await apiFetch(`/api/incidents/${encodeURIComponent(incidentId)}/escalation/status`, {
    cache: "no-store",
  });
  if (!r.ok) {
    throw new Error(await getErrorDetail(r, `escalation status ${r.status}`));
  }
  const payload = await r.json();
  renderEscalationStatus(payload);
}

async function loadIncidentTimeline(explicitIncidentId = "") {
  const incidentId = String(explicitIncidentId || "").trim() || getIncidentIdOrThrow();
  const query = new URLSearchParams({ limit: String(INCIDENT_TIMELINE_LIMIT) });
  const r = await apiFetch(`/api/incidents/${encodeURIComponent(incidentId)}/timeline?${query.toString()}`, {
    cache: "no-store",
  });
  if (!r.ok) {
    throw new Error(await getErrorDetail(r, `incident timeline ${r.status}`));
  }
  const payload = await r.json();
  renderIncidentTimeline(payload);
  if (!el.incidentIdInput.value) {
    el.incidentIdInput.value = incidentId;
  }
  try {
    await loadIncidentEscalationStatus(incidentId);
  } catch (_err) {
    // Timeline can still load if escalation status is unavailable.
  }
}

function exportIncidentPdf() {
  const incidentId = getIncidentIdOrThrow();
  const query = new URLSearchParams({ limit: String(INCIDENT_TIMELINE_LIMIT) });
  window.open(`/api/incidents/${encodeURIComponent(incidentId)}/report.pdf?${query.toString()}`, "_blank");
}

async function addIncidentEvent(event) {
  event.preventDefault();
  const incidentId = getIncidentIdOrThrow();
  const payload = {
    event_type: String(el.incidentEventTypeSelect.value || "").trim(),
    note: String(el.incidentNoteInput.value || "").trim(),
    source: String(el.incidentEventSourceInput.value || "").trim(),
    unit_id: String(el.incidentUnitInput.value || "").trim(),
    officer_id: String(el.incidentOfficerInput.value || "").trim(),
  };
  const etaValue = String(el.incidentEtaInput.value || "").trim();
  if (etaValue) {
    const eta = Number(etaValue);
    if (!Number.isFinite(eta) || eta < 0) {
      throw new Error("ETA minutes must be a non-negative number");
    }
    payload.eta_minutes = Math.floor(eta);
  }

  const r = await apiFetch(`/api/incidents/${encodeURIComponent(incidentId)}/events`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  if (!r.ok) {
    throw new Error(await getErrorDetail(r, `incident event ${r.status}`));
  }
  await r.json();
  addActivity(`Incident event recorded (${payload.event_type}) for ${incidentId}`);
  el.incidentNoteInput.value = "";
  await loadIncidentTimeline(incidentId);
}

async function startIncidentEscalation() {
  const incidentId = getIncidentIdOrThrow();
  const payload = {
    source: String(el.incidentEventSourceInput.value || "").trim(),
    note: String(el.incidentNoteInput.value || "").trim(),
    reason: "MANUAL_START",
  };
  const r = await apiFetch(`/api/incidents/${encodeURIComponent(incidentId)}/escalation/start`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  if (!r.ok) {
    throw new Error(await getErrorDetail(r, `escalation start ${r.status}`));
  }
  const data = await r.json();
  addActivity(`Escalation started for ${incidentId}`);
  if (data && typeof data === "object") {
    renderEscalationStatus(data);
  }
  await loadIncidentTimeline(incidentId);
}

async function acknowledgeIncidentEscalation() {
  const incidentId = getIncidentIdOrThrow();
  const note = window.prompt("Acknowledgement note (optional):", "") || "";
  const r = await apiFetch(`/api/incidents/${encodeURIComponent(incidentId)}/escalation/ack`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ note, resolution: "ACKNOWLEDGED" }),
  });
  if (!r.ok) {
    throw new Error(await getErrorDetail(r, `escalation ack ${r.status}`));
  }
  const data = await r.json();
  addActivity(`Escalation acknowledged for ${incidentId}`);
  if (data && typeof data === "object") {
    renderEscalationStatus(data);
  }
  await loadIncidentTimeline(incidentId);
}

function pad2(value) {
  return String(Math.max(0, Number(value) || 0)).padStart(2, "0");
}

function toDateTimeLocalInputValue(value) {
  const d = value instanceof Date ? value : new Date(value);
  if (Number.isNaN(d.getTime())) return "";
  const year = d.getFullYear();
  const month = pad2(d.getMonth() + 1);
  const day = pad2(d.getDate());
  const hour = pad2(d.getHours());
  const minute = pad2(d.getMinutes());
  return `${year}-${month}-${day}T${hour}:${minute}`;
}

function ensureAnalyticsWindowInputs() {
  const now = new Date();
  if (!String(el.analyticsToInput.value || "").trim()) {
    el.analyticsToInput.value = toDateTimeLocalInputValue(now);
  }
  if (!String(el.analyticsFromInput.value || "").trim()) {
    const from = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);
    el.analyticsFromInput.value = toDateTimeLocalInputValue(from);
  }
}

function parseDateTimeLocalToIso(value, label) {
  const text = String(value || "").trim();
  if (!text) return null;
  const dt = new Date(text);
  if (Number.isNaN(dt.getTime())) {
    throw new Error(`Invalid ${label} date/time`);
  }
  return dt.toISOString();
}

function parseHourFilter(value, label) {
  const raw = String(value || "").trim();
  if (!raw) return null;
  const parsed = Number(raw);
  if (!Number.isInteger(parsed) || parsed < 0 || parsed > 23) {
    throw new Error(`${label} must be an integer between 0 and 23`);
  }
  return parsed;
}

function analyticsBaseQuery() {
  ensureAnalyticsWindowInputs();
  const fromTs = parseDateTimeLocalToIso(el.analyticsFromInput.value, "from");
  const toTs = parseDateTimeLocalToIso(el.analyticsToInput.value, "to");
  const query = new URLSearchParams();
  if (fromTs) query.set("from_ts", fromTs);
  if (toTs) query.set("to_ts", toTs);
  if (!fromTs && !toTs) query.set("days", "30");
  return query;
}

function analyticsZoneFilter() {
  return String(el.analyticsZoneInput.value || "").trim();
}

function renderShiftAnalytics(rows) {
  const items = Array.isArray(rows) ? rows : [];
  const html = items
    .map((row) => {
      const name = escapeHtml(row.name || "-");
      const windowLabel = `${escapeHtml(row.start || "-")} -> ${escapeHtml(row.end || "-")}`;
      const count = Number(row.count || 0);
      const percent = Number(row.percent || 0).toFixed(2);
      return `
        <tr>
          <td>${name}</td>
          <td><span class="mono">${windowLabel}</span></td>
          <td>${count}</td>
          <td>${percent}%</td>
        </tr>
      `;
    })
    .join("");
  el.shiftAnalyticsBody.innerHTML = html || '<tr><td colspan="4" class="muted">No incidents in selected window</td></tr>';
}

function renderOperatorAnalytics(rows) {
  const items = Array.isArray(rows) ? rows : [];
  const html = items
    .map((row) => {
      const operatorId = escapeHtml(row.operator_id || "unknown");
      const handled = Number(row.handled || 0);
      const avg = Number(row.avg_response_seconds || 0).toFixed(2);
      const p50 = Number(row.p50_response_seconds || 0).toFixed(2);
      const minSec = Number(row.min_response_seconds || 0).toFixed(2);
      const maxSec = Number(row.max_response_seconds || 0).toFixed(2);
      const ack = Number(row.acknowledged || 0);
      const esc = Number(row.escalated || 0);
      const dismiss = Number(row.dismissed || 0);
      return `
        <tr>
          <td><span class="mono">${operatorId}</span></td>
          <td>${handled}</td>
          <td>${avg}</td>
          <td>${p50}</td>
          <td>${minSec} / ${maxSec}</td>
          <td>${ack} / ${esc} / ${dismiss}</td>
        </tr>
      `;
    })
    .join("");
  el.operatorAnalyticsBody.innerHTML =
    html || '<tr><td colspan="6" class="muted">No operator actions in selected window</td></tr>';
}

function renderZoneRisk(rows) {
  const items = Array.isArray(rows) ? rows : [];
  const html = items
    .map((row) => {
      const zoneKey = escapeHtml(row.zone_key || "zone:unknown");
      const count = Number(row.count || 0);
      return `
        <tr>
          <td><span class="mono">${zoneKey}</span></td>
          <td>${count}</td>
        </tr>
      `;
    })
    .join("");
  el.zoneRiskBody.innerHTML = html || '<tr><td colspan="2" class="muted">No zone incidents in selected window</td></tr>';
}

function renderAnalyticsOverview(payload) {
  state.analyticsOverview = payload || null;
  if (!payload) {
    el.analyticsSummaryText.textContent = "Load analytics window";
    renderShiftAnalytics([]);
    renderOperatorAnalytics([]);
    renderZoneRisk([]);
    return;
  }

  const summary = payload.summary || {};
  const windowInfo = payload.window || {};
  const fromLabel = toLocalDateTime(windowInfo.from);
  const toLabel = toLocalDateTime(windowInfo.to);
  el.analyticsSummaryText.textContent =
    `Window ${fromLabel} -> ${toLabel} | Incidents=${summary.total_incidents ?? 0} | ` +
    `Operators=${summary.operators_with_actions ?? 0} | Zones=${summary.zones_in_scope ?? 0}`;

  renderShiftAnalytics(payload.incidents_by_shift);
  renderOperatorAnalytics(payload.operator_response);
  renderZoneRisk(payload.zone_risk);
}

function heatmapCellStyle(count, maxCount) {
  const safeCount = Number(count || 0);
  const safeMax = Number(maxCount || 0);
  if (safeCount <= 0 || safeMax <= 0) {
    return "background: rgba(16, 36, 50, 0.55); color: #7f9caf;";
  }
  const ratio = Math.max(0, Math.min(1, safeCount / safeMax));
  const alpha = (0.12 + ratio * 0.78).toFixed(3);
  const text = ratio > 0.55 ? "#02121b" : "#dff4ff";
  const weight = ratio > 0.7 ? 700 : 500;
  return `background: rgba(63, 210, 255, ${alpha}); color: ${text}; font-weight: ${weight};`;
}

function renderSingleZoneHeatmap(zonePayload, daysOfWeek, hours) {
  const matrix = Array.isArray(zonePayload?.matrix) ? zonePayload.matrix : [];
  const maxCount = Number(zonePayload?.max_count || 0);
  const peak = zonePayload?.peak || {};
  const headerCells = (Array.isArray(hours) ? hours : Array.from({ length: 24 }, (_, idx) => idx))
    .map((hour) => `<th>${pad2(hour)}</th>`)
    .join("");

  const bodyRows = (Array.isArray(daysOfWeek) ? daysOfWeek : []).map((dayLabel, dayIndex) => {
    const row = Array.isArray(matrix[dayIndex]) ? matrix[dayIndex] : [];
    const cells = Array.from({ length: 24 }, (_, hour) => {
      const count = Number(row[hour] || 0);
      return `<td style="${heatmapCellStyle(count, maxCount)}">${count}</td>`;
    }).join("");
    return `<tr><th class="heatmap-day">${escapeHtml(dayLabel)}</th>${cells}</tr>`;
  });

  return `
    <div class="heatmap-zone-block">
      <div class="service-meta">Zone <span class="mono">${escapeHtml(zonePayload.zone_key || "zone:unknown")}</span> | Total ${Number(
    zonePayload.total || 0,
  )} | Peak ${escapeHtml(peak.day || "-")} ${pad2(peak.hour ?? 0)}:00 (${Number(peak.count || 0)})</div>
      <table class="heatmap-table">
        <thead>
          <tr>
            <th>Day</th>
            ${headerCells}
          </tr>
        </thead>
        <tbody>
          ${bodyRows.join("")}
        </tbody>
      </table>
    </div>
  `;
}

function renderHeatmapGridFromState() {
  const payload = state.analyticsHeatmap;
  if (!payload) {
    el.heatmapGrid.innerHTML = '<p class="muted">Load analytics heatmap</p>';
    return;
  }

  const daysOfWeek = Array.isArray(payload.days_of_week) ? payload.days_of_week : [];
  const hours = Array.isArray(payload.hours) ? payload.hours : Array.from({ length: 24 }, (_, idx) => idx);
  const zones = Array.isArray(payload.zones) ? payload.zones : [];
  if (zones.length === 0) {
    el.heatmapGrid.innerHTML = '<p class="muted">No heatmap data in selected window</p>';
    return;
  }

  const selected = String(el.heatmapZoneSelect.value || "__all__");
  let blocks = [];
  if (selected === "__all__") {
    blocks = zones.map((zone) => renderSingleZoneHeatmap(zone, daysOfWeek, hours));
  } else {
    const zone = zones.find((item) => String(item.zone_key) === selected);
    if (!zone) {
      el.heatmapGrid.innerHTML = '<p class="muted">Selected zone has no heatmap data</p>';
      return;
    }
    blocks = [renderSingleZoneHeatmap(zone, daysOfWeek, hours)];
  }
  el.heatmapGrid.innerHTML = blocks.join('<div style="height:10px"></div>');
}

function renderHeatmapZoneOptions(payload, preferredZone = "") {
  const zones = Array.isArray(payload?.zones) ? payload.zones : [];
  const zoneKeys = zones.map((item) => String(item.zone_key || "")).filter(Boolean);
  const existing = String(el.heatmapZoneSelect.value || "");
  const preferred = String(preferredZone || "").trim();
  const options = ['<option value="__all__">All Zones</option>'];
  for (const zoneKey of zoneKeys) {
    options.push(`<option value="${escapeHtml(zoneKey)}">${escapeHtml(zoneKey)}</option>`);
  }
  el.heatmapZoneSelect.innerHTML = options.join("");

  if (preferred && zoneKeys.includes(preferred)) {
    el.heatmapZoneSelect.value = preferred;
  } else if (existing && zoneKeys.includes(existing)) {
    el.heatmapZoneSelect.value = existing;
  } else {
    el.heatmapZoneSelect.value = "__all__";
  }
}

async function loadAnalyticsHeatmap(preferredZone = "") {
  const query = analyticsBaseQuery();
  const r = await apiFetch(`/api/analytics/heatmap?${query.toString()}`, { cache: "no-store" });
  if (!r.ok) {
    throw new Error(await getErrorDetail(r, `heatmap ${r.status}`));
  }
  const payload = await r.json();
  state.analyticsHeatmap = payload;
  renderHeatmapZoneOptions(payload, preferredZone);
  renderHeatmapGridFromState();
}

function renderShiftWindowRows(windows) {
  const items = Array.isArray(windows) ? windows : [];
  const editable = state.role === "admin";
  const html = items
    .map((windowItem, idx) => {
      const name = escapeHtml(windowItem.name || "");
      const start = escapeHtml(windowItem.start || "00:00");
      const end = escapeHtml(windowItem.end || "00:00");
      return `
        <tr data-shift-row="${idx}">
          <td><input data-shift-field="name" class="analytics-input" type="text" value="${name}" ${
  editable ? "" : "disabled"
} /></td>
          <td><input data-shift-field="start" class="analytics-input small mono" type="text" value="${start}" ${
  editable ? "" : "disabled"
} placeholder="HH:MM" /></td>
          <td><input data-shift-field="end" class="analytics-input small mono" type="text" value="${end}" ${
  editable ? "" : "disabled"
} placeholder="HH:MM" /></td>
        </tr>
      `;
    })
    .join("");
  el.shiftWindowBody.innerHTML = html || '<tr><td colspan="3" class="muted">No shift windows configured</td></tr>';
}

async function loadShiftWindows() {
  const r = await apiFetch("/api/analytics/shift-windows", { cache: "no-store" });
  if (!r.ok) {
    throw new Error(await getErrorDetail(r, `shift windows ${r.status}`));
  }
  const payload = await r.json();
  renderShiftWindowRows(payload.windows || []);
}

function isValidHHMM(value) {
  return /^([01]\d|2[0-3]):([0-5]\d)$/.test(String(value || "").trim());
}

function collectShiftWindowInputs() {
  const rows = Array.from(el.shiftWindowBody.querySelectorAll("tr[data-shift-row]"));
  if (rows.length === 0) {
    throw new Error("At least one shift window is required");
  }

  const windows = [];
  const seenNames = new Set();
  for (const row of rows) {
    const nameInput = row.querySelector('[data-shift-field="name"]');
    const startInput = row.querySelector('[data-shift-field="start"]');
    const endInput = row.querySelector('[data-shift-field="end"]');
    const name = String(nameInput?.value || "").trim();
    const start = String(startInput?.value || "").trim();
    const end = String(endInput?.value || "").trim();

    if (!name) {
      throw new Error("Each shift needs a name");
    }
    const normalizedName = name.toLowerCase();
    if (seenNames.has(normalizedName)) {
      throw new Error(`Duplicate shift name: ${name}`);
    }
    if (!isValidHHMM(start)) {
      throw new Error(`Invalid start time for ${name}. Use HH:MM`);
    }
    if (!isValidHHMM(end)) {
      throw new Error(`Invalid end time for ${name}. Use HH:MM`);
    }
    seenNames.add(normalizedName);
    windows.push({ name, start, end });
  }
  return windows;
}

async function saveShiftWindows() {
  if (state.role !== "admin") {
    throw new Error("Admin access required");
  }
  const windows = collectShiftWindowInputs();
  const r = await apiFetch("/api/analytics/shift-windows", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ windows }),
  });
  if (!r.ok) {
    throw new Error(await getErrorDetail(r, `save shift windows ${r.status}`));
  }
  const payload = await r.json();
  renderShiftWindowRows(payload.windows || []);
  addActivity("Shift windows updated");
}

async function loadAnalyticsOverview() {
  const query = analyticsBaseQuery();
  const zone = analyticsZoneFilter();
  const hourStart = parseHourFilter(el.analyticsHourStartInput.value, "Hour start");
  const hourEnd = parseHourFilter(el.analyticsHourEndInput.value, "Hour end");
  if (zone) query.set("zone_key", zone);
  if (hourStart !== null) query.set("hour_start", String(hourStart));
  if (hourEnd !== null) query.set("hour_end", String(hourEnd));

  const r = await apiFetch(`/api/analytics/overview?${query.toString()}`, { cache: "no-store" });
  if (!r.ok) {
    throw new Error(await getErrorDetail(r, `analytics overview ${r.status}`));
  }
  const payload = await r.json();
  renderAnalyticsOverview(payload);
}

async function loadAnalyticsBundle() {
  const preferredZone = analyticsZoneFilter();
  await loadAnalyticsOverview();
  await loadAnalyticsHeatmap(preferredZone);
  if (!el.shiftWindowBody.querySelector("tr[data-shift-row]")) {
    await loadShiftWindows();
  }
}

async function createAlertDisposition(alertId, disposition) {
  const safeAlertId = String(alertId || "").trim();
  if (!safeAlertId) {
    throw new Error("Missing alert id");
  }
  const safeDisposition = String(disposition || "").trim().toLowerCase();
  if (!safeDisposition) {
    throw new Error("Missing disposition");
  }

  const note = window.prompt(`Optional note for ${safeDisposition}:`, "") || "";
  const r = await apiFetch(`/api/alerts/${encodeURIComponent(safeAlertId)}/disposition`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ disposition: safeDisposition, note }),
  });
  if (!r.ok) {
    throw new Error(await getErrorDetail(r, `disposition ${r.status}`));
  }
  const payload = await r.json();
  addActivity(`Alert ${safeAlertId} marked ${safeDisposition} by ${state.username || "operator"}`);
  if (payload?.learning?.auto_tuned) {
    const policy = payload.learning.policy || {};
    addActivity(
      `Auto-learn tuned ${policy.zone_key || "zone"} hour ${policy.hour_of_day ?? "-"} to threshold ${
        policy.adaptive_threshold ?? "-"
      }`,
    );
  }
  if (payload?.learning?.auto_snoozed) {
    const policy = payload.learning.policy || {};
    addActivity(`Zone snoozed until ${toLocalTime(policy.snooze_until || "-")}`);
  }
  if (state.role === "admin") {
    await fetchZonePolicy(true).catch(() => {});
  }
  await fetchAlertHistory();
}

function onAlertDispositionClick(event) {
  const target = event.target;
  if (!(target instanceof HTMLElement)) return;
  const button = target.closest("button[data-alert-id][data-disposition]");
  if (!button) return;

  const alertId = button.getAttribute("data-alert-id") || "";
  const disposition = button.getAttribute("data-disposition") || "";
  button.disabled = true;
  createAlertDisposition(alertId, disposition)
    .catch((err) => {
      const msg = err instanceof Error ? err.message : "unknown error";
      addActivity(`Disposition update failed (${msg})`);
    })
    .finally(() => {
      button.disabled = false;
    });
}

function connectFrameSocket() {
  if (state.frameReconnectTimer) {
    clearTimeout(state.frameReconnectTimer);
    state.frameReconnectTimer = null;
  }
  if (state.frameSocket) {
    state.frameSocket.close();
  }

  const socket = new WebSocket(`${wsBase()}/ws/stream`);
  state.frameSocket = socket;

  socket.onopen = () => {
    setConnected(true);
    addActivity("Frame socket connected");
  };

  socket.onmessage = (event) => {
    try {
      const payload = JSON.parse(event.data);
      if (!payload.frame) return;

      const width = Number(payload.width || 0);
      const height = Number(payload.height || 0);
      if (width > 0 && height > 0) {
        state.frameWidth = width;
        state.frameHeight = height;
      }

      el.feedImage.src = `data:image/jpeg;base64,${payload.frame}`;
      el.frameMeta.textContent = `frame=${payload.frame_id ?? "-"} fps=${payload.fps ?? "-"} ts=${toLocalTime(payload.timestamp)}`;
      drawOverlay();
    } catch (err) {
      addActivity("Frame payload parse error");
    }
  };

  socket.onclose = (event) => {
    if (state.frameSocket !== socket) return;
    state.frameSocket = null;
    setConnected(false);
    if (event.code === 1008) {
      redirectToLogin();
      return;
    }
    addActivity("Frame socket closed");
    state.frameReconnectTimer = setTimeout(connectFrameSocket, 1500);
  };

  socket.onerror = () => {
    addActivity("Frame socket error");
    socket.close();
  };
}

function connectDetectionSocket() {
  if (state.detectionReconnectTimer) {
    clearTimeout(state.detectionReconnectTimer);
    state.detectionReconnectTimer = null;
  }
  if (state.detectionSocket) {
    state.detectionSocket.close();
  }
  const socket = new WebSocket(`${wsBase()}/ws/detections`);
  state.detectionSocket = socket;

  socket.onopen = () => {
    addActivity("Detection socket connected");
  };

  socket.onmessage = (event) => {
    try {
      const packet = JSON.parse(event.data);
      pushDetection(packet);
      if (packet.severity?.level === "HIGH") {
        addActivity(`HIGH alert context detected (${packet.severity.weapon || "unknown"})`);
      }
    } catch (err) {
      addActivity("Detection payload parse error");
    }
  };

  socket.onclose = (event) => {
    if (state.detectionSocket !== socket) return;
    if (event.code === 1008) {
      redirectToLogin();
      return;
    }
    addActivity("Detection socket closed");
    state.detectionReconnectTimer = setTimeout(connectDetectionSocket, 1500);
  };

  socket.onerror = () => {
    addActivity("Detection socket error");
    socket.close();
  };
}

async function fetchStatus() {
  try {
    const r = await apiFetch("/api/status", { cache: "no-store" });
    if (!r.ok) throw new Error(`status ${r.status}`);
    const data = await r.json();
    state.liveCameraActive = String(data.source || "").startsWith("camera:");
    state.currentSource = String(data.source || "");
    setLiveCameraButton();
    el.statusSource.textContent = data.source || "-";
    el.statusFps.textContent = String(data.fps ?? 0);
    const width = data.resolution?.width ?? 0;
    const height = data.resolution?.height ?? 0;
    el.statusResolution.textContent = `${width}x${height}`;
    if (width > 0 && height > 0) {
      state.frameWidth = Number(width);
      state.frameHeight = Number(height);
      drawOverlay();
    }
    el.statusAction.textContent = data.action_enabled ? "Enabled" : "Disabled";
    fetchZonePolicy(false).catch(() => {
      // Avoid noisy status-loop errors in activity log.
    });
  } catch (err) {
    addActivity("Status polling failed");
  }
}

async function fetchAlertHistory() {
  try {
    const r = await apiFetch("/api/alerts/history?limit=120", { cache: "no-store" });
    if (!r.ok) throw new Error(`alerts ${r.status}`);
    const data = await r.json();
    state.alerts = Array.isArray(data.alerts) ? data.alerts.slice().reverse() : [];
    renderAlerts();
    if (!String(el.incidentIdInput.value || "").trim()) {
      const guess = defaultIncidentId();
      if (guess) el.incidentIdInput.value = guess;
    }
  } catch (err) {
    addActivity("Alert history refresh failed");
  }
}

async function fetchDetectionHistory() {
  try {
    const r = await apiFetch("/api/detections/history?limit=120", { cache: "no-store" });
    if (!r.ok) throw new Error(`detections ${r.status}`);
    const data = await r.json();
    const records = Array.isArray(data.detections) ? data.detections : [];
    state.detections = records
      .slice()
      .reverse()
      .map((packet) => {
        const first = Array.isArray(packet.detections) && packet.detections.length > 0 ? packet.detections[0] : {};
        return {
          time: packet.timestamp,
          weapon: first.label || "-",
          threatId: first?.reid?.threat_id || "-",
          confidence: Number(first.confidence || 0),
          severity: packet.severity?.level || "LOW",
          action: packet.action?.label || "unknown",
        };
      });

    state.counts = { HIGH: 0, MEDIUM: 0, LOW: 0 };
    for (const row of state.detections) {
      const sev = row.severity.toUpperCase();
      if (state.counts[sev] !== undefined) {
        state.counts[sev] += 1;
      }
    }
    updateSeverityCounters();
    renderDetections();
    if (!String(el.incidentIdInput.value || "").trim()) {
      const guess = defaultIncidentId();
      if (guess) el.incidentIdInput.value = guess;
    }
  } catch (err) {
    addActivity("Detection history refresh failed");
  }
}

async function clearDetections() {
  const r = await apiFetch("/api/detections/history", { method: "DELETE" });
  if (!r.ok) {
    throw new Error(await getErrorDetail(r, `clear detections ${r.status}`));
  }
  state.detections = [];
  state.counts = { HIGH: 0, MEDIUM: 0, LOW: 0 };
  state.overlayDetections = [];
  state.overlaySeenAt = 0;
  clearOverlay();
  updateSeverityCounters();
  renderDetections();
  addActivity("Detections cleared");
}

async function clearAlerts() {
  const r = await apiFetch("/api/alerts/history", { method: "DELETE" });
  if (!r.ok) {
    throw new Error(await getErrorDetail(r, `clear alerts ${r.status}`));
  }
  state.alerts = [];
  renderAlerts();
  addActivity("Alerts cleared");
}

async function openLiveCamera() {
  try {
    const r = await apiFetch("/api/camera/open?index=0", { method: "POST" });
    if (!r.ok) {
      let reason = `camera ${r.status}`;
      try {
        const body = await r.json();
        if (body?.detail) reason = String(body.detail);
      } catch (_err) {
        // Ignore parse failure.
      }
      throw new Error(reason);
    }
    const data = await r.json();
    await fetchStatus();
    state.liveCameraActive = String(data.status?.source || "").startsWith("camera:");
    setLiveCameraButton();
    if (data.fallback || !state.liveCameraActive) {
      addActivity(data.message || "Live camera unavailable; switched to default video");
      el.frameMeta.textContent = "Live camera unavailable. Showing default video.";
    } else {
      addActivity(`Live camera opened (${data.status?.source || "camera:0"})`);
    }
  } catch (err) {
    const msg = err instanceof Error ? err.message : "unknown error";
    addActivity(`Open live camera failed (${msg})`);
    try {
      await closeLiveCamera();
      el.frameMeta.textContent = "Live camera unavailable. Showing default video.";
    } catch (_fallbackErr) {
      el.frameMeta.textContent = "Failed to open live camera";
    }
    state.liveCameraActive = false;
    setLiveCameraButton();
    await fetchStatus();
  }
}

async function closeLiveCamera() {
  try {
    const r = await apiFetch("/api/camera/close", { method: "POST" });
    if (!r.ok) {
      let reason = `video ${r.status}`;
      try {
        const body = await r.json();
        if (body?.detail) reason = String(body.detail);
      } catch (_err) {
        // Ignore parse failure.
      }
      throw new Error(reason);
    }
    const data = await r.json();
    state.liveCameraActive = false;
    setLiveCameraButton();
    await fetchStatus();
    addActivity(data.message || "Switched to default video");
  } catch (err) {
    const msg = err instanceof Error ? err.message : "unknown error";
    addActivity(`Switch to default video failed (${msg})`);
    await fetchStatus();
  }
}

async function toggleLiveCamera() {
  if (state.liveCameraActive) {
    el.frameMeta.textContent = "Switching to normal video...";
    await closeLiveCamera();
    return;
  }

  el.frameMeta.textContent = "Connecting to live camera...";
  await openLiveCamera();
}

function reconnectAll() {
  addActivity("Manual reconnect triggered");
  connectFrameSocket();
  connectDetectionSocket();
}

function setMapStatus(text, isError = false) {
  el.mapStatus.textContent = text;
  el.mapStatus.classList.toggle("status-error", isError);
}

function setActiveTab(tabName) {
  state.activeTab = tabName;
  const monitorActive = tabName === "monitor";
  const mapActive = tabName === "map";
  const incidentActive = tabName === "incident";
  const analyticsActive = tabName === "analytics";
  el.monitorTab.hidden = !monitorActive;
  el.mapTab.hidden = !mapActive;
  el.incidentTab.hidden = !incidentActive;
  el.analyticsTab.hidden = !analyticsActive;
  el.tabMonitorBtn.classList.toggle("tab-active", monitorActive);
  el.tabMapBtn.classList.toggle("tab-active", mapActive);
  el.tabIncidentBtn.classList.toggle("tab-active", incidentActive);
  el.tabAnalyticsBtn.classList.toggle("tab-active", analyticsActive);

  if (mapActive) {
    if (ensureMapInitialized()) {
      setTimeout(() => {
        if (state.map) {
          state.map.invalidateSize();
        }
      }, 120);
    }
  }
}

function getSelectedRadiusKm() {
  const parsed = Number(el.mapRadiusSelect.value || state.mapRadiusKm);
  if (MAP_ALLOWED_RADII.has(parsed)) {
    return parsed;
  }
  return 5;
}

function formatLatLon(lat, lon) {
  return `${Number(lat).toFixed(6)}, ${Number(lon).toFixed(6)}`;
}

function ensureMapInitialized() {
  if (state.mapInitialized) {
    return true;
  }
  if (!window.L) {
    setMapStatus("Leaflet map library failed to load", true);
    return false;
  }

  const L = window.L;
  state.map = L.map(el.mapView, { zoomControl: true, preferCanvas: true }).setView([20.5937, 78.9629], 5);
  L.tileLayer("https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png", {
    attribution: "&copy; OpenStreetMap contributors",
    maxZoom: 19,
  }).addTo(state.map);

  state.mapLayers = {
    camera: L.layerGroup().addTo(state.map),
    radius: L.layerGroup().addTo(state.map),
    hospitals: L.layerGroup().addTo(state.map),
    police: L.layerGroup().addTo(state.map),
    fire: L.layerGroup().addTo(state.map),
  };
  state.mapInitialized = true;
  return true;
}

function renderServiceList(listElement, places, emptyLabel) {
  if (!Array.isArray(places) || places.length === 0) {
    listElement.innerHTML = `<li class="service-empty">${escapeHtml(emptyLabel)}</li>`;
    return;
  }

  listElement.innerHTML = places
    .slice(0, 30)
    .map((place) => {
      const name = escapeHtml(place.name || "Unknown");
      const distance = Number(place.distance_km || 0).toFixed(2);
      const location = place.address ? escapeHtml(place.address) : formatLatLon(place.lat, place.lon);
      return `
        <li>
          <span class="service-name">${name}</span>
          <span class="service-meta mono">${distance} km</span>
          <span class="service-meta">${location}</span>
        </li>
      `;
    })
    .join("");
}

function setCameraLocation(lat, lon, sourceLabel) {
  const parsedLat = Number(lat);
  const parsedLon = Number(lon);
  if (!Number.isFinite(parsedLat) || !Number.isFinite(parsedLon)) {
    return;
  }
  state.cameraLocation = { lat: parsedLat, lon: parsedLon };
  el.cameraLatInput.value = parsedLat.toFixed(6);
  el.cameraLonInput.value = parsedLon.toFixed(6);
  el.cameraLocationText.textContent = `Camera location: ${formatLatLon(parsedLat, parsedLon)} (${sourceLabel})`;
}

function updateCameraAndRadiusOverlay() {
  if (!state.mapInitialized || !state.cameraLocation) {
    return;
  }
  const L = window.L;
  const { lat, lon } = state.cameraLocation;
  const radiusKm = state.mapRadiusKm;

  state.mapLayers.camera.clearLayers();
  state.mapLayers.radius.clearLayers();

  const marker = L.marker([lat, lon], { title: "Camera Location" });
  marker.bindPopup(`<strong>Camera</strong><br>${escapeHtml(formatLatLon(lat, lon))}`);
  marker.addTo(state.mapLayers.camera);

  L.circle([lat, lon], {
    radius: radiusKm * 1000,
    color: "#3fd2ff",
    weight: 2,
    fillColor: "#3fd2ff",
    fillOpacity: 0.08,
  }).addTo(state.mapLayers.radius);
}

function addServiceMarkers(places, layerGroup, color, label) {
  if (!state.mapInitialized) return;
  const L = window.L;
  layerGroup.clearLayers();
  for (const place of places) {
    if (!Number.isFinite(Number(place.lat)) || !Number.isFinite(Number(place.lon))) continue;
    const marker = L.circleMarker([Number(place.lat), Number(place.lon)], {
      radius: 6,
      color,
      fillColor: color,
      fillOpacity: 0.9,
      weight: 2,
    });
    const popup = `
      <strong>${escapeHtml(label)}</strong><br>
      ${escapeHtml(place.name || "Unknown")}<br>
      Distance: ${Number(place.distance_km || 0).toFixed(2)} km
    `;
    marker.bindPopup(popup);
    marker.addTo(layerGroup);
  }
}

function renderNearbyPlaces(payload) {
  const hospitals = Array.isArray(payload.hospitals) ? payload.hospitals : [];
  const police = Array.isArray(payload.police_stations) ? payload.police_stations : [];
  const fire = Array.isArray(payload.fire_stations) ? payload.fire_stations : [];
  const total = Number(payload.total || hospitals.length + police.length + fire.length);

  el.hospitalCount.textContent = String(hospitals.length);
  el.policeCount.textContent = String(police.length);
  el.fireCount.textContent = String(fire.length);
  el.mapTotalCount.textContent = `${total} places`;

  renderServiceList(el.hospitalList, hospitals, "No hospitals found in selected radius");
  renderServiceList(el.policeList, police, "No police stations found in selected radius");
  renderServiceList(el.fireList, fire, "No fire stations found in selected radius");

  if (!ensureMapInitialized() || !state.cameraLocation) {
    return;
  }

  updateCameraAndRadiusOverlay();
  addServiceMarkers(hospitals, state.mapLayers.hospitals, "#4faeff", "Hospital");
  addServiceMarkers(police, state.mapLayers.police, "#ffd264", "Police Station");
  addServiceMarkers(fire, state.mapLayers.fire, "#ff7e66", "Fire Station");

  const bounds = [];
  bounds.push([state.cameraLocation.lat, state.cameraLocation.lon]);
  for (const p of hospitals) bounds.push([Number(p.lat), Number(p.lon)]);
  for (const p of police) bounds.push([Number(p.lat), Number(p.lon)]);
  for (const p of fire) bounds.push([Number(p.lat), Number(p.lon)]);
  if (bounds.length > 1) {
    state.map.fitBounds(bounds, { padding: [26, 26] });
  } else {
    state.map.setView([state.cameraLocation.lat, state.cameraLocation.lon], 13);
  }
}

async function fetchNearbyServices() {
  if (state.mapLoading) return;
  if (!state.cameraLocation) {
    setMapStatus("Set camera location to load nearby services", true);
    return;
  }

  state.mapRadiusKm = getSelectedRadiusKm();
  updateCameraAndRadiusOverlay();
  setMapStatus(`Loading hospitals, police, and fire stations within ${state.mapRadiusKm} km...`);
  state.mapLoading = true;

  try {
    const query = new URLSearchParams({
      lat: String(state.cameraLocation.lat),
      lon: String(state.cameraLocation.lon),
      radius_km: String(state.mapRadiusKm),
    });
    const r = await apiFetch(`/api/map/nearby?${query.toString()}`, { cache: "no-store" });
    if (!r.ok) {
      let reason = `status ${r.status}`;
      try {
        const body = await r.json();
        if (body?.detail) reason = String(body.detail);
      } catch (_err) {
        // Ignore parse failure.
      }
      throw new Error(reason);
    }
    const payload = await r.json();
    renderNearbyPlaces(payload);
    setMapStatus(
      `Updated ${toLocalTime(payload.timestamp)} | ${payload.total ?? 0} services within ${payload.radius_km ?? state.mapRadiusKm} km`,
    );
  } catch (err) {
    const msg = err instanceof Error ? err.message : "unknown error";
    setMapStatus(`Map lookup failed: ${msg}`, true);
    addActivity(`Map lookup failed (${msg})`);
  } finally {
    state.mapLoading = false;
  }
}

function readManualCoordinates() {
  const lat = Number(el.cameraLatInput.value);
  const lon = Number(el.cameraLonInput.value);
  if (!Number.isFinite(lat) || !Number.isFinite(lon)) {
    throw new Error("Enter valid numeric latitude and longitude");
  }
  if (lat < -90 || lat > 90) {
    throw new Error("Latitude must be between -90 and 90");
  }
  if (lon < -180 || lon > 180) {
    throw new Error("Longitude must be between -180 and 180");
  }
  return { lat, lon };
}

function getCurrentPosition() {
  return new Promise((resolve, reject) => {
    if (!navigator.geolocation) {
      reject(new Error("Geolocation not available in this browser"));
      return;
    }

    navigator.geolocation.getCurrentPosition(
      (position) => {
        resolve({
          lat: Number(position.coords.latitude),
          lon: Number(position.coords.longitude),
        });
      },
      (error) => reject(new Error(error.message || "Unable to get current location")),
      {
        enableHighAccuracy: true,
        timeout: 12000,
        maximumAge: 30000,
      },
    );
  });
}

async function useCurrentLocation() {
  setMapStatus("Fetching current camera location...");
  try {
    const loc = await getCurrentPosition();
    setCameraLocation(loc.lat, loc.lon, "browser geolocation");
    if (ensureMapInitialized()) {
      updateCameraAndRadiusOverlay();
      state.map.setView([loc.lat, loc.lon], 13);
    }
    await fetchNearbyServices();
    addActivity(`Camera location set to ${formatLatLon(loc.lat, loc.lon)}`);
  } catch (err) {
    const msg = err instanceof Error ? err.message : "unable to get location";
    setMapStatus(msg, true);
    addActivity(`Location fetch failed (${msg})`);
  }
}

async function applyManualCoordinates() {
  try {
    const loc = readManualCoordinates();
    setCameraLocation(loc.lat, loc.lon, "manual");
    if (ensureMapInitialized()) {
      updateCameraAndRadiusOverlay();
      state.map.setView([loc.lat, loc.lon], 13);
    }
    await fetchNearbyServices();
    addActivity(`Manual camera location set to ${formatLatLon(loc.lat, loc.lon)}`);
  } catch (err) {
    const msg = err instanceof Error ? err.message : "invalid coordinates";
    setMapStatus(msg, true);
  }
}

function initializeMapSidebar() {
  el.hospitalCount.textContent = "0";
  el.policeCount.textContent = "0";
  el.fireCount.textContent = "0";
  el.mapTotalCount.textContent = "0 places";
  renderServiceList(el.hospitalList, [], "No hospitals loaded");
  renderServiceList(el.policeList, [], "No police stations loaded");
  renderServiceList(el.fireList, [], "No fire stations loaded");
  setMapStatus("Set camera location to load map");
  el.cameraLocationText.textContent = "Camera location: -";
}

async function init() {
  try {
    await loadAuthContext();
  } catch (_err) {
    redirectToLogin();
    return;
  }

  renderDetections();
  renderAlerts();
  updateSeverityCounters();
  setLiveCameraButton();
  applyRolePermissions();
  el.frameMeta.textContent = "Waiting for frames...";
  el.zonePolicyMeta.textContent = "Zone: - | Hour: -";
  el.zonePolicyCurrent.textContent = state.role === "admin" ? "Threshold: loading..." : "Threshold: admin-only view";
  renderIncidentTimeline(null);
  renderEscalationStatus(null);
  renderAnalyticsOverview(null);
  renderHeatmapGridFromState();
  ensureAnalyticsWindowInputs();
  loadShiftWindows().catch(() => {
    el.shiftWindowBody.innerHTML = '<tr><td colspan="3" class="muted">Unable to load shift windows</td></tr>';
  });
  clearOverlay();
  initializeMapSidebar();

  el.logoutBtn.addEventListener("click", () => {
    logout().catch(() => redirectToLogin());
  });
  el.liveCameraBtn.addEventListener("click", () => {
    toggleLiveCamera().catch(() => addActivity("Camera toggle failed"));
  });
  el.reconnectBtn.addEventListener("click", reconnectAll);
  el.clearDetectionsBtn.addEventListener("click", () => {
    clearDetections().catch((err) => {
      const msg = err instanceof Error ? err.message : "unknown error";
      addActivity(`Clear detections failed (${msg})`);
    });
  });
  el.clearAlertsBtn.addEventListener("click", () => {
    clearAlerts().catch((err) => {
      const msg = err instanceof Error ? err.message : "unknown error";
      addActivity(`Clear alerts failed (${msg})`);
    });
  });
  el.zonePolicyApplyBtn.addEventListener("click", () => {
    applyZonePolicy().catch((err) => {
      const msg = err instanceof Error ? err.message : "unknown error";
      addActivity(`Zone policy update failed (${msg})`);
    });
  });
  el.alertsBody.addEventListener("click", onAlertDispositionClick);
  el.loadIncidentBtn.addEventListener("click", () => {
    loadIncidentTimeline().catch((err) => {
      const msg = err instanceof Error ? err.message : "unknown error";
      addActivity(`Incident timeline load failed (${msg})`);
    });
  });
  el.exportIncidentPdfBtn.addEventListener("click", () => {
    try {
      exportIncidentPdf();
    } catch (err) {
      const msg = err instanceof Error ? err.message : "unknown error";
      addActivity(`Incident PDF export failed (${msg})`);
    }
  });
  el.incidentEventForm.addEventListener("submit", (event) => {
    addIncidentEvent(event).catch((err) => {
      const msg = err instanceof Error ? err.message : "unknown error";
      addActivity(`Incident event add failed (${msg})`);
    });
  });
  el.startEscalationBtn.addEventListener("click", () => {
    startIncidentEscalation().catch((err) => {
      const msg = err instanceof Error ? err.message : "unknown error";
      addActivity(`Escalation start failed (${msg})`);
    });
  });
  el.ackEscalationBtn.addEventListener("click", () => {
    acknowledgeIncidentEscalation().catch((err) => {
      const msg = err instanceof Error ? err.message : "unknown error";
      addActivity(`Escalation acknowledge failed (${msg})`);
    });
  });
  el.refreshEscalationBtn.addEventListener("click", () => {
    loadIncidentEscalationStatus().catch((err) => {
      const msg = err instanceof Error ? err.message : "unknown error";
      addActivity(`Escalation status refresh failed (${msg})`);
    });
  });
  el.feedImage.addEventListener("load", drawOverlay);
  window.addEventListener("resize", () => {
    drawOverlay();
    if (state.activeTab === "map" && state.map) {
      state.map.invalidateSize();
    }
  });

  el.tabMonitorBtn.addEventListener("click", () => setActiveTab("monitor"));
  el.tabMapBtn.addEventListener("click", () => {
    setActiveTab("map");
    if (state.cameraLocation && !state.mapLoading) {
      fetchNearbyServices().catch(() => setMapStatus("Map refresh failed", true));
    } else if (!state.cameraLocation) {
      setMapStatus("Use Camera Location or set manual coordinates", false);
    }
  });
  el.tabIncidentBtn.addEventListener("click", () => {
    setActiveTab("incident");
    loadIncidentTimeline().catch(() => {
      // User may not have incident id yet.
    });
  });
  el.tabAnalyticsBtn.addEventListener("click", () => {
    setActiveTab("analytics");
    loadAnalyticsBundle().catch((err) => {
      const msg = err instanceof Error ? err.message : "unknown error";
      addActivity(`Analytics load failed (${msg})`);
    });
  });
  el.loadAnalyticsBtn.addEventListener("click", () => {
    loadAnalyticsBundle().catch((err) => {
      const msg = err instanceof Error ? err.message : "unknown error";
      addActivity(`Analytics load failed (${msg})`);
    });
  });
  el.refreshHeatmapBtn.addEventListener("click", () => {
    const preferredZone = String(el.heatmapZoneSelect.value || "").trim();
    loadAnalyticsHeatmap(preferredZone).catch((err) => {
      const msg = err instanceof Error ? err.message : "unknown error";
      addActivity(`Heatmap refresh failed (${msg})`);
    });
  });
  el.heatmapZoneSelect.addEventListener("change", () => {
    renderHeatmapGridFromState();
  });
  el.saveShiftWindowsBtn.addEventListener("click", () => {
    saveShiftWindows()
      .then(() => loadAnalyticsOverview())
      .catch((err) => {
        const msg = err instanceof Error ? err.message : "unknown error";
        addActivity(`Shift window save failed (${msg})`);
      });
  });
  el.mapRadiusSelect.addEventListener("change", () => {
    state.mapRadiusKm = getSelectedRadiusKm();
    updateCameraAndRadiusOverlay();
    if (state.cameraLocation) {
      fetchNearbyServices().catch(() => setMapStatus("Map refresh failed", true));
    }
  });
  el.useMyLocationBtn.addEventListener("click", () => {
    useCurrentLocation().catch(() => setMapStatus("Location fetch failed", true));
  });
  el.refreshMapBtn.addEventListener("click", () => {
    fetchNearbyServices().catch(() => setMapStatus("Map refresh failed", true));
  });
  el.applyCoordinatesBtn.addEventListener("click", () => {
    applyManualCoordinates().catch(() => setMapStatus("Invalid coordinates", true));
  });

  connectFrameSocket();
  connectDetectionSocket();
  fetchStatus().then(() => {
    fetchZonePolicy(true).catch(() => {});
  });
  fetchDetectionHistory();
  fetchAlertHistory();

  setInterval(fetchStatus, 2500);
  setInterval(fetchDetectionHistory, 6000);
  setInterval(fetchAlertHistory, 4000);
  setInterval(() => {
    if (state.activeTab === "map" && state.cameraLocation) {
      fetchNearbyServices().catch(() => setMapStatus("Map auto refresh failed", true));
    }
  }, MAP_REFRESH_INTERVAL_MS);
}

init().catch(() => redirectToLogin());
