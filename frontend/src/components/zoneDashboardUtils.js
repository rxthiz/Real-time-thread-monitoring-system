import { compareSeverity, normalizeSeverity } from "../lib/severity";

export const MAX_RECENT_ITEMS = 8;

export function deriveZoneKey(sourceOrZoneKey) {
  const value = String(sourceOrZoneKey || "").trim().toLowerCase();
  if (!value) {
    return "zone:default";
  }
  if (value.startsWith("camera:") || value.startsWith("zone:")) {
    return value;
  }
  return `zone:${value.replace(/\s+/g, "-")}`;
}

export function formatZoneLabel(zoneKey) {
  const safe = deriveZoneKey(zoneKey);
  const [prefix, rawName = "default"] = safe.split(":");
  const label = rawName
    .split(/[-_]/g)
    .filter(Boolean)
    .map((token) => token.charAt(0).toUpperCase() + token.slice(1))
    .join(" ");
  return `${prefix.toUpperCase()} ${label || "Default"}`;
}

export function currentLocalHour() {
  return new Date().getHours();
}

export function asDateValue(value) {
  const date = new Date(value || 0);
  return Number.isNaN(date.getTime()) ? 0 : date.getTime();
}

export function formatTimestamp(value) {
  if (!value) {
    return "No activity";
  }
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return String(value);
  }
  return date.toLocaleString();
}

export function formatCompactTime(value) {
  if (!value) {
    return "--";
  }
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) {
    return "--";
  }
  return date.toLocaleTimeString();
}

export function clamp(value, min, max) {
  return Math.min(max, Math.max(min, value));
}

export function toNumber(value, fallback = 0) {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : fallback;
}

export function errorMessage(error) {
  return error instanceof Error ? error.message : "Request failed";
}

export function buildCurrentPolicyMap(policies) {
  const exactHour = {};
  const latest = {};
  const hourOfDay = currentLocalHour();

  for (const policy of Array.isArray(policies) ? policies : []) {
    const zoneKey = deriveZoneKey(policy?.zone_key);
    const updatedAt = asDateValue(policy?.updated_at);
    if (!latest[zoneKey] || updatedAt > asDateValue(latest[zoneKey]?.updated_at)) {
      latest[zoneKey] = policy;
    }
    if (
      Number(policy?.hour_of_day) === hourOfDay &&
      (!exactHour[zoneKey] || updatedAt > asDateValue(exactHour[zoneKey]?.updated_at))
    ) {
      exactHour[zoneKey] = policy;
    }
  }

  return {
    ...latest,
    ...exactHour,
  };
}

export function buildZoneState({
  liveStatus,
  policies,
  analyticsOverview,
  heatmapData,
  detectionHistory,
  alertHistory,
  previousState,
}) {
  const next = {};
  const alertCounts = {};
  const heatCounts = {};

  function ensure(zoneKey) {
    const safeZoneKey = deriveZoneKey(zoneKey);
    if (!next[safeZoneKey]) {
      next[safeZoneKey] = {
        zone_key: safeZoneKey,
        severity: "LOW",
        alert_count: 0,
        last_updated: null,
        current_threshold: null,
        is_snoozed: false,
        heat_count: 0,
        heat_ratio: 0,
        recent_packet: null,
      };
    }
    return next[safeZoneKey];
  }

  function applySeverity(zone, level, score) {
    const normalized = normalizeSeverity(level, score);
    if (compareSeverity(normalized, zone.severity) >= 0) {
      zone.severity = normalized;
    }
  }

  function applyTimestamp(zone, value) {
    if (asDateValue(value) >= asDateValue(zone.last_updated)) {
      zone.last_updated = value;
    }
  }

  for (const item of Array.isArray(liveStatus) ? liveStatus : []) {
    const zone = ensure(item?.zone_key);
    zone.alert_count = Math.max(zone.alert_count, toNumber(item?.alert_count, 0));
    zone.current_threshold = item?.current_threshold ?? zone.current_threshold;
    zone.is_snoozed = Boolean(item?.is_snoozed);
    applySeverity(zone, item?.severity, null);
    applyTimestamp(zone, item?.last_event_ts);
  }

  for (const [zoneKey, policy] of Object.entries(policies || {})) {
    const zone = ensure(zoneKey);
    zone.current_threshold = policy?.adaptive_threshold ?? zone.current_threshold;
    zone.is_snoozed = Boolean(policy?.is_snoozed);
    applyTimestamp(zone, policy?.updated_at);
  }

  for (const packet of Array.isArray(detectionHistory) ? detectionHistory : []) {
    const zone = ensure(packet?.zone_key || packet?.source);
    applySeverity(zone, packet?.severity?.level, packet?.severity?.score);
    applyTimestamp(zone, packet?.timestamp);
    if (!zone.recent_packet || asDateValue(packet?.timestamp) >= asDateValue(zone.recent_packet?.timestamp)) {
      zone.recent_packet = packet;
    }
  }

  for (const alert of Array.isArray(alertHistory) ? alertHistory : []) {
    const zoneKey = deriveZoneKey(alert?.zone_key || alert?.source);
    const zone = ensure(zoneKey);
    alertCounts[zoneKey] = (alertCounts[zoneKey] || 0) + 1;
    applySeverity(zone, alert?.event?.level, alert?.event?.score);
    applyTimestamp(zone, alert?.timestamp);
  }

  for (const item of heatmapData?.zones || []) {
    const zoneKey = deriveZoneKey(item?.zone_key);
    heatCounts[zoneKey] = toNumber(item?.total, 0);
    ensure(zoneKey);
  }

  for (const item of analyticsOverview?.zone_risk || []) {
    const zoneKey = deriveZoneKey(item?.zone_key);
    heatCounts[zoneKey] = Math.max(toNumber(heatCounts[zoneKey], 0), toNumber(item?.count, 0));
    ensure(zoneKey);
  }

  const maxHeat = Math.max(1, ...Object.values(heatCounts).map((value) => toNumber(value, 0)));

  for (const [zoneKey, count] of Object.entries(alertCounts)) {
    const zone = ensure(zoneKey);
    zone.alert_count = Math.max(zone.alert_count, count);
  }

  for (const [zoneKey, zone] of Object.entries(next)) {
    zone.heat_count = heatCounts[zoneKey] || 0;
    zone.heat_ratio = zone.heat_count / maxHeat;
  }

  for (const [zoneKey, zone] of Object.entries(previousState || {})) {
    if (!next[zoneKey]) {
      next[zoneKey] = { ...zone };
      continue;
    }
    if (asDateValue(zone.last_updated) > asDateValue(next[zoneKey].last_updated)) {
      next[zoneKey].last_updated = zone.last_updated;
      next[zoneKey].recent_packet = zone.recent_packet || next[zoneKey].recent_packet;
      next[zoneKey].alert_count = Math.max(
        toNumber(next[zoneKey].alert_count, 0),
        toNumber(zone.alert_count, 0),
      );
      if (compareSeverity(zone.severity, next[zoneKey].severity) >= 0) {
        next[zoneKey].severity = zone.severity;
      }
    }
    if (next[zoneKey].current_threshold == null && zone.current_threshold != null) {
      next[zoneKey].current_threshold = zone.current_threshold;
    }
  }

  return next;
}

export function collectZoneDetections(zoneKey, detectionHistory) {
  if (!zoneKey) {
    return [];
  }
  const items = [];
  for (const packet of Array.isArray(detectionHistory) ? detectionHistory : []) {
    if (deriveZoneKey(packet?.zone_key || packet?.source) !== zoneKey) {
      continue;
    }
    const severity = normalizeSeverity(packet?.severity?.level, packet?.severity?.score);
    const detections = Array.isArray(packet?.detections) ? packet.detections : [];
    if (!detections.length) {
      items.push({
        timestamp: packet?.timestamp,
        label: "Detection packet",
        confidence: null,
        severity,
        threat_id: packet?.correlation?.primary_threat_id || "--",
        reason: packet?.explanation?.reason || packet?.severity?.explanation?.reason || packet?.severity?.reason || "",
        score: packet?.explanation?.final_score ?? packet?.severity?.score ?? null,
      });
      continue;
    }
    for (const detection of detections) {
      items.push({
        timestamp: packet?.timestamp,
        label: detection?.label || "Unknown",
        confidence: detection?.confidence,
        severity,
        threat_id: detection?.reid?.threat_id || "--",
        reason: detection?.explanation?.reason || packet?.explanation?.reason || packet?.severity?.explanation?.reason || packet?.severity?.reason || "",
        score: detection?.explanation?.final_score ?? packet?.explanation?.final_score ?? packet?.severity?.score ?? null,
      });
    }
  }
  items.sort((left, right) => asDateValue(right.timestamp) - asDateValue(left.timestamp));
  return items.slice(0, MAX_RECENT_ITEMS);
}

export function collectZoneAlerts(zoneKey, alertHistory) {
  if (!zoneKey) {
    return [];
  }
  const items = (Array.isArray(alertHistory) ? alertHistory : [])
    .filter((alert) => deriveZoneKey(alert?.zone_key || alert?.source) === zoneKey)
    .sort((left, right) => asDateValue(right.timestamp) - asDateValue(left.timestamp));
  return items.slice(0, MAX_RECENT_ITEMS);
}
