import { normalizeSeverity } from "../lib/severity";
import { deriveZoneKey, toNumber } from "./zoneDashboardUtils";

export const MARKER_RETENTION_MS = 20000;

export function buildHeatmapIndex(heatmapPayload) {
  const next = {};
  for (const item of Array.isArray(heatmapPayload?.zones) ? heatmapPayload.zones : []) {
    const zoneKey = deriveZoneKey(item?.zone_key);
    next[zoneKey] = {
      zone_key: zoneKey,
      total: Math.max(0, Math.round(toNumber(item?.total, 0))),
      max_count: Math.max(0, Math.round(toNumber(item?.max_count, 0))),
      peak: item?.peak && typeof item.peak === "object" ? { ...item.peak } : null,
    };
  }
  return next;
}

function normalizeMarkerPoint(detection, packet) {
  const center = detection?.bbox_center && typeof detection.bbox_center === "object" ? detection.bbox_center : null;
  const pathPoint = detection?.reid?.path_point && typeof detection.reid.path_point === "object"
    ? detection.reid.path_point
    : null;
  const rawX = pathPoint?.x ?? center?.x ?? 0.5;
  const rawY = pathPoint?.y ?? center?.y ?? 0.5;
  return {
    x: Math.max(0, Math.min(1, toNumber(rawX, 0.5))),
    y: Math.max(0, Math.min(1, toNumber(rawY, 0.5))),
    zone_key: deriveZoneKey(pathPoint?.zone_key || packet?.zone_key || packet?.source),
  };
}

export function buildMarkerFromDetection(packet, detection, index = 0) {
  if (!packet || !detection) {
    return null;
  }
  const severity = normalizeSeverity(packet?.severity?.level, packet?.severity?.score);
  const point = normalizeMarkerPoint(detection, packet);
  const id =
    String(detection?.alert_id || "").trim() ||
    String(packet?.alert_id || "").trim() ||
    `${packet?.timestamp || "ts"}:${point.zone_key}:${index}`;

  return {
    id,
    alert_id: String(packet?.alert_id || "").trim() || null,
    zone_key: point.zone_key,
    severity,
    label: String(detection?.label || packet?.severity?.weapon || "Threat"),
    confidence: toNumber(detection?.confidence, packet?.severity?.score),
    timestamp: packet?.timestamp || null,
    x: point.x,
    y: point.y,
    explanation: detection?.explanation || packet?.explanation || packet?.severity?.explanation || null,
    threat_id: detection?.reid?.track_id || detection?.reid?.threat_id || null,
    raw_detection: detection,
    packet,
  };
}

export function buildMarkerMapFromHistory(detectionHistory) {
  const next = {};
  for (const packet of Array.isArray(detectionHistory) ? detectionHistory : []) {
    const detections = Array.isArray(packet?.detections) ? packet.detections : [];
    detections.forEach((detection, index) => {
      const marker = buildMarkerFromDetection(packet, detection, index);
      if (!marker) {
        return;
      }
      const previous = next[marker.id];
      if (!previous || Date.parse(marker.timestamp || 0) >= Date.parse(previous.timestamp || 0)) {
        next[marker.id] = marker;
      }
    });
  }
  return next;
}

export function mergeMarkerPacket(markerMap, packet) {
  const next = { ...(markerMap || {}) };
  const detections = Array.isArray(packet?.detections) ? packet.detections : [];
  detections.forEach((detection, index) => {
    const marker = buildMarkerFromDetection(packet, detection, index);
    if (marker) {
      next[marker.id] = marker;
    }
  });
  return next;
}

export function pruneMarkerMap(markerMap, now = Date.now(), maxAgeMs = MARKER_RETENTION_MS) {
  const next = {};
  for (const [markerId, marker] of Object.entries(markerMap || {})) {
    const tsValue = Date.parse(marker?.timestamp || 0);
    if (!Number.isFinite(tsValue)) {
      continue;
    }
    if (now - tsValue > maxAgeMs) {
      continue;
    }
    next[markerId] = marker;
  }
  return next;
}
