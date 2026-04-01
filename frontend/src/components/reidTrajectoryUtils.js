import { normalizeSeverity } from "../lib/severity";
import { asDateValue, clamp, deriveZoneKey, toNumber } from "./zoneDashboardUtils";

const MAX_TRACK_PATH_POINTS = 160;
const MAX_VISIBLE_TRACKS = 18;

function uniqueValues(values) {
  const ordered = [];
  const seen = new Set();
  for (const value of values) {
    const token = String(value || "").trim();
    if (!token || seen.has(token)) {
      continue;
    }
    seen.add(token);
    ordered.push(token);
  }
  return ordered;
}

function sanitizePathPoint(point) {
  if (!point || typeof point !== "object") {
    return null;
  }
  const zoneKey = deriveZoneKey(point.zone_key);
  const cameraId = String(point.camera_id || "").trim() || "camera:unknown";
  return {
    x: Number(clamp(toNumber(point.x, 0.5), 0, 1).toFixed(4)),
    y: Number(clamp(toNumber(point.y, 0.5), 0, 1).toFixed(4)),
    zone_key: zoneKey,
    camera_id: cameraId,
    ts: String(point.ts || point.timestamp || ""),
    frame_id: point.frame_id ?? null,
  };
}

function dedupePath(points) {
  const merged = [];
  for (const item of points) {
    const point = sanitizePathPoint(item);
    if (!point) {
      continue;
    }
    const last = merged[merged.length - 1];
    if (
      last &&
      last.zone_key === point.zone_key &&
      last.camera_id === point.camera_id &&
      last.ts === point.ts &&
      Math.abs(last.x - point.x) < 0.0001 &&
      Math.abs(last.y - point.y) < 0.0001
    ) {
      continue;
    }
    merged.push(point);
  }
  return merged.slice(-MAX_TRACK_PATH_POINTS);
}

function normalizeTrackProfile(profile) {
  if (!profile || typeof profile !== "object") {
    return null;
  }
  const riskHistory = Array.isArray(profile.risk_history)
    ? profile.risk_history.map((value) => Number(clamp(toNumber(value, 0), 0, 1).toFixed(4))).slice(-50)
    : [];
  const zoneHistory = Array.isArray(profile.zone_history)
    ? profile.zone_history.map((value) => deriveZoneKey(value)).filter(Boolean).slice(-50)
    : [];
  return {
    track_id: String(profile.track_id || "").trim() || null,
    first_seen: String(profile.first_seen || "").trim() || null,
    last_seen: String(profile.last_seen || "").trim() || null,
    visit_count: Math.max(0, Math.round(toNumber(profile.visit_count ?? profile.visits, 0))),
    visits: Math.max(0, Math.round(toNumber(profile.visits ?? profile.visit_count, 0))),
    total_duration: Number(Math.max(0, toNumber(profile.total_duration, 0)).toFixed(3)),
    current_visit_duration: Number(Math.max(0, toNumber(profile.current_visit_duration, 0)).toFixed(3)),
    avg_risk_score: Number(clamp(toNumber(profile.avg_risk_score ?? profile.avg_risk, 0), 0, 1).toFixed(4)),
    max_risk_score: Number(clamp(toNumber(profile.max_risk_score ?? profile.max_risk, 0), 0, 1).toFixed(4)),
    behavior_risk_score: Number(clamp(toNumber(profile.behavior_risk_score ?? profile.final_behavior_risk_score, 0), 0, 1).toFixed(4)),
    behavior_flags: Array.isArray(profile.behavior_flags) ? [...profile.behavior_flags] : [],
    risk_history: riskHistory,
    zone_history: zoneHistory,
    zones: Array.isArray(profile.zones) ? profile.zones.map((value) => deriveZoneKey(value)).filter(Boolean) : zoneHistory,
    last_zone_key: deriveZoneKey(profile.last_zone_key || zoneHistory[zoneHistory.length - 1] || "zone:unknown"),
    high_risk: Boolean(profile.high_risk || toNumber(profile.behavior_risk_score, 0) >= 0.78),
    archived: Boolean(profile.archived),
  };
}

function normalizePredictive(predictive) {
  if (!predictive || typeof predictive !== "object") {
    return null;
  }
  const trackId = String(predictive.track_id || predictive.threat_id || "").trim();
  const riskScore = Math.max(0, Math.min(1, toNumber(predictive.risk_score, 0)));
  const riskLevel = normalizeSeverity(predictive.risk_level || (riskScore >= 0.85 ? "CRITICAL" : riskScore >= 0.7 ? "HIGH" : riskScore >= 0.45 ? "MEDIUM" : "LOW"));
  return {
    track_id: trackId || null,
    risk_score: Number(riskScore.toFixed(4)),
    risk_score_raw: Number(toNumber(predictive.risk_score_raw, riskScore).toFixed(4)),
    risk_level: riskLevel,
    high_risk: Boolean(predictive.high_risk || riskScore >= 0.7),
    pre_alert: Boolean(predictive.pre_alert || riskScore >= 0.85),
    behavior_flags: Array.isArray(predictive.behavior_flags) ? [...predictive.behavior_flags] : [],
    current_zone: deriveZoneKey(predictive.current_zone || predictive.zone_key || "zone:unknown"),
    duration: Number(toNumber(predictive.duration, 0).toFixed(3)),
    reason: String(predictive.reason || "").trim(),
    summary: String(predictive.summary || "").trim(),
    factors: Array.isArray(predictive.factors) ? [...predictive.factors] : [],
    model_breakdown: predictive.model_breakdown && typeof predictive.model_breakdown === "object" ? { ...predictive.model_breakdown } : {},
    feature_importance: Array.isArray(predictive.feature_importance) ? [...predictive.feature_importance] : [],
    explanation: predictive.explanation && typeof predictive.explanation === "object" ? { ...predictive.explanation } : null,
    last_seen: String(predictive.last_seen || predictive.timestamp || "").trim() || null,
    track_profile: normalizeTrackProfile(predictive.track_profile || predictive.behavior_context),
  };
}

export function normalizeTrack(track) {
  const trackId = String(track?.track_id || track?.threat_id || "").trim();
  if (!trackId) {
    return null;
  }

  const path = dedupePath(Array.isArray(track?.path) ? track.path : []);
  const derivedZones = path.map((point) => point.zone_key);
  const lastPoint = path[path.length - 1] || null;
  const lastSeen = String(track?.last_seen || track?.last_seen_at || lastPoint?.ts || "").trim() || null;
  const zoneKey = deriveZoneKey(track?.zone_key || lastPoint?.zone_key || "zone:unknown");
  const cameraId = String(track?.camera_id || lastPoint?.camera_id || "").trim() || "camera:unknown";
  const zones = uniqueValues([...(Array.isArray(track?.zones) ? track.zones.map(deriveZoneKey) : []), ...derivedZones, zoneKey]);
  const cameras = uniqueValues([
    ...(Array.isArray(track?.cameras) ? track.cameras.map((value) => String(value || "").trim()) : []),
    ...path.map((point) => point.camera_id),
    cameraId,
  ]);

  return {
    track_id: trackId,
    threat_id: trackId,
    created_at: track?.created_at || null,
    last_seen: lastSeen,
    zone_key: zoneKey,
    camera_id: cameraId,
    zones,
    cameras,
    path,
    confidence: Number(toNumber(track?.confidence, 0).toFixed(4)),
    event_count: Math.max(0, Math.round(toNumber(track?.event_count, 0))),
    match_count: Math.max(0, Math.round(toNumber(track?.match_count, 0))),
    labels: track?.labels && typeof track.labels === "object" ? { ...track.labels } : {},
    predictive: normalizePredictive(track?.predictive),
    track_profile: normalizeTrackProfile(track?.track_profile || track?.profile),
  };
}

export function mergeTrackPatch(existing, patch) {
  const base = normalizeTrack(existing || {});
  const next = normalizeTrack(patch || {});
  if (!next) {
    return base;
  }
  if (!base) {
    return next;
  }

  const path = dedupePath([...(base.path || []), ...(next.path || [])]);
  const lastSeen = asDateValue(next.last_seen) >= asDateValue(base.last_seen) ? next.last_seen : base.last_seen;
  const useNextHead = asDateValue(next.last_seen) >= asDateValue(base.last_seen);
  const labels = { ...base.labels };
  for (const [label, count] of Object.entries(next.labels || {})) {
    labels[label] = Math.max(toNumber(labels[label], 0), toNumber(count, 0));
  }

  return {
    ...base,
    ...next,
    last_seen: lastSeen,
    zone_key: useNextHead ? next.zone_key : base.zone_key,
    camera_id: useNextHead ? next.camera_id : base.camera_id,
    path,
    zones: uniqueValues([...(base.zones || []), ...(next.zones || []), ...path.map((point) => point.zone_key)]),
    cameras: uniqueValues([...(base.cameras || []), ...(next.cameras || []), ...path.map((point) => point.camera_id)]),
    confidence: Math.max(toNumber(base.confidence, 0), toNumber(next.confidence, 0)),
    event_count: Math.max(toNumber(base.event_count, 0), toNumber(next.event_count, 0)),
    match_count: Math.max(toNumber(base.match_count, 0), toNumber(next.match_count, 0)),
    labels,
    predictive: next.predictive || base.predictive || null,
    track_profile: next.track_profile || base.track_profile || next.predictive?.track_profile || base.predictive?.track_profile || null,
  };
}

export function buildTrackMap(tracks) {
  const next = {};
  for (const track of Array.isArray(tracks) ? tracks : []) {
    const normalized = normalizeTrack(track);
    if (!normalized) {
      continue;
    }
    next[normalized.track_id] = normalized;
  }
  return next;
}

export function sortTracks(trackMap) {
  return Object.values(trackMap || {}).sort((left, right) => asDateValue(right.last_seen) - asDateValue(left.last_seen));
}

export function routeLabel(track) {
  const zones = Array.isArray(track?.zones) ? track.zones : [];
  if (!zones.length) {
    return deriveZoneKey(track?.zone_key || "zone:unknown");
  }
  return zones.slice(-4).join(" -> ");
}

export function trackSeverity(track, zoneState) {
  const predictiveLevel = normalizeSeverity(track?.predictive?.risk_level);
  if (predictiveLevel !== "LOW" || track?.predictive?.risk_score > 0) {
    return predictiveLevel;
  }
  const behaviorScore = toNumber(track?.track_profile?.behavior_risk_score, 0);
  const behaviorLevel = normalizeSeverity(
    behaviorScore >= 0.85 ? "CRITICAL" : behaviorScore >= 0.7 ? "HIGH" : behaviorScore >= 0.45 ? "MEDIUM" : "LOW",
  );
  if (behaviorLevel !== "LOW" || behaviorScore > 0) {
    return behaviorLevel;
  }
  const zoneKey = deriveZoneKey(track?.zone_key || "zone:unknown");
  return normalizeSeverity(zoneState?.[zoneKey]?.severity);
}

export function trackRiskScore(track) {
  return Math.max(
    0,
    Math.min(
      1,
      Math.max(
        toNumber(track?.predictive?.risk_score, 0),
        toNumber(track?.track_profile?.behavior_risk_score, 0),
      ),
    ),
  );
}

export function mergePredictiveIntoTracks(trackMap, predictiveItems) {
  const next = { ...(trackMap || {}) };
  for (const item of Array.isArray(predictiveItems) ? predictiveItems : []) {
    const predictive = normalizePredictive(item);
    const trackId = String(predictive?.track_id || item?.track_id || item?.threat_id || "").trim();
    if (!predictive || !trackId) {
      continue;
    }
    const previous = next[trackId];
    if (!previous) {
      next[trackId] = normalizeTrack({
        track_id: trackId,
        threat_id: trackId,
        last_seen: predictive.last_seen,
        zone_key: predictive.current_zone,
        zones: [predictive.current_zone],
        cameras: [],
        path: [],
        confidence: 0,
        event_count: 0,
        match_count: 0,
        labels: {},
        predictive,
        track_profile: predictive.track_profile,
      });
      continue;
    }
    next[trackId] = {
      ...previous,
      predictive,
      track_profile: predictive.track_profile || previous.track_profile || null,
    };
  }
  return next;
}

function mapPathPointToCanvas(point, layout) {
  const zoneKey = deriveZoneKey(point.zone_key);
  const rect = layout?.[zoneKey];
  if (!rect) {
    return null;
  }
  return {
    ...point,
    zone_key: zoneKey,
    map_x: Number((rect.x + rect.width * clamp(toNumber(point.x, 0.5), 0, 1)).toFixed(3)),
    map_y: Number((rect.y + rect.height * clamp(toNumber(point.y, 0.5), 0, 1)).toFixed(3)),
  };
}

export function buildTrajectoryOverlay({
  trackMap,
  layout,
  zoneState,
  selectedTrackId,
  selectedZoneKey,
}) {
  return sortTracks(trackMap)
    .slice(0, MAX_VISIBLE_TRACKS)
    .map((track) => {
      const points = (track.path || []).map((point) => mapPathPointToCanvas(point, layout)).filter(Boolean);
      if (!points.length) {
        return null;
      }
      const severity = trackSeverity(track, zoneState);
      const isSelected = Boolean(selectedTrackId) && track.track_id === selectedTrackId;
      const isZoneMatch = Boolean(selectedZoneKey) && (track.zones || []).includes(selectedZoneKey);
      const opacity = isSelected ? 0.98 : isZoneMatch ? 0.78 : 0.36;
      return {
        track_id: track.track_id,
        severity,
        predictive: track.predictive || null,
        isSelected,
        isZoneMatch,
        opacity,
        stroke_width: isSelected ? 0.72 : isZoneMatch ? 0.5 : 0.32,
        points,
        points_text: points.map((point) => `${point.map_x},${point.map_y}`).join(" "),
        last_point: points[points.length - 1],
        route: routeLabel(track),
      };
    })
    .filter(Boolean);
}

export function upsertTracksFromPacket(trackMap, packet) {
  if (packet?.type === "predictive") {
    return mergePredictiveIntoTracks(trackMap, [packet.predictive || packet]);
  }
  const next = { ...(trackMap || {}) };
  const detections = Array.isArray(packet?.detections) ? packet.detections : [];
  for (const detection of detections) {
    const reid = detection?.reid;
    const trackId = String(reid?.track_id || reid?.threat_id || "").trim();
    if (!trackId) {
      continue;
    }

    const pathPoint = sanitizePathPoint(
      reid?.path_point || {
        x: 0.5,
        y: 0.5,
        zone_key: reid?.zone_key || packet?.zone_key || packet?.source,
        camera_id: reid?.camera_id || packet?.camera_id || packet?.source,
        ts: packet?.timestamp,
        frame_id: packet?.frame_id,
      },
    );
    const zoneKey = deriveZoneKey(reid?.zone_key || pathPoint?.zone_key || packet?.zone_key || packet?.source);
    const cameraId = String(reid?.camera_id || pathPoint?.camera_id || packet?.camera_id || packet?.source || "camera:unknown");
    const previous = next[trackId];
    const labels = previous?.labels ? { ...previous.labels } : {};
    const label = String(detection?.label || "").trim();
    if (label) {
      labels[label] = Math.max(1, Math.round(toNumber(labels[label], 0) + 1));
    }

    next[trackId] = mergeTrackPatch(previous, {
      track_id: trackId,
      threat_id: trackId,
      last_seen: packet?.timestamp || reid?.matched_timestamp || pathPoint?.ts || null,
      zone_key: zoneKey,
      camera_id: cameraId,
      confidence: reid?.confidence,
      event_count: Math.max(1, toNumber(previous?.event_count, 0) + 1),
      match_count: Math.max(toNumber(previous?.match_count, 0), toNumber(reid?.is_new_track ? 0 : 1, 0)),
      zones: uniqueValues([...(previous?.zones || []), zoneKey]),
      cameras: uniqueValues([...(previous?.cameras || []), cameraId]),
      path: pathPoint ? [...(previous?.path || []), pathPoint] : previous?.path || [],
      labels,
      predictive: normalizePredictive(detection?.predictive || reid?.predictive),
      track_profile: normalizeTrackProfile(detection?.track_profile || reid?.track_profile || detection?.behavior_context),
    });
  }
  return mergePredictiveIntoTracks(next, Array.isArray(packet?.predictive) ? packet.predictive : []);
}
