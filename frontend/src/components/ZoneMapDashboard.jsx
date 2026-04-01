import {
  startTransition,
  useDeferredValue,
  useEffect,
  useRef,
  useState,
} from "react";

import {
  acknowledgeIncident,
  ApiError,
  dispatchSos,
  fetchAlertEvidence,
  fetchAlertHistory,
  fetchAnalyticsHeatmap,
  fetchDetectionHistory,
  fetchFalsePositiveModelStatus,
  fetchIncidentResponse,
  fetchLiveZoneStatus,
  fetchPredictiveTracks,
  fetchTrackProfile,
  fetchReidTrackPath,
  fetchReidTracks,
  fetchZoneLayout,
  fetchZonePolicies,
  saveZonePolicy,
  submitFalsePositiveFeedback,
  triggerManualSos,
} from "../lib/api";
import {
  clearSavedLayout,
  layoutFromCoordinates,
  loadSavedLayout,
  saveLayout,
  syncLayout,
} from "../lib/layout";
import { compareSeverity, normalizeSeverity } from "../lib/severity";
import { useDetectionSocket } from "../hooks/useDetectionSocket";
import { MetricCard } from "./DashboardPrimitives";
import EvidenceModal from "./EvidenceModal";
import { buildHeatmapIndex, buildMarkerMapFromHistory, mergeMarkerPacket, pruneMarkerMap } from "./liveMapUtils";
import PathLayer from "./PathLayer";
import SidePanel from "./SidePanel";
import ThreatMarker from "./ThreatMarker";
import ZoneLayer from "./ZoneLayer";
import {
  asDateValue,
  buildCurrentPolicyMap,
  buildZoneState,
  clamp,
  collectZoneAlerts,
  collectZoneDetections,
  currentLocalHour,
  deriveZoneKey,
  errorMessage,
  formatCompactTime,
  formatZoneLabel,
  toNumber,
} from "./zoneDashboardUtils";
import {
  buildTrackMap,
  buildTrajectoryOverlay,
  mergeTrackPatch,
  mergePredictiveIntoTracks,
  sortTracks,
  upsertTracksFromPacket,
} from "./reidTrajectoryUtils";

function stringifyLayout(layout) {
  return JSON.stringify(layout || {});
}

function evidenceStub(alertId, severity) {
  const level = String(severity || "").toUpperCase();
  const status = ["HIGH", "CRITICAL"].includes(level) ? "processing" : "not_requested";
  return {
    path: null,
    duration: null,
    frames: null,
    status,
    created_at: null,
    thumbnail_path: null,
    thumbnail_url: null,
    sha256: null,
    clip_name: null,
    logical_filename: null,
    download_url:
      status !== "not_requested" && alertId
        ? `/api/alerts/${encodeURIComponent(alertId)}/evidence?download=1`
        : null,
    error: null,
  };
}

function markerAlertPayload(marker, alertHistory) {
  if (!marker) {
    return null;
  }
  const matched = Array.isArray(alertHistory)
    ? alertHistory.find((item) => item?.alert_id && item.alert_id === marker.alert_id)
    : null;
  if (matched) {
    return {
      ...matched,
      alert_type:
        matched.alert_type ||
        marker.packet?.alert_type ||
        (marker.packet?.fp_filter?.decision === "uncertain" ? "OPERATOR_REVIEW_ALERT" : "THREAT_ALERT"),
      fp_filter: matched.fp_filter || marker.packet?.fp_filter || null,
      threat_probability:
        matched.threat_probability ?? marker.packet?.threat_probability ?? marker.packet?.fp_filter?.threat_probability ?? null,
      false_positive_feedback: matched.false_positive_feedback || marker.packet?.false_positive_feedback || null,
    };
  }
  return {
    alert_id: marker.alert_id || null,
    alert_type:
      marker.packet?.alert_type ||
      (marker.packet?.fp_filter?.decision === "uncertain" ? "OPERATOR_REVIEW_ALERT" : "THREAT_ALERT"),
    timestamp: marker.timestamp,
    zone_key: marker.zone_key,
    severity: marker.severity,
    event: marker.packet?.severity || null,
    explanation: marker.explanation || marker.packet?.explanation || null,
    top_weapon: marker.label,
    fp_filter: marker.packet?.fp_filter || null,
    threat_probability: marker.packet?.threat_probability ?? marker.packet?.fp_filter?.threat_probability ?? null,
    false_positive_feedback: marker.packet?.false_positive_feedback || null,
    evidence_status: evidenceStub(marker.alert_id, marker.severity).status,
    evidence_clip: evidenceStub(marker.alert_id, marker.severity),
  };
}

export default function ZoneMapDashboard() {
  const [zoneState, setZoneState] = useState({});
  const [liveAlerts, setLiveAlerts] = useState({});
  const [reidTracks, setReidTracks] = useState({});
  const [detectionHistory, setDetectionHistory] = useState([]);
  const [alertHistory, setAlertHistory] = useState([]);
  const [heatmapIndex, setHeatmapIndex] = useState({});
  const [zoneLayoutRecords, setZoneLayoutRecords] = useState([]);
  const [selectedZoneKey, setSelectedZoneKey] = useState("");
  const [selectedTrackId, setSelectedTrackId] = useState("");
  const [selectedMarkerId, setSelectedMarkerId] = useState("");
  const [hoveredZone, setHoveredZone] = useState(null);
  const [layout, setLayout] = useState(() => loadSavedLayout());
  const [editMode, setEditMode] = useState(false);
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [lastSyncedAt, setLastSyncedAt] = useState(null);
  const [errorText, setErrorText] = useState("");
  const [policyAccess, setPolicyAccess] = useState("loading");
  const [policyForm, setPolicyForm] = useState({
    threshold: "",
    snoozeMinutes: "30",
  });
  const [policySaving, setPolicySaving] = useState(false);
  const [layoutNotice, setLayoutNotice] = useState("");
  const [trackPathLoading, setTrackPathLoading] = useState(false);
  const [trackProfileLoading, setTrackProfileLoading] = useState(false);
  const [expandedAlertId, setExpandedAlertId] = useState("");
  const [incidentResponse, setIncidentResponse] = useState(null);
  const [incidentResponseLoading, setIncidentResponseLoading] = useState(false);
  const [sosActionLoading, setSosActionLoading] = useState("");
  const [sosError, setSosError] = useState("");
  const [feedbackLoadingAlertId, setFeedbackLoadingAlertId] = useState("");
  const [modelStatus, setModelStatus] = useState(null);
  const [evidenceModal, setEvidenceModal] = useState({
    open: false,
    alertId: "",
    loading: false,
    payload: null,
    error: "",
  });

  const selectedZoneKeyDeferred = useDeferredValue(selectedZoneKey);
  const mapRef = useRef(null);
  const dragRef = useRef(null);
  const inFlightRef = useRef(false);
  const seededZoneRef = useRef("");

  const remoteLayoutMap = layoutFromCoordinates(zoneLayoutRecords);
  const remoteLayoutSignature = stringifyLayout(remoteLayoutMap);

  const zoneKeys = Object.keys(zoneState).sort();
  const zoneEntries = zoneKeys
    .map((zoneKey) => [zoneKey, zoneState[zoneKey]])
    .sort((left, right) => {
      const severityDelta = compareSeverity(right[1]?.severity, left[1]?.severity);
      if (severityDelta !== 0) {
        return severityDelta;
      }
      const alertDelta = toNumber(right[1]?.alert_count, 0) - toNumber(left[1]?.alert_count, 0);
      if (alertDelta !== 0) {
        return alertDelta;
      }
      return asDateValue(right[1]?.last_updated) - asDateValue(left[1]?.last_updated);
    });

  const markerEntries = Object.values(liveAlerts)
    .filter((marker) => layout[marker.zone_key])
    .sort((left, right) => asDateValue(right.timestamp) - asDateValue(left.timestamp));
  const selectedZone = selectedZoneKeyDeferred ? zoneState[selectedZoneKeyDeferred] || null : null;
  const selectedTrack = selectedTrackId ? reidTracks[selectedTrackId] || null : null;
  const selectedMarker = selectedMarkerId ? liveAlerts[selectedMarkerId] || null : null;
  const selectedMarkerAlert = markerAlertPayload(selectedMarker, alertHistory);
  const selectedAlerts = collectZoneAlerts(selectedZoneKeyDeferred, alertHistory);
  const selectedIncidentId =
    selectedMarkerAlert?.incident_id ||
    selectedAlerts?.[0]?.incident_id ||
    "";
  const selectedDetections = collectZoneDetections(selectedZoneKeyDeferred, detectionHistory);
  const hoveredZoneAlert = hoveredZone?.zoneKey ? collectZoneAlerts(hoveredZone.zoneKey, alertHistory)[0] || null : null;
  const trackEntries = sortTracks(reidTracks);
  const highRiskTracks = trackEntries.filter(
    (track) => Boolean(track?.predictive?.high_risk || track?.track_profile?.high_risk),
  );
  const selectedZoneTracks = selectedZoneKeyDeferred
    ? trackEntries.filter((track) => (track.zones || []).includes(selectedZoneKeyDeferred))
    : [];
  const trajectoryOverlay = buildTrajectoryOverlay({
    trackMap: reidTracks,
    layout,
    zoneState,
    selectedTrackId,
    selectedZoneKey: selectedZoneKeyDeferred,
  });
  const selectedZoneHeat = selectedZoneKeyDeferred ? heatmapIndex[selectedZoneKeyDeferred] || null : null;

  const totalAlerts = zoneEntries.reduce((sum, [, zone]) => sum + toNumber(zone?.alert_count, 0), 0);
  const activeThreatZones = zoneEntries.filter(([, zone]) => compareSeverity(zone?.severity, "LOW") > 0).length;
  const liveMarkerCount = markerEntries.length;
  const activeTrackCount = trackEntries.length;

  function withTrackZones(previousState, trackMap) {
    const nextState = { ...(previousState || {}) };
    let changed = false;
    for (const track of Object.values(trackMap || {})) {
      const zoneKeysToEnsure = Array.isArray(track?.zones) && track.zones.length ? track.zones : [track?.zone_key];
      for (const zoneKey of zoneKeysToEnsure) {
        const safeZoneKey = deriveZoneKey(zoneKey);
        if (nextState[safeZoneKey]) {
          continue;
        }
        nextState[safeZoneKey] = {
          zone_key: safeZoneKey,
          severity: "LOW",
          alert_count: 0,
          last_updated: track?.last_seen || null,
          current_threshold: null,
          is_snoozed: false,
          heat_count: 0,
          heat_ratio: 0,
          recent_packet: null,
        };
        changed = true;
      }
    }
    return changed ? nextState : previousState;
  }

  async function loadDashboardData(backgroundRefresh = false) {
    if (inFlightRef.current) {
      return;
    }
    inFlightRef.current = true;
    if (backgroundRefresh) {
      setRefreshing(true);
    } else {
      setLoading(true);
    }

    try {
      const results = await Promise.allSettled([
        fetchLiveZoneStatus(),
        fetchZonePolicies(),
        fetchAnalyticsHeatmap(),
        fetchDetectionHistory(),
        fetchAlertHistory(),
        fetchReidTracks(),
        fetchPredictiveTracks(),
        fetchZoneLayout(),
        fetchFalsePositiveModelStatus(),
      ]);

      const issues = [];
      const liveStatus =
        results[0].status === "fulfilled" && Array.isArray(results[0].value) ? results[0].value : [];
      if (results[0].status === "rejected") {
        issues.push(`Live status: ${errorMessage(results[0].reason)}`);
      }

      let policies = [];
      let nextPolicyAccess = "granted";
      if (results[1].status === "fulfilled") {
        policies = Array.isArray(results[1].value?.policies) ? results[1].value.policies : [];
      } else if (results[1].reason instanceof ApiError && results[1].reason.status === 403) {
        nextPolicyAccess = "restricted";
      } else {
        nextPolicyAccess = "error";
        issues.push(`Zone policies: ${errorMessage(results[1].reason)}`);
      }

      const heatmapPayload = results[2].status === "fulfilled" ? results[2].value : null;
      const detectionItems =
        results[3].status === "fulfilled" && Array.isArray(results[3].value?.detections)
          ? [...results[3].value.detections].reverse()
          : [];
      const alertItems =
        results[4].status === "fulfilled" && Array.isArray(results[4].value?.alerts)
          ? [...results[4].value.alerts].reverse()
          : [];
      const trackMap =
        results[5].status === "fulfilled" && Array.isArray(results[5].value)
          ? buildTrackMap(results[5].value)
          : {};
      const predictiveItems =
        results[6].status === "fulfilled" && Array.isArray(results[6].value) ? results[6].value : [];
      const layoutRecords =
        results[7].status === "fulfilled" && Array.isArray(results[7].value) ? results[7].value : [];
      const fpModelStatus =
        results[8].status === "fulfilled" && results[8].value && typeof results[8].value === "object"
          ? results[8].value
          : null;

      if (results[2].status === "rejected") {
        issues.push(`Heatmap: ${errorMessage(results[2].reason)}`);
      }
      if (results[3].status === "rejected") {
        issues.push(`Detections: ${errorMessage(results[3].reason)}`);
      }
      if (results[4].status === "rejected") {
        issues.push(`Alerts: ${errorMessage(results[4].reason)}`);
      }
      if (results[5].status === "rejected") {
        issues.push(`ReID tracks: ${errorMessage(results[5].reason)}`);
      }
      if (results[6].status === "rejected") {
        issues.push(`Predictive tracks: ${errorMessage(results[6].reason)}`);
      }
      if (results[7].status === "rejected") {
        issues.push(`Zone layout: ${errorMessage(results[7].reason)}`);
      }
      if (results[8].status === "rejected") {
        issues.push(`FP model: ${errorMessage(results[8].reason)}`);
      }

      const policyMap = buildCurrentPolicyMap(policies);
      const heatIndex = buildHeatmapIndex(heatmapPayload);
      const markerMap = pruneMarkerMap(buildMarkerMapFromHistory(detectionItems));

      startTransition(() => {
        setDetectionHistory(detectionItems);
        setAlertHistory(alertItems);
        setPolicyAccess(nextPolicyAccess);
        setHeatmapIndex(heatIndex);
        setZoneLayoutRecords(layoutRecords);
        setZoneState((previousState) =>
          withTrackZones(
            buildZoneState({
              liveStatus,
              policies: policyMap,
              analyticsOverview: null,
              heatmapData: heatmapPayload,
              detectionHistory: detectionItems,
              alertHistory: alertItems,
              previousState,
            }),
            trackMap,
          ),
        );
        setReidTracks((previousTracks) => {
          const nextTracks = mergePredictiveIntoTracks({ ...trackMap }, predictiveItems);
          for (const [trackId, existingTrack] of Object.entries(previousTracks || {})) {
            if (!nextTracks[trackId]) {
              continue;
            }
            nextTracks[trackId] = mergeTrackPatch(nextTracks[trackId], existingTrack);
          }
          return nextTracks;
        });
        setLiveAlerts(markerMap);
        setModelStatus(fpModelStatus);
        setLastSyncedAt(new Date().toISOString());
        setErrorText(issues.join(" | "));
      });
    } finally {
      inFlightRef.current = false;
      setLoading(false);
      setRefreshing(false);
    }
  }

  function updateHover(zoneKey, event) {
    if (!mapRef.current) {
      return;
    }
    const bounds = mapRef.current.getBoundingClientRect();
    setHoveredZone({
      zoneKey,
      x: event.clientX - bounds.left + 18,
      y: event.clientY - bounds.top + 18,
    });
  }

  function startDrag(zoneKey, event) {
    if (!editMode || !mapRef.current) {
      return;
    }
    event.preventDefault();
    const bounds = mapRef.current.getBoundingClientRect();
    const rect = layout[zoneKey];
    if (!rect) {
      return;
    }
    dragRef.current = {
      zoneKey,
      width: rect.width,
      height: rect.height,
      offsetX: ((event.clientX - bounds.left) / bounds.width) * 100 - rect.x,
      offsetY: ((event.clientY - bounds.top) / bounds.height) * 100 - rect.y,
    };
  }

  function persistLayout() {
    saveLayout(layout);
    setLayoutNotice("Layout saved to local storage");
  }

  function resetLayout() {
    clearSavedLayout();
    setLayout(syncLayout(zoneKeys, {}, remoteLayoutMap));
    setLayoutNotice("Layout reset to zone layout feed");
  }

  function exportLayoutJson() {
    const blob = new Blob([JSON.stringify(layout, null, 2)], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const anchor = document.createElement("a");
    anchor.href = url;
    anchor.download = "zone-layout.json";
    anchor.click();
    URL.revokeObjectURL(url);
    setLayoutNotice("Layout JSON exported");
  }

  function handlePolicyFormChange(field, value) {
    setPolicyForm((previous) => ({
      ...previous,
      [field]: value,
    }));
  }

  async function applyPolicy(event) {
    event.preventDefault();
    if (!selectedZoneKeyDeferred) {
      return;
    }

    setPolicySaving(true);
    setErrorText("");
    try {
      const payload = { hour_of_day: currentLocalHour() };
      if (String(policyForm.threshold).trim() !== "") {
        const value = Number(policyForm.threshold);
        if (!Number.isFinite(value) || value < 0 || value > 1) {
          throw new Error("Threshold must be between 0 and 1");
        }
        payload.adaptive_threshold = value;
      }
      if (String(policyForm.snoozeMinutes).trim() !== "") {
        const value = Number(policyForm.snoozeMinutes);
        if (!Number.isFinite(value) || value < 0 || value > 720) {
          throw new Error("Snooze minutes must be between 0 and 720");
        }
        payload.snooze_minutes = Math.round(value);
      }
      await saveZonePolicy(selectedZoneKeyDeferred, payload);
      seededZoneRef.current = "";
      await loadDashboardData(true);
    } catch (error) {
      if (error instanceof ApiError && error.status === 403) {
        setPolicyAccess("restricted");
      }
      setErrorText(errorMessage(error));
    } finally {
      setPolicySaving(false);
    }
  }

  async function loadIncidentState(incidentId) {
    const safeIncidentId = String(incidentId || "").trim();
    if (!safeIncidentId) {
      setIncidentResponse(null);
      setSosError("");
      return;
    }
    setIncidentResponseLoading(true);
    try {
      const payload = await fetchIncidentResponse(safeIncidentId);
      setIncidentResponse(payload);
      setSosError("");
    } catch (error) {
      setSosError(errorMessage(error));
    } finally {
      setIncidentResponseLoading(false);
    }
  }

  async function handleSosAction(action, services) {
    if (!selectedIncidentId) {
      setSosError("Select an alert with an incident before dispatching SOS.");
      return;
    }
    setSosActionLoading(action);
    setSosError("");
    try {
      if (action === "cancel") {
        await acknowledgeIncident(selectedIncidentId, { note: "Cancelled from dashboard", resolution: "CANCELLED" });
      } else if (action === "dispatch") {
        await dispatchSos({ incident_id: selectedIncidentId, services, reason: `Dashboard dispatch: ${services.join(", ")}` });
      } else {
        await triggerManualSos({ incident_id: selectedIncidentId, services, reason: `Dashboard manual trigger: ${services.join(", ")}` });
      }
      await loadIncidentState(selectedIncidentId);
      await loadDashboardData(true);
    } catch (error) {
      setSosError(errorMessage(error));
    } finally {
      setSosActionLoading("");
    }
  }

  function handleSelectMarker(marker) {
    setSelectedMarkerId(marker.id);
    setSelectedZoneKey(marker.zone_key);
  }

  function handleSelectTrack(trackId, zoneKey) {
    setSelectedTrackId(trackId);
    if (zoneKey) {
      setSelectedZoneKey(zoneKey);
    }
  }

  async function loadEvidenceForAlert(alertId) {
    const safeAlertId = String(alertId || "").trim();
    if (!safeAlertId) {
      return;
    }
    setEvidenceModal((previous) => ({
      open: true,
      alertId: safeAlertId,
      loading: true,
      payload: previous.alertId === safeAlertId ? previous.payload : null,
      error: "",
    }));
    try {
      const payload = await fetchAlertEvidence(safeAlertId);
      setEvidenceModal({
        open: true,
        alertId: safeAlertId,
        loading: false,
        payload,
        error: "",
      });
    } catch (error) {
      setEvidenceModal({
        open: true,
        alertId: safeAlertId,
        loading: false,
        payload: null,
        error: errorMessage(error),
      });
    }
  }

  function openEvidence(alert) {
    if (!alert?.alert_id) {
      return;
    }
    loadEvidenceForAlert(alert.alert_id).catch((error) => {
      setEvidenceModal({
        open: true,
        alertId: String(alert.alert_id),
        loading: false,
        payload: null,
        error: errorMessage(error),
      });
    });
  }

  function closeEvidenceModal() {
    setEvidenceModal({
      open: false,
      alertId: "",
      loading: false,
      payload: null,
      error: "",
    });
  }

  async function handleAlertFeedback(alertId, label) {
    const safeAlertId = String(alertId || "").trim();
    const safeLabel = String(label || "").trim().toLowerCase();
    if (!safeAlertId || !["true", "false"].includes(safeLabel)) {
      return;
    }

    setFeedbackLoadingAlertId(safeAlertId);
    try {
      const response = await submitFalsePositiveFeedback({
        alert_id: safeAlertId,
        label: safeLabel,
      });
      const updatedAlert = response?.alert && typeof response.alert === "object" ? response.alert : null;
      const nextModelStatus = response?.model_status && typeof response.model_status === "object" ? response.model_status : null;

      startTransition(() => {
        if (updatedAlert) {
          setAlertHistory((previous) => [updatedAlert, ...previous.filter((item) => item?.alert_id !== safeAlertId)].slice(0, 160));
          setLiveAlerts((previous) => {
            let changed = false;
            const next = {};
            for (const [markerId, marker] of Object.entries(previous || {})) {
              if (marker?.alert_id !== safeAlertId) {
                next[markerId] = marker;
                continue;
              }
              changed = true;
              next[markerId] = {
                ...marker,
                explanation: updatedAlert.explanation || marker.explanation,
                packet: {
                  ...(marker.packet || {}),
                  alert_id: safeAlertId,
                  alert_type: updatedAlert.alert_type || marker.packet?.alert_type,
                  incident_id: updatedAlert.incident_id || marker.packet?.incident_id || null,
                  fp_filter: updatedAlert.fp_filter || marker.packet?.fp_filter || null,
                  false_positive_feedback:
                    updatedAlert.false_positive_feedback || marker.packet?.false_positive_feedback || null,
                  threat_probability:
                    updatedAlert.threat_probability ?? marker.packet?.threat_probability ?? null,
                },
              };
            }
            return changed ? next : previous;
          });
        }
        if (nextModelStatus) {
          setModelStatus(nextModelStatus);
        }
      });
    } catch (error) {
      setErrorText(errorMessage(error));
    } finally {
      setFeedbackLoadingAlertId("");
    }
  }

  useEffect(() => {
    loadDashboardData(false).catch((error) => {
      setErrorText(errorMessage(error));
      setLoading(false);
    });

    const intervalId = window.setInterval(() => {
      if (!document.hidden) {
        loadDashboardData(true).catch((error) => setErrorText(errorMessage(error)));
      }
    }, 15000);

    return () => {
      window.clearInterval(intervalId);
    };
  }, []);

  const { connectionState, lastPacketAt } = useDetectionSocket({
    enabled: true,
    throttleMs: 90,
    onDetection: (packet) => {
      if (packet?.type === "SOS_TRIGGERED" || packet?.type === "SOS_DISPATCHED" || packet?.type === "ESCALATION_UPDATE") {
        if (packet?.incident_id && packet.incident_id === selectedIncidentId) {
          loadIncidentState(packet.incident_id).catch((error) => setSosError(errorMessage(error)));
        }
        return;
      }
      if (packet?.type === "predictive") {
        const zoneKey = deriveZoneKey(packet?.zone_key || packet?.predictive?.zone_key || packet?.source);
        const timestamp = packet?.timestamp || new Date().toISOString();
        const severity = normalizeSeverity(packet?.risk_level || packet?.severity?.level, packet?.risk_score || packet?.severity?.score);

        startTransition(() => {
          setReidTracks((previousTracks) => upsertTracksFromPacket(previousTracks, packet));
          if (packet?.alert_id) {
            setAlertHistory((previous) => {
              const nextAlert = {
                alert_id: packet.alert_id,
                alert_type: packet.alert_type || "PREDICTIVE_ALERT",
                timestamp,
                source: packet.source,
                zone_key: zoneKey,
                severity,
                event: packet?.severity || {
                  level: severity,
                  score: packet?.risk_score,
                  reason: packet?.reason,
                },
                explanation: packet?.explanation || packet?.predictive?.explanation || null,
                top_weapon: "Predictive Risk",
                fp_filter: null,
                threat_probability: null,
                false_positive_feedback: null,
                evidence_status: "not_requested",
                evidence_clip: evidenceStub(packet.alert_id, "LOW"),
                predictive: packet?.predictive || null,
              };
              return [nextAlert, ...previous.filter((item) => item?.alert_id !== packet.alert_id)].slice(0, 160);
            });
            setZoneState((previousState) => {
              const existing = previousState[zoneKey] || {
                zone_key: zoneKey,
                severity: "LOW",
                alert_count: 0,
                last_updated: null,
                current_threshold: null,
                is_snoozed: false,
                heat_count: 0,
                heat_ratio: 0,
                recent_packet: null,
              };
              return {
                ...previousState,
                [zoneKey]: {
                  ...existing,
                  severity: compareSeverity(severity, existing.severity) >= 0 ? severity : existing.severity,
                  alert_count: existing.alert_count + 1,
                  last_updated: timestamp,
                  recent_packet: packet,
                },
              };
            });
          }
        });
        return;
      }

      const zoneKey = deriveZoneKey(packet?.zone_key || packet?.source);
      const timestamp = packet?.timestamp || new Date().toISOString();
      const severity = normalizeSeverity(packet?.severity?.level, packet?.severity?.score);

      startTransition(() => {
        setDetectionHistory((previous) => [packet, ...previous].slice(0, 160));
        setLiveAlerts((previous) => pruneMarkerMap(mergeMarkerPacket(previous, packet)));
        if (packet?.alert_id) {
          setAlertHistory((previous) => {
            const evidence = evidenceStub(packet.alert_id, packet?.severity?.level || severity);
            const nextAlert = {
              alert_id: packet.alert_id,
              alert_type: packet.alert_type || "THREAT_ALERT",
              timestamp: packet.timestamp,
              source: packet.source,
              zone_key: packet.zone_key || packet.source,
              incident_id: packet.incident_id || null,
              severity: packet?.severity?.level,
              event: packet?.severity || null,
              explanation: packet?.explanation || packet?.severity?.explanation || null,
              top_weapon: packet?.severity?.weapon || packet?.detections?.[0]?.label || "Threat",
              fp_filter: packet?.fp_filter || null,
              threat_probability: packet?.threat_probability ?? packet?.fp_filter?.threat_probability ?? null,
              false_positive_feedback: packet?.false_positive_feedback || null,
              evidence_status: evidence.status,
              evidence_clip: evidence,
              predictive: Array.isArray(packet?.predictive) && packet.predictive.length ? packet.predictive[0]?.predictive || packet.predictive[0] : null,
            };
            return [nextAlert, ...previous.filter((item) => item?.alert_id !== packet.alert_id)].slice(0, 160);
          });
        }
        setZoneState((previousState) => {
          const existing = previousState[zoneKey] || {
            zone_key: zoneKey,
            severity: "LOW",
            alert_count: 0,
            last_updated: null,
            current_threshold: null,
            is_snoozed: false,
            heat_count: 0,
            heat_ratio: 0,
            recent_packet: null,
          };

          return {
            ...previousState,
            [zoneKey]: {
              ...existing,
              severity: compareSeverity(severity, existing.severity) >= 0 ? severity : existing.severity,
              alert_count: existing.alert_count + (packet?.alert_id ? 1 : 0),
              last_updated: timestamp,
              recent_packet: packet,
            },
          };
        });
        setReidTracks((previousTracks) => upsertTracksFromPacket(previousTracks, packet));
      });
    },
  });

  useEffect(() => {
    if (!selectedIncidentId) {
      setIncidentResponse(null);
      setSosError("");
      return;
    }
    loadIncidentState(selectedIncidentId).catch((error) => setSosError(errorMessage(error)));
  }, [selectedIncidentId]);

  useEffect(() => {
    setLayout((previous) => {
      const next = syncLayout(zoneKeys, previous, remoteLayoutMap);
      return stringifyLayout(next) === stringifyLayout(previous) ? previous : next;
    });
    if (!zoneKeys.length) {
      setSelectedZoneKey("");
      return;
    }
    if (!selectedZoneKey || !zoneState[selectedZoneKey]) {
      setSelectedZoneKey(zoneKeys[0]);
    }
  }, [selectedZoneKey, zoneKeys.join("|"), remoteLayoutSignature]);

  useEffect(() => {
    if (!selectedZoneKeyDeferred || seededZoneRef.current === selectedZoneKeyDeferred) {
      return;
    }
    seededZoneRef.current = selectedZoneKeyDeferred;
    const selected = zoneState[selectedZoneKeyDeferred];
    setPolicyForm({
      threshold: selected?.current_threshold != null ? String(selected.current_threshold) : "",
      snoozeMinutes: "30",
    });
  }, [selectedZoneKeyDeferred, zoneState]);

  useEffect(() => {
    if (selectedTrackId && !reidTracks[selectedTrackId]) {
      setSelectedTrackId("");
    }
  }, [reidTracks, selectedTrackId]);

  useEffect(() => {
    if (selectedMarkerId && !liveAlerts[selectedMarkerId]) {
      setSelectedMarkerId("");
    }
  }, [liveAlerts, selectedMarkerId]);

  useEffect(() => {
    const intervalId = window.setInterval(() => {
      setLiveAlerts((previous) => pruneMarkerMap(previous));
    }, 2000);
    return () => {
      window.clearInterval(intervalId);
    };
  }, []);

  useEffect(() => {
    if (!expandedAlertId) {
      return;
    }
    const exists = alertHistory.some((alert) => alert?.alert_id === expandedAlertId);
    if (!exists) {
      setExpandedAlertId("");
    }
  }, [alertHistory, expandedAlertId]);

  useEffect(() => {
    if (!layoutNotice) {
      return undefined;
    }
    const timeoutId = window.setTimeout(() => setLayoutNotice(""), 2400);
    return () => {
      window.clearTimeout(timeoutId);
    };
  }, [layoutNotice]);

  useEffect(() => {
    if (!evidenceModal.open) {
      return undefined;
    }
    function handleKeyDown(event) {
      if (event.key === "Escape") {
        closeEvidenceModal();
      }
    }
    window.addEventListener("keydown", handleKeyDown);
    return () => {
      window.removeEventListener("keydown", handleKeyDown);
    };
  }, [evidenceModal.open]);

  useEffect(() => {
    if (!editMode) {
      dragRef.current = null;
      return undefined;
    }

    function handlePointerMove(event) {
      if (!dragRef.current || !mapRef.current) {
        return;
      }
      const bounds = mapRef.current.getBoundingClientRect();
      const drag = dragRef.current;
      const x = clamp(((event.clientX - bounds.left) / bounds.width) * 100 - drag.offsetX, 0, 100 - drag.width);
      const y = clamp(((event.clientY - bounds.top) / bounds.height) * 100 - drag.offsetY, 0, 100 - drag.height);

      setLayout((previous) => ({
        ...previous,
        [drag.zoneKey]: {
          ...previous[drag.zoneKey],
          x,
          y,
        },
      }));
    }

    function handlePointerUp() {
      dragRef.current = null;
    }

    window.addEventListener("pointermove", handlePointerMove);
    window.addEventListener("pointerup", handlePointerUp);

    return () => {
      window.removeEventListener("pointermove", handlePointerMove);
      window.removeEventListener("pointerup", handlePointerUp);
    };
  }, [editMode]);

  useEffect(() => {
    if (!selectedTrackId) {
      setTrackPathLoading(false);
      setTrackProfileLoading(false);
      return undefined;
    }

    let cancelled = false;
    setTrackPathLoading(true);
    setTrackProfileLoading(true);

    fetchReidTrackPath(selectedTrackId)
      .then((payload) => {
        if (cancelled) {
          return;
        }
        startTransition(() => {
          setReidTracks((previousTracks) => {
            const existingTrack = previousTracks[selectedTrackId];
            if (!existingTrack) {
              return previousTracks;
            }
            return {
              ...previousTracks,
              [selectedTrackId]: mergeTrackPatch(existingTrack, payload),
            };
          });
        });
      })
      .catch((error) => {
        if (!cancelled) {
          setErrorText((current) => current || `Track path: ${errorMessage(error)}`);
        }
      })
      .finally(() => {
        if (!cancelled) {
          setTrackPathLoading(false);
        }
      });

    fetchTrackProfile(selectedTrackId)
      .then((payload) => {
        if (cancelled) {
          return;
        }
        startTransition(() => {
          setReidTracks((previousTracks) => {
            const existingTrack = previousTracks[selectedTrackId];
            const currentTrack = payload?.current_track || { track_id: selectedTrackId, threat_id: selectedTrackId };
            const mergedTrack = mergeTrackPatch(existingTrack, currentTrack);
            return {
              ...previousTracks,
              [selectedTrackId]: {
                ...mergedTrack,
                track_profile: payload,
              },
            };
          });
        });
      })
      .catch((error) => {
        if (!cancelled) {
          setErrorText((current) => current || `Track profile: ${errorMessage(error)}`);
        }
      })
      .finally(() => {
        if (!cancelled) {
          setTrackProfileLoading(false);
        }
      });

    return () => {
      cancelled = true;
    };
  }, [selectedTrackId]);

  const connectionBadgeClass =
    connectionState === "open"
      ? "border-emerald-400/30 bg-emerald-400/10 text-emerald-200"
      : connectionState === "connecting"
        ? "border-cyan-400/30 bg-cyan-400/10 text-cyan-100"
        : "border-rose-400/30 bg-rose-400/10 text-rose-200";

  return (
    <div className="min-h-screen bg-slate-950 px-4 py-4 text-slate-100 sm:px-6 lg:px-8">
      <div className="control-room-shell mx-auto flex min-h-[calc(100vh-2rem)] max-w-[1800px] flex-col gap-5">
        <header className="rounded-[1.75rem] border border-white/10 bg-white/[0.035] px-5 py-5 shadow-glow backdrop-blur">
          <div className="flex flex-col gap-5 xl:flex-row xl:items-start xl:justify-between">
            <div>
              <p className="text-[11px] uppercase tracking-[0.4em] text-cyan-300/80">
                Threat Monitoring System
              </p>
              <h1 className="mt-3 font-sans text-3xl font-semibold tracking-[0.08em] text-slate-100 sm:text-4xl">
                Live Threat Map Dashboard
              </h1>
              <p className="mt-3 max-w-3xl text-sm text-slate-400">
                Control-room map view with live zone state, websocket threat markers,
                ReID movement paths, and side-panel alert context.
              </p>
            </div>

            <div className="flex flex-wrap items-center gap-3">
              <span
                className={`inline-flex items-center rounded-full border px-3 py-2 text-xs font-semibold uppercase tracking-[0.24em] ${connectionBadgeClass}`}
              >
                WS {connectionState}
              </span>
              <span className="rounded-full border border-white/10 bg-white/5 px-3 py-2 text-xs uppercase tracking-[0.24em] text-slate-300">
                Last packet {formatCompactTime(lastPacketAt)}
              </span>
              <button
                type="button"
                onClick={() => loadDashboardData(true).catch((error) => setErrorText(errorMessage(error)))}
                className="rounded-full border border-cyan-400/30 bg-cyan-400/10 px-4 py-2 text-xs font-semibold uppercase tracking-[0.24em] text-cyan-100 transition hover:bg-cyan-400/20"
              >
                {refreshing ? "Refreshing" : "Refresh"}
              </button>
              <button
                type="button"
                onClick={() => setEditMode((value) => !value)}
                className={`rounded-full border px-4 py-2 text-xs font-semibold uppercase tracking-[0.24em] transition ${
                  editMode
                    ? "border-amber-400/40 bg-amber-400/12 text-amber-100"
                    : "border-white/10 bg-white/5 text-slate-300 hover:bg-white/10"
                }`}
              >
                {editMode ? "Exit Layout Mode" : "Edit Layout"}
              </button>
              <button
                type="button"
                onClick={persistLayout}
                className="rounded-full border border-white/10 bg-white/5 px-4 py-2 text-xs font-semibold uppercase tracking-[0.24em] text-slate-300 transition hover:bg-white/10"
              >
                Save Layout
              </button>
              <button
                type="button"
                onClick={exportLayoutJson}
                className="rounded-full border border-white/10 bg-white/5 px-4 py-2 text-xs font-semibold uppercase tracking-[0.24em] text-slate-300 transition hover:bg-white/10"
              >
                Export JSON
              </button>
              <button
                type="button"
                onClick={resetLayout}
                className="rounded-full border border-white/10 bg-white/5 px-4 py-2 text-xs font-semibold uppercase tracking-[0.24em] text-slate-300 transition hover:bg-white/10"
              >
                Reset Layout
              </button>
            </div>
          </div>
        </header>

        <section className="grid gap-4 sm:grid-cols-2 xl:grid-cols-4">
          <MetricCard label="Zones Online" value={zoneEntries.length} helper="Backend-generated live layout" />
          <MetricCard label="Threat Zones" value={activeThreatZones} helper="Zones above low severity" />
          <MetricCard label="Live Markers" value={liveMarkerCount} helper="Recent websocket threat detections" />
          <MetricCard label="Active Tracks" value={activeTrackCount} helper={`Last sync ${formatCompactTime(lastSyncedAt)}`} />
        </section>

        {(errorText || layoutNotice) ? (
          <section className="flex flex-col gap-2">
            {errorText ? (
              <div className="rounded-2xl border border-rose-400/25 bg-rose-400/10 px-4 py-3 text-sm text-rose-100">
                {errorText}
              </div>
            ) : null}
            {layoutNotice ? (
              <div className="rounded-2xl border border-cyan-400/25 bg-cyan-400/10 px-4 py-3 text-sm text-cyan-100">
                {layoutNotice}
              </div>
            ) : null}
          </section>
        ) : null}

        <div className="grid flex-1 gap-5 xl:grid-cols-[minmax(0,1fr)_24rem]">
          <section className="rounded-[1.8rem] border border-white/10 bg-white/[0.035] p-4 shadow-glow backdrop-blur">
            <div className="mb-4 flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
              <div>
                <p className="text-[11px] uppercase tracking-[0.32em] text-slate-500">
                  Live Map
                </p>
                <h2 className="mt-2 text-xl font-semibold text-slate-100">
                  Zone, marker, and movement layers
                </h2>
              </div>
              <div className="flex flex-wrap items-center gap-2 text-xs text-slate-400">
                <span className="rounded-full border border-white/10 bg-white/5 px-3 py-1.5">
                  Hover zones for live state
                </span>
                <span className="rounded-full border border-white/10 bg-white/5 px-3 py-1.5">
                  Click markers for alert detail
                </span>
                <span className="rounded-full border border-white/10 bg-white/5 px-3 py-1.5">
                  ReID paths {trajectoryOverlay.length}
                </span>
              </div>
            </div>

            <div
              ref={mapRef}
              className="zone-map-canvas relative min-h-[640px] overflow-hidden rounded-[1.8rem] border border-cyan-400/10 bg-slate-950"
            >
              <div className="zone-map-grid absolute inset-0" />
              <div className="zone-map-glow absolute inset-0" />

              {loading && !zoneEntries.length ? (
                <div className="absolute inset-0 flex items-center justify-center">
                  <div className="rounded-full border border-white/10 bg-white/5 px-5 py-3 text-sm uppercase tracking-[0.28em] text-slate-300">
                    Loading live map
                  </div>
                </div>
              ) : null}

              {!loading && !zoneEntries.length ? (
                <div className="absolute inset-0 flex items-center justify-center px-6 text-center">
                  <div className="max-w-md rounded-[1.4rem] border border-white/10 bg-slate-900/80 px-6 py-6 text-sm text-slate-400">
                    No zones are available yet. Once the backend publishes zone state,
                    layout, or live detections, they will appear here automatically.
                  </div>
                </div>
              ) : null}

              <ZoneLayer
                zoneEntries={zoneEntries}
                layout={layout}
                selectedZoneKey={selectedZoneKey}
                editMode={editMode}
                onSelectZone={setSelectedZoneKey}
                onHoverZone={updateHover}
                onLeaveZone={() => setHoveredZone(null)}
                onStartDrag={startDrag}
              />

              <PathLayer tracks={trajectoryOverlay} />

              {markerEntries.map((marker) => (
                <ThreatMarker
                  key={marker.id}
                  marker={marker}
                  layoutRect={layout[marker.zone_key]}
                  isSelected={selectedMarkerId === marker.id}
                  onSelect={handleSelectMarker}
                />
              ))}

              {hoveredZone && zoneState[hoveredZone.zoneKey] ? (
                <div
                  className="pointer-events-none absolute z-30 w-64 rounded-2xl border border-white/10 bg-slate-950/95 px-4 py-3 shadow-[0_20px_60px_rgba(0,0,0,0.45)] backdrop-blur"
                  style={{
                    left: clamp(hoveredZone.x, 12, 1000),
                    top: clamp(hoveredZone.y, 12, 560),
                  }}
                >
                  <p className="text-[11px] uppercase tracking-[0.32em] text-slate-500">
                    {formatZoneLabel(hoveredZone.zoneKey)}
                  </p>
                  <p className="mt-2 text-base font-semibold text-slate-100">
                    {hoveredZone.zoneKey}
                  </p>
                  <div className="mt-4 grid gap-3 text-sm">
                    <div className="flex items-center justify-between">
                      <span className="text-slate-400">Current severity</span>
                      <span className="font-semibold text-slate-100">
                        {zoneState[hoveredZone.zoneKey]?.severity || "LOW"}
                      </span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-slate-400">Active alerts</span>
                      <span className="font-semibold text-slate-100">
                        {zoneState[hoveredZone.zoneKey]?.alert_count || 0}
                      </span>
                    </div>
                    <div className="flex items-center justify-between">
                      <span className="text-slate-400">Threshold</span>
                      <span className="font-semibold text-slate-100">
                        {zoneState[hoveredZone.zoneKey]?.current_threshold != null
                          ? Number(zoneState[hoveredZone.zoneKey].current_threshold).toFixed(2)
                          : "--"}
                      </span>
                    </div>
                    {hoveredZoneAlert?.explanation?.reason ? (
                      <div className="rounded-xl border border-white/10 bg-white/5 px-3 py-3">
                        <p className="text-[11px] uppercase tracking-[0.24em] text-slate-500">
                          Latest Reason
                        </p>
                        <p className="mt-2 text-sm text-slate-200">
                          {hoveredZoneAlert.explanation.reason}
                        </p>
                      </div>
                    ) : null}
                  </div>
                </div>
              ) : null}
            </div>
          </section>

          <SidePanel
            selectedZone={selectedZone}
            selectedZoneKey={selectedZoneKeyDeferred}
            zoneState={zoneState}
            policyAccess={policyAccess}
            policyForm={policyForm}
            onPolicyFormChange={handlePolicyFormChange}
            onApplyPolicy={applyPolicy}
            policySaving={policySaving}
            selectedDetections={selectedDetections}
            selectedAlerts={selectedAlerts}
            expandedAlertId={expandedAlertId}
            onToggleAlert={(alertId) => setExpandedAlertId((current) => (current === alertId ? "" : alertId))}
            selectedMarker={selectedMarker}
            selectedMarkerAlert={selectedMarkerAlert}
            selectedIncidentId={selectedIncidentId}
            incidentResponse={incidentResponse}
            incidentResponseLoading={incidentResponseLoading}
            sosActionLoading={sosActionLoading}
            sosError={sosError}
            onTriggerPolice={() => handleSosAction("dispatch", ["police"])}
            onCallAmbulance={() => handleSosAction("manual", ["hospital"])}
            onTriggerFire={() => handleSosAction("manual", ["fire"])}
            onCancelSos={() => handleSosAction("cancel", [])}
            heatmapDetails={selectedZoneHeat}
            selectedZoneTracks={selectedZoneTracks}
            selectedTrack={selectedTrack}
            highRiskTracks={highRiskTracks}
            trackPathLoading={trackPathLoading}
            trackProfileLoading={trackProfileLoading}
            onSelectTrack={handleSelectTrack}
            onViewEvidence={openEvidence}
            evidenceLoadingAlertId={evidenceModal.loading ? evidenceModal.alertId : ""}
            feedbackLoadingAlertId={feedbackLoadingAlertId}
            fpModelStatus={modelStatus}
            onConfirmThreat={(alertId) => handleAlertFeedback(alertId, "true")}
            onMarkFalsePositive={(alertId) => handleAlertFeedback(alertId, "false")}
          />
        </div>
        <EvidenceModal
          state={evidenceModal}
          onClose={closeEvidenceModal}
          onRefresh={() => loadEvidenceForAlert(evidenceModal.alertId)}
        />
      </div>
    </div>
  );
}
