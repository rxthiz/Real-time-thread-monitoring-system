import { AlertExplanationCard, ConfidenceBar } from "./XaiPanels";
import { SeverityBadge } from "./DashboardPrimitives";
import { routeLabel, trackSeverity } from "./reidTrajectoryUtils";
import { severityStyle } from "../lib/severity";
import {
  formatCompactTime,
  formatTimestamp,
  formatZoneLabel,
} from "./zoneDashboardUtils";

function formatDurationCompact(seconds) {
  const value = Math.max(0, Number(seconds || 0));
  if (value >= 3600) {
    return `${(value / 3600).toFixed(1)} h`;
  }
  if (value >= 60) {
    return `${(value / 60).toFixed(1)} min`;
  }
  return `${Math.round(value)} s`;
}

function riskLevelFromScore(score) {
  const value = Math.max(0, Math.min(1, Number(score || 0)));
  if (value >= 0.85) {
    return "CRITICAL";
  }
  if (value >= 0.7) {
    return "HIGH";
  }
  if (value >= 0.45) {
    return "MEDIUM";
  }
  return "LOW";
}

function sparklinePath(values, width = 220, height = 56) {
  const points = Array.isArray(values) ? values.slice(-24) : [];
  if (points.length < 2) {
    return "";
  }
  return points
    .map((value, index) => {
      const x = (index / (points.length - 1)) * width;
      const y = height - Math.max(0, Math.min(1, Number(value || 0))) * height;
      return `${index === 0 ? "M" : "L"}${x.toFixed(2)},${y.toFixed(2)}`;
    })
    .join(" ");
}

export default function SidePanel({
  selectedZone,
  selectedZoneKey,
  zoneState,
  policyAccess,
  policyForm,
  onPolicyFormChange,
  onApplyPolicy,
  policySaving,
  selectedDetections,
  selectedAlerts,
  expandedAlertId,
  onToggleAlert,
  selectedMarker,
  selectedMarkerAlert,
  selectedIncidentId,
  incidentResponse,
  incidentResponseLoading,
  sosActionLoading,
  sosError,
  onTriggerPolice,
  onCallAmbulance,
  onTriggerFire,
  onCancelSos,
  heatmapDetails,
  selectedZoneTracks,
  selectedTrack,
  highRiskTracks,
  trackPathLoading,
  trackProfileLoading,
  onSelectTrack,
  onViewEvidence,
  evidenceLoadingAlertId,
  feedbackLoadingAlertId,
  fpModelStatus,
  onConfirmThreat,
  onMarkFalsePositive,
}) {
  const selectedTrackPredictive = selectedTrack?.predictive || null;
  const selectedTrackProfile = selectedTrack?.track_profile || selectedTrackPredictive?.track_profile || null;
  const selectedTrackPredictiveStyle = severityStyle(selectedTrackPredictive?.risk_level);
  const selectedTrackBehaviorStyle = severityStyle(riskLevelFromScore(selectedTrackProfile?.behavior_risk_score));
  const dispatches = Array.isArray(incidentResponse?.dispatches) ? incidentResponse.dispatches : [];
  const escalationSteps = Array.isArray(incidentResponse?.escalation?.steps) ? incidentResponse.escalation.steps : [];
  const latestDispatchStatus = dispatches.length ? dispatches[dispatches.length - 1]?.status : "--";

  return (
    <aside className="grid gap-5">
      <section className="rounded-[1.6rem] border border-white/10 bg-white/[0.035] p-4 shadow-glow backdrop-blur">
        <div className="flex items-center justify-between">
          <div>
            <p className="text-[11px] uppercase tracking-[0.32em] text-slate-500">
              Zone Detail
            </p>
            <h2 className="mt-2 text-xl font-semibold text-slate-100">
              {selectedZoneKey || "Select a zone"}
            </h2>
            {selectedZoneKey ? (
              <p className="mt-1 text-xs text-slate-500">{formatZoneLabel(selectedZoneKey)}</p>
            ) : null}
          </div>
          {selectedZone ? <SeverityBadge level={selectedZone.severity} /> : null}
        </div>

        {selectedZone ? (
          <div className="mt-5 grid gap-5">
            <div className="grid grid-cols-2 gap-3">
              <div className="rounded-2xl border border-white/10 bg-white/5 px-4 py-3">
                <p className="text-[11px] uppercase tracking-[0.28em] text-slate-500">
                  Last Updated
                </p>
                <p className="mt-2 text-sm font-semibold text-slate-100">
                  {formatTimestamp(selectedZone.last_updated)}
                </p>
              </div>
              <div className="rounded-2xl border border-white/10 bg-white/5 px-4 py-3">
                <p className="text-[11px] uppercase tracking-[0.28em] text-slate-500">
                  Alerts In Window
                </p>
                <p className="mt-2 text-2xl font-semibold text-slate-100">
                  {selectedZone.alert_count}
                </p>
              </div>
            </div>

            {heatmapDetails ? (
              <div className="rounded-2xl border border-white/10 bg-white/5 px-4 py-4">
                <div className="flex items-center justify-between gap-3">
                  <div>
                    <p className="text-[11px] uppercase tracking-[0.28em] text-slate-500">
                      Analytics Summary
                    </p>
                    <p className="mt-2 text-sm text-slate-400">
                      Heatmap totals and peak alert period for this zone.
                    </p>
                  </div>
                  <span className="text-xs uppercase tracking-[0.22em] text-slate-500">
                    30 day heatmap
                  </span>
                </div>
                <div className="mt-4 grid grid-cols-2 gap-3 text-sm">
                  <div className="rounded-xl border border-white/10 bg-slate-950/70 px-3 py-3">
                    <p className="text-[11px] uppercase tracking-[0.22em] text-slate-500">
                      Total Alerts
                    </p>
                    <p className="mt-2 text-xl font-semibold text-slate-100">{heatmapDetails.total}</p>
                  </div>
                  <div className="rounded-xl border border-white/10 bg-slate-950/70 px-3 py-3">
                    <p className="text-[11px] uppercase tracking-[0.22em] text-slate-500">
                      Peak Window
                    </p>
                    <p className="mt-2 text-sm font-semibold text-slate-100">
                      {heatmapDetails.peak?.day || "--"} {heatmapDetails.peak?.hour ?? "--"}:00
                    </p>
                  </div>
                </div>
              </div>
            ) : null}

            <div className="rounded-2xl border border-white/10 bg-white/5 px-4 py-4">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-[11px] uppercase tracking-[0.28em] text-slate-500">
                    Threshold Settings
                  </p>
                  <p className="mt-2 text-sm text-slate-400">
                    Current hour policy for the selected zone.
                  </p>
                </div>
                <span className="text-xs uppercase tracking-[0.22em] text-slate-500">
                  {policyAccess === "granted" ? "Editable" : policyAccess === "restricted" ? "Read only" : "Pending"}
                </span>
              </div>

              <form onSubmit={onApplyPolicy} className="mt-4 grid gap-3">
                <div className="grid grid-cols-2 gap-3">
                  <label className="grid gap-2 text-xs uppercase tracking-[0.22em] text-slate-500">
                    Threshold
                    <input
                      value={policyForm.threshold}
                      onChange={(event) => onPolicyFormChange("threshold", event.target.value)}
                      type="number"
                      min="0"
                      max="1"
                      step="0.01"
                      disabled={policyAccess !== "granted" || policySaving}
                      className="rounded-xl border border-white/10 bg-slate-950 px-3 py-2 text-sm text-slate-100 outline-none transition focus:border-cyan-400/40"
                    />
                  </label>

                  <label className="grid gap-2 text-xs uppercase tracking-[0.22em] text-slate-500">
                    Snooze Min
                    <input
                      value={policyForm.snoozeMinutes}
                      onChange={(event) => onPolicyFormChange("snoozeMinutes", event.target.value)}
                      type="number"
                      min="0"
                      max="720"
                      step="1"
                      disabled={policyAccess !== "granted" || policySaving}
                      className="rounded-xl border border-white/10 bg-slate-950 px-3 py-2 text-sm text-slate-100 outline-none transition focus:border-cyan-400/40"
                    />
                  </label>
                </div>

                <div className="flex items-center justify-between gap-3 text-xs text-slate-500">
                  <span>
                    Live threshold {selectedZone.current_threshold != null ? Number(selectedZone.current_threshold).toFixed(2) : "--"}
                  </span>
                  <span>Snoozed {selectedZone.is_snoozed ? "Yes" : "No"}</span>
                </div>

                <button
                  type="submit"
                  disabled={policyAccess !== "granted" || policySaving}
                  className="rounded-xl border border-cyan-400/30 bg-cyan-400/10 px-4 py-2 text-sm font-semibold uppercase tracking-[0.24em] text-cyan-100 transition hover:bg-cyan-400/20 disabled:cursor-not-allowed disabled:border-white/10 disabled:bg-white/5 disabled:text-slate-500"
                >
                  {policySaving ? "Applying" : "Apply Policy"}
                </button>
              </form>
            </div>

            {selectedMarker ? (
              <div className="rounded-2xl border border-rose-400/20 bg-rose-400/10 px-4 py-4">
                <div className="flex items-center justify-between gap-3">
                  <div>
                    <p className="text-[11px] uppercase tracking-[0.28em] text-rose-200/70">
                      Selected Threat
                    </p>
                    <p className="mt-2 text-sm font-semibold text-slate-100">
                      {selectedMarker.label}
                    </p>
                  </div>
                  <SeverityBadge level={selectedMarker.severity} />
                </div>
                <div className="mt-4 grid gap-3">
                  <ConfidenceBar
                    label="Confidence"
                    value={selectedMarker.confidence}
                    accentColor="#fb7185"
                    helper={`Observed ${formatCompactTime(selectedMarker.timestamp)}`}
                  />
                  {selectedMarkerAlert ? (
                    <AlertExplanationCard
                      alert={selectedMarkerAlert}
                      expanded
                      onToggle={() => {}}
                      onViewEvidence={onViewEvidence}
                      evidenceLoading={evidenceLoadingAlertId === selectedMarkerAlert?.alert_id}
                      feedbackLoading={feedbackLoadingAlertId === selectedMarkerAlert?.alert_id}
                      onConfirmThreat={onConfirmThreat}
                      onMarkFalsePositive={onMarkFalsePositive}
                    />
                  ) : selectedMarker?.explanation?.reason ? (
                    <div className="rounded-xl border border-white/10 bg-slate-950/70 px-3 py-3 text-sm text-slate-300">
                      {selectedMarker.explanation.reason}
                    </div>
                  ) : null}
                </div>
              </div>
            ) : null}

            <div className="rounded-2xl border border-amber-300/20 bg-amber-300/10 px-4 py-4">
              <div className="flex items-center justify-between gap-3">
                <div>
                  <p className="text-[11px] uppercase tracking-[0.28em] text-amber-100/70">
                    Emergency Response
                  </p>
                  <p className="mt-2 text-sm font-semibold text-slate-100">
                    {selectedIncidentId || "Select an alert-linked incident"}
                  </p>
                </div>
                <span className="rounded-full border border-white/10 bg-black/20 px-3 py-1.5 text-xs uppercase tracking-[0.2em] text-slate-200">
                  {incidentResponse?.simulation_mode ? "Simulation" : "Live"}
                </span>
              </div>

              <div className="mt-4 grid grid-cols-2 gap-3">
                <button
                  type="button"
                  onClick={onTriggerPolice}
                  disabled={!selectedIncidentId || Boolean(sosActionLoading)}
                  className="rounded-xl border border-amber-200/30 bg-black/20 px-3 py-3 text-xs font-semibold uppercase tracking-[0.22em] text-amber-50 transition hover:bg-black/30 disabled:cursor-not-allowed disabled:border-white/10 disabled:bg-white/5 disabled:text-slate-500"
                >
                  {sosActionLoading === "dispatch" ? "Dispatching" : "Trigger Police"}
                </button>
                <button
                  type="button"
                  onClick={onCallAmbulance}
                  disabled={!selectedIncidentId || Boolean(sosActionLoading)}
                  className="rounded-xl border border-amber-200/30 bg-black/20 px-3 py-3 text-xs font-semibold uppercase tracking-[0.22em] text-amber-50 transition hover:bg-black/30 disabled:cursor-not-allowed disabled:border-white/10 disabled:bg-white/5 disabled:text-slate-500"
                >
                  {sosActionLoading === "manual" ? "Sending" : "Call Ambulance"}
                </button>
                <button
                  type="button"
                  onClick={onTriggerFire}
                  disabled={!selectedIncidentId || Boolean(sosActionLoading)}
                  className="rounded-xl border border-amber-200/30 bg-black/20 px-3 py-3 text-xs font-semibold uppercase tracking-[0.22em] text-amber-50 transition hover:bg-black/30 disabled:cursor-not-allowed disabled:border-white/10 disabled:bg-white/5 disabled:text-slate-500"
                >
                  {sosActionLoading === "manual" ? "Sending" : "Trigger Fire"}
                </button>
                <button
                  type="button"
                  onClick={onCancelSos}
                  disabled={!selectedIncidentId || Boolean(sosActionLoading)}
                  className="rounded-xl border border-white/15 bg-black/20 px-3 py-3 text-xs font-semibold uppercase tracking-[0.22em] text-slate-200 transition hover:bg-black/30 disabled:cursor-not-allowed disabled:border-white/10 disabled:bg-white/5 disabled:text-slate-500"
                >
                  {sosActionLoading === "cancel" ? "Stopping" : "Cancel SOS"}
                </button>
              </div>

              <div className="mt-4 grid gap-2 text-sm text-slate-300">
                <div className="flex items-center justify-between gap-3">
                  <span className="text-slate-400">Services notified</span>
                  <span className="text-slate-100">{dispatches.length}</span>
                </div>
                <div className="flex items-center justify-between gap-3">
                  <span className="text-slate-400">Escalation level</span>
                  <span className="text-slate-100">
                    {escalationSteps.filter((step) => step?.triggered_at).length || 0}
                  </span>
                </div>
                <div className="flex items-center justify-between gap-3">
                  <span className="text-slate-400">Delivery status</span>
                  <span className="text-slate-100">{latestDispatchStatus}</span>
                </div>
              </div>

              {incidentResponseLoading ? (
                <p className="mt-4 text-sm text-slate-400">Loading incident response state...</p>
              ) : null}
              {sosError ? <p className="mt-4 text-sm text-rose-200">{sosError}</p> : null}

              <div className="mt-4 grid gap-2">
                {dispatches.length ? (
                  dispatches.slice(-4).reverse().map((dispatch) => (
                    <div
                      key={`${dispatch.id}-${dispatch.phone}`}
                      className="rounded-xl border border-white/10 bg-black/20 px-3 py-3 text-sm text-slate-300"
                    >
                      <div className="flex items-center justify-between gap-3">
                        <span className="font-semibold text-slate-100">{dispatch.service_name}</span>
                        <span className="text-xs uppercase tracking-[0.2em] text-slate-400">{dispatch.status}</span>
                      </div>
                      <div className="mt-2 flex items-center justify-between gap-3 text-xs text-slate-500">
                        <span>{dispatch.service_type}</span>
                        <span>{dispatch.distance_km != null ? `${Number(dispatch.distance_km).toFixed(1)} km` : "--"}</span>
                      </div>
                    </div>
                  ))
                ) : (
                  <p className="rounded-xl border border-dashed border-white/10 px-3 py-4 text-sm text-slate-500">
                    No SOS dispatches recorded for the selected incident yet.
                  </p>
                )}
              </div>
            </div>

            <div className="rounded-2xl border border-white/10 bg-white/5 px-4 py-4">
              <p className="text-[11px] uppercase tracking-[0.28em] text-slate-500">
                Recent Detections
              </p>
              <div className="mt-4 grid gap-3">
                {selectedDetections.length ? (
                  selectedDetections.map((item, index) => (
                    <div
                      key={`${item.timestamp}-${item.label}-${index}`}
                      title={item.reason || ""}
                      className="rounded-xl border border-white/10 bg-slate-950/70 px-3 py-3"
                    >
                      <div className="flex items-center justify-between gap-3">
                        <p className="font-semibold text-slate-100">{item.label}</p>
                        <SeverityBadge level={item.severity} />
                      </div>
                      {item.reason ? <p className="mt-2 text-sm text-slate-300">{item.reason}</p> : null}
                      {item.score != null ? (
                        <div className="mt-3 h-1.5 rounded-full bg-white/5">
                          <div
                            className="h-1.5 rounded-full bg-cyan-400/80"
                            style={{ width: `${Math.max(6, Math.min(100, Number(item.score) * 100))}%` }}
                          />
                        </div>
                      ) : null}
                      <div className="mt-2 flex items-center justify-between gap-3 text-xs text-slate-500">
                        <span>{formatCompactTime(item.timestamp)}</span>
                        <span>{item.confidence != null ? `${(Number(item.confidence) * 100).toFixed(1)}%` : "No score"}</span>
                      </div>
                      <p className="mt-1 text-xs text-slate-500">Threat ID {item.threat_id}</p>
                    </div>
                  ))
                ) : (
                  <p className="rounded-xl border border-dashed border-white/10 px-3 py-4 text-sm text-slate-500">
                    No recent detections for this zone.
                  </p>
                )}
              </div>
            </div>

            <div className="rounded-2xl border border-white/10 bg-white/5 px-4 py-4">
              <div className="flex items-center justify-between gap-3">
                <p className="text-[11px] uppercase tracking-[0.28em] text-slate-500">
                  Alert History
                </p>
                {fpModelStatus ? (
                  <span className="rounded-full border border-white/10 bg-slate-950/70 px-3 py-1 text-[10px] uppercase tracking-[0.24em] text-slate-400">
                    FP Model {fpModelStatus.trained ? "trained" : "seed"} | {fpModelStatus.sample_count || 0} labels
                  </span>
                ) : null}
              </div>
              <div className="mt-4 grid gap-3">
                {selectedAlerts.length ? (
                  selectedAlerts.map((alert) => (
                    <AlertExplanationCard
                      key={alert.alert_id}
                      alert={alert}
                      expanded={expandedAlertId === alert.alert_id}
                      onToggle={() => onToggleAlert(alert.alert_id)}
                      onViewEvidence={onViewEvidence}
                      evidenceLoading={evidenceLoadingAlertId === alert.alert_id}
                      feedbackLoading={feedbackLoadingAlertId === alert.alert_id}
                      onConfirmThreat={onConfirmThreat}
                      onMarkFalsePositive={onMarkFalsePositive}
                    />
                  ))
                ) : (
                  <p className="rounded-xl border border-dashed border-white/10 px-3 py-4 text-sm text-slate-500">
                    No alerts recorded for this zone in the loaded window.
                  </p>
                )}
              </div>
            </div>
          </div>
        ) : (
          <div className="mt-5 rounded-2xl border border-dashed border-white/10 px-4 py-8 text-sm text-slate-500">
            Select a zone on the map to inspect detections, alerts, threshold controls, and analytics.
          </div>
        )}
      </section>

      <section className="rounded-[1.6rem] border border-white/10 bg-white/[0.035] p-4 shadow-glow backdrop-blur">
        <div className="flex items-center justify-between gap-3">
          <div>
            <p className="text-[11px] uppercase tracking-[0.32em] text-slate-500">
              High Risk Individuals
            </p>
            <h2 className="mt-2 text-lg font-semibold text-slate-100">
              Predictive + memory
            </h2>
          </div>
          <span className="rounded-full border border-white/10 bg-white/5 px-3 py-1.5 text-xs uppercase tracking-[0.24em] text-slate-400">
            {highRiskTracks.length} high risk
          </span>
        </div>

        <div className="mt-4 grid gap-3">
          {highRiskTracks.length ? (
            highRiskTracks.slice(0, 6).map((track) => (
              <button
                key={`predictive-${track.track_id}`}
                type="button"
                onClick={() => onSelectTrack(track.track_id, track.zone_key)}
                title={track.predictive?.reason || ""}
                className={`rounded-2xl border px-3 py-3 text-left transition ${
                  selectedTrack?.track_id === track.track_id
                    ? "border-rose-400/35 bg-rose-400/10"
                    : "border-white/10 bg-slate-950/70 hover:border-white/20 hover:bg-slate-950"
                }`}
              >
                <div className="flex items-start justify-between gap-3">
                  <div>
                    <p className="text-sm font-semibold text-slate-100">{track.track_id}</p>
                    <p className="mt-1 text-xs text-slate-500">{track.predictive?.current_zone || track.zone_key}</p>
                  </div>
                  <SeverityBadge
                    level={
                      Number(track.track_profile?.behavior_risk_score || 0) > Number(track.predictive?.risk_score || 0)
                        ? riskLevelFromScore(track.track_profile?.behavior_risk_score)
                        : track.predictive?.risk_level
                    }
                  />
                </div>
                <div className="mt-3">
                  <ConfidenceBar
                    label="Risk Score"
                    value={
                      Math.max(
                        Number(track.predictive?.risk_score || 0),
                        Number(track.track_profile?.behavior_risk_score || 0),
                      )
                    }
                    accentColor={
                      severityStyle(
                        Number(track.track_profile?.behavior_risk_score || 0) > Number(track.predictive?.risk_score || 0)
                          ? riskLevelFromScore(track.track_profile?.behavior_risk_score)
                          : track.predictive?.risk_level,
                      ).accent
                    }
                    helper={
                      track.track_profile?.behavior_risk_score > 0
                        ? `Behavior ${(Number(track.track_profile.behavior_risk_score) * 100).toFixed(0)}%`
                        : track.predictive?.reason || ""
                    }
                  />
                </div>
              </button>
            ))
          ) : (
            <p className="rounded-2xl border border-dashed border-white/10 px-3 py-4 text-sm text-slate-500">
              No tracked individuals currently exceed the predictive or behavioral risk thresholds.
            </p>
          )}
        </div>
      </section>

      <section className="rounded-[1.6rem] border border-white/10 bg-white/[0.035] p-4 shadow-glow backdrop-blur">
        <div className="flex items-center justify-between gap-3">
          <div>
            <p className="text-[11px] uppercase tracking-[0.32em] text-slate-500">
              ReID Tracks
            </p>
            <h2 className="mt-2 text-lg font-semibold text-slate-100">
              Live movement paths
            </h2>
          </div>
          <span className="rounded-full border border-white/10 bg-white/5 px-3 py-1.5 text-xs uppercase tracking-[0.24em] text-slate-400">
            {selectedZoneKey ? `${selectedZoneTracks.length} in zone` : "Track list"}
          </span>
        </div>

        {selectedTrack ? (
          <div className="mt-4 rounded-2xl border border-cyan-400/20 bg-cyan-400/10 px-4 py-4">
              <div className="flex items-start justify-between gap-3">
                <div>
                  <p className="text-[11px] uppercase tracking-[0.28em] text-cyan-200/70">
                    Selected Track
                  </p>
                  <p className="mt-2 text-sm font-semibold text-slate-100">{selectedTrack.track_id}</p>
                </div>
                <SeverityBadge level={trackSeverity(selectedTrack, zoneState)} />
              </div>
            <div className="mt-4 grid gap-2 text-sm text-slate-300">
              <div className="flex items-center justify-between gap-3">
                <span className="text-slate-400">Route</span>
                <span className="max-w-[12rem] text-right text-slate-100">{routeLabel(selectedTrack)}</span>
              </div>
              <div className="flex items-center justify-between gap-3">
                <span className="text-slate-400">Last seen</span>
                <span className="text-slate-100">{formatCompactTime(selectedTrack.last_seen)}</span>
              </div>
              <div className="flex items-center justify-between gap-3">
                <span className="text-slate-400">Path points</span>
                <span className="text-slate-100">{selectedTrack.path?.length || 0}</span>
              </div>
            </div>
            {selectedTrackPredictive ? (
              <div className="mt-4 grid gap-3">
                <ConfidenceBar
                  label="Predictive Risk"
                  value={selectedTrackPredictive.risk_score}
                  accentColor={selectedTrackPredictiveStyle.accent}
                  helper={selectedTrackPredictive.reason || ""}
                />
                <div className="grid gap-2">
                  {selectedTrackPredictive.factors?.slice(0, 3).map((factor) => (
                    <div
                      key={`${selectedTrack.track_id}-${factor.name}`}
                      className="flex items-center justify-between gap-3 rounded-xl border border-white/10 bg-slate-950/70 px-3 py-2 text-sm"
                    >
                      <span className="text-slate-300">
                        {String(factor.name || "").replace(/_/g, " ")}: {String(factor.value)}
                      </span>
                      <span className="text-slate-500">
                        {(Math.max(0, Number(factor.impact || 0)) * 100).toFixed(0)}%
                      </span>
                    </div>
                  ))}
                </div>
              </div>
            ) : null}
            {selectedTrackProfile ? (
              <div className="mt-4 rounded-2xl border border-white/10 bg-slate-950/70 px-3 py-3">
                <div className="flex items-start justify-between gap-3">
                  <div>
                    <p className="text-[11px] uppercase tracking-[0.24em] text-slate-500">
                      Behavior Memory
                    </p>
                    <p className="mt-1 text-xs text-slate-400">
                      Historical activity profile for this tracked individual.
                    </p>
                  </div>
                  <span
                    className="rounded-full border px-3 py-1 text-[11px] font-semibold uppercase tracking-[0.18em]"
                    style={{
                      borderColor: `${selectedTrackBehaviorStyle.accent}44`,
                      color: selectedTrackBehaviorStyle.accent,
                    }}
                  >
                    {(Number(selectedTrackProfile.behavior_risk_score || 0) * 100).toFixed(0)}%
                  </span>
                </div>

                <div className="mt-4 grid grid-cols-2 gap-3 text-sm">
                  <div className="rounded-xl border border-white/10 bg-black/20 px-3 py-3">
                    <p className="text-[11px] uppercase tracking-[0.18em] text-slate-500">Visits</p>
                    <p className="mt-2 text-lg font-semibold text-slate-100">{selectedTrackProfile.visits}</p>
                  </div>
                  <div className="rounded-xl border border-white/10 bg-black/20 px-3 py-3">
                    <p className="text-[11px] uppercase tracking-[0.18em] text-slate-500">Duration</p>
                    <p className="mt-2 text-lg font-semibold text-slate-100">
                      {formatDurationCompact(selectedTrackProfile.total_duration)}
                    </p>
                  </div>
                  <div className="rounded-xl border border-white/10 bg-black/20 px-3 py-3">
                    <p className="text-[11px] uppercase tracking-[0.18em] text-slate-500">Avg Risk</p>
                    <p className="mt-2 text-lg font-semibold text-slate-100">
                      {(Number(selectedTrackProfile.avg_risk_score || 0) * 100).toFixed(0)}%
                    </p>
                  </div>
                  <div className="rounded-xl border border-white/10 bg-black/20 px-3 py-3">
                    <p className="text-[11px] uppercase tracking-[0.18em] text-slate-500">Max Risk</p>
                    <p className="mt-2 text-lg font-semibold text-slate-100">
                      {(Number(selectedTrackProfile.max_risk_score || 0) * 100).toFixed(0)}%
                    </p>
                  </div>
                </div>

                {selectedTrackProfile.risk_history?.length ? (
                  <div className="mt-4">
                    <div className="flex items-center justify-between gap-3 text-xs uppercase tracking-[0.18em] text-slate-500">
                      <span>Risk Trend</span>
                      <span>{selectedTrackProfile.risk_history.length} points</span>
                    </div>
                    <div className="mt-2 rounded-xl border border-white/10 bg-black/20 px-3 py-3">
                      <svg viewBox="0 0 220 56" className="h-14 w-full">
                        <path
                          d={sparklinePath(selectedTrackProfile.risk_history)}
                          fill="none"
                          stroke={selectedTrackBehaviorStyle.accent}
                          strokeWidth="2.5"
                          strokeLinecap="round"
                          strokeLinejoin="round"
                        />
                      </svg>
                    </div>
                  </div>
                ) : null}

                {selectedTrackProfile.behavior_flags?.length ? (
                  <div className="mt-4 flex flex-wrap gap-2">
                    {selectedTrackProfile.behavior_flags.map((flag) => (
                      <span
                        key={`${selectedTrack.track_id}-${flag}`}
                        className="rounded-full border border-white/10 bg-black/20 px-3 py-1 text-[11px] uppercase tracking-[0.16em] text-slate-300"
                      >
                        {String(flag).replace(/_/g, " ")}
                      </span>
                    ))}
                  </div>
                ) : null}

                <div className="mt-4 grid gap-2 text-sm text-slate-300">
                  <div className="flex items-center justify-between gap-3">
                    <span className="text-slate-400">Current visit</span>
                    <span className="text-slate-100">
                      {formatDurationCompact(selectedTrackProfile.current_visit_duration)}
                    </span>
                  </div>
                  <div className="flex items-center justify-between gap-3">
                    <span className="text-slate-400">Zone trail</span>
                    <span className="max-w-[12rem] text-right text-slate-100">
                      {(selectedTrackProfile.zone_history || []).slice(-4).join(" -> ") || "--"}
                    </span>
                  </div>
                </div>
              </div>
            ) : null}
            <div className="mt-4 flex items-center justify-between gap-3 text-xs text-slate-400">
              <span>{selectedTrack.cameras?.length || 0} cameras</span>
              <span>
                {trackPathLoading || trackProfileLoading
                  ? "Loading path + memory"
                  : "Path + memory ready"}
              </span>
            </div>
          </div>
        ) : null}

        <div className="mt-4 grid gap-3">
          {selectedZoneTracks.length ? (
            selectedZoneTracks.slice(0, 8).map((track) => (
              <button
                key={track.track_id}
                type="button"
                onClick={() => onSelectTrack(track.track_id, track.zone_key)}
                className={`rounded-2xl border px-3 py-3 text-left transition ${
                  selectedTrack?.track_id === track.track_id
                    ? "border-cyan-400/35 bg-cyan-400/10"
                    : "border-white/10 bg-slate-950/70 hover:border-white/20 hover:bg-slate-950"
                }`}
              >
                <div className="flex items-start justify-between gap-3">
                  <div>
                    <p className="text-sm font-semibold text-slate-100">{track.track_id}</p>
                    <p className="mt-1 text-xs text-slate-500">{routeLabel(track)}</p>
                  </div>
                  <SeverityBadge level={trackSeverity(track, zoneState)} />
                </div>
                <div className="mt-3 flex items-center justify-between gap-3 text-xs text-slate-500">
                  <span>
                    {track.track_profile?.behavior_risk_score > 0
                      ? `Behavior ${(Number(track.track_profile.behavior_risk_score) * 100).toFixed(0)}%`
                      : track.predictive?.risk_score > 0
                      ? `Risk ${(Number(track.predictive.risk_score) * 100).toFixed(0)}%`
                      : `${track.path?.length || 0} path points`}
                  </span>
                  <span>{formatCompactTime(track.last_seen)}</span>
                </div>
              </button>
            ))
          ) : (
            <p className="rounded-2xl border border-dashed border-white/10 px-3 py-4 text-sm text-slate-500">
              No active tracks for this zone.
            </p>
          )}
        </div>
      </section>
    </aside>
  );
}
