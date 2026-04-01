import { severityStyle } from "../lib/severity";
import { formatCompactTime, toNumber } from "./zoneDashboardUtils";
import { SeverityBadge } from "./DashboardPrimitives";

const FEATURE_COLORS = ["#22c55e", "#06b6d4", "#f59e0b", "#ef4444", "#a855f7"];

function humanizeKey(value) {
  return String(value || "")
    .replace(/_/g, " ")
    .replace(/\b\w/g, (token) => token.toUpperCase());
}

function explanationPayload(alert) {
  return alert?.explanation && typeof alert.explanation === "object"
    ? alert.explanation
    : alert?.event?.explanation && typeof alert.event.explanation === "object"
      ? alert.event.explanation
      : {};
}

function filterPayload(alert) {
  if (alert?.fp_filter && typeof alert.fp_filter === "object") {
    return alert.fp_filter;
  }
  const explanation = explanationPayload(alert);
  return explanation?.false_positive_filter && typeof explanation.false_positive_filter === "object"
    ? explanation.false_positive_filter
    : null;
}

function feedbackPayload(alert) {
  if (alert?.false_positive_feedback && typeof alert.false_positive_feedback === "object") {
    return alert.false_positive_feedback;
  }
  const filter = filterPayload(alert);
  return filter?.feedback && typeof filter.feedback === "object" ? filter.feedback : null;
}

function decisionTone(decision) {
  switch (String(decision || "").trim().toLowerCase()) {
    case "accepted":
      return "border-emerald-400/25 bg-emerald-400/10 text-emerald-100";
    case "uncertain":
      return "border-amber-300/30 bg-amber-300/10 text-amber-50";
    case "rejected":
      return "border-rose-400/25 bg-rose-400/10 text-rose-100";
    default:
      return "border-white/10 bg-white/5 text-slate-300";
  }
}

function evidencePayload(alert) {
  const nested = alert?.evidence_clip && typeof alert.evidence_clip === "object" ? alert.evidence_clip : {};
  const severity = String(alert?.severity || alert?.event?.level || "").toUpperCase();
  const path = nested.path || alert?.evidence_clip_path || null;
  const status =
    nested.status ||
    alert?.evidence_status ||
    (path ? "ready" : ["HIGH", "CRITICAL"].includes(severity) ? "processing" : "not_requested");

  return {
    path,
    status,
    duration: nested.duration ?? alert?.clip_duration ?? null,
    frames: nested.frames ?? alert?.frame_count ?? null,
    created_at: nested.created_at || alert?.evidence_created_at || null,
    thumbnail_url: nested.thumbnail_url || null,
    error: nested.error || alert?.evidence_error || null,
  };
}

export function ConfidenceBar({ label, value, accentColor, helper = "" }) {
  const safeValue = Math.max(0, Math.min(1, toNumber(value, 0)));
  return (
    <div className="grid gap-2">
      <div className="flex items-center justify-between gap-3 text-xs uppercase tracking-[0.18em] text-slate-500">
        <span>{label}</span>
        <span className="text-slate-300">{(safeValue * 100).toFixed(1)}%</span>
      </div>
      <div className="h-2 rounded-full bg-white/5">
        <div
          className="h-2 rounded-full transition-all"
          style={{
            width: `${Math.max(4, safeValue * 100)}%`,
            backgroundColor: accentColor,
            boxShadow: `0 0 18px ${accentColor}33`,
          }}
        />
      </div>
      {helper ? <p className="text-xs text-slate-500">{helper}</p> : null}
    </div>
  );
}

export function FeatureImportanceChart({ items }) {
  const features = Array.isArray(items) ? items.filter((item) => toNumber(item?.importance, 0) > 0) : [];
  if (!features.length) {
    return (
      <div className="rounded-2xl border border-dashed border-white/10 px-3 py-4 text-sm text-slate-500">
        No feature contribution data.
      </div>
    );
  }

  let cursor = 0;
  const slices = features.map((item, index) => {
    const share = Math.max(0, Math.min(1, toNumber(item.importance, 0)));
    const start = cursor;
    cursor += share * 360;
    return {
      ...item,
      color: FEATURE_COLORS[index % FEATURE_COLORS.length],
      start,
      end: cursor,
    };
  });
  const gradient = slices
    .map((slice) => `${slice.color} ${slice.start}deg ${slice.end}deg`)
    .join(", ");

  return (
    <div className="grid gap-4 md:grid-cols-[6rem_minmax(0,1fr)] md:items-center">
      <div
        className="mx-auto h-24 w-24 rounded-full border border-white/10"
        style={{
          background: `conic-gradient(${gradient})`,
          boxShadow: "inset 0 0 0 14px rgba(2, 6, 23, 0.95)",
        }}
      />
      <div className="grid gap-2">
        {slices.map((slice) => (
          <div key={slice.feature} className="flex items-center justify-between gap-3 text-sm">
            <div className="flex min-w-0 items-center gap-2">
              <span
                className="h-2.5 w-2.5 rounded-full"
                style={{ backgroundColor: slice.color }}
              />
              <span className="truncate text-slate-300">{humanizeKey(slice.feature)}</span>
            </div>
            <span className="text-slate-500">{(toNumber(slice.importance, 0) * 100).toFixed(0)}%</span>
          </div>
        ))}
      </div>
    </div>
  );
}

export function AlertExplanationCard({
  alert,
  expanded = false,
  onToggle,
  onViewEvidence,
  evidenceLoading = false,
  feedbackLoading = false,
  onConfirmThreat,
  onMarkFalsePositive,
}) {
  const alertType = String(alert?.alert_type || "").trim().toUpperCase();
  const explanation = explanationPayload(alert);
  const fpFilter = filterPayload(alert);
  const feedback = feedbackPayload(alert);
  const fpDecision = String(fpFilter?.decision || "").trim().toLowerCase();
  const severity = alert?.severity || alert?.event?.level || explanation?.severity || "LOW";
  const palette = severityStyle(severity);
  const finalScore = toNumber(fpFilter?.final_score, toNumber(explanation?.final_score, alert?.event?.score));
  const threatProbability = fpFilter?.threat_probability != null ? toNumber(fpFilter?.threat_probability, 0) : null;
  const detectorScore = toNumber(fpFilter?.model_confidence, toNumber(alert?.confidence, alert?.event?.score));
  const thresholds = fpFilter?.thresholds && typeof fpFilter.thresholds === "object" ? fpFilter.thresholds : null;
  const reason = String(fpFilter?.reason || explanation?.reason || alert?.event?.reason || "Threat conditions met").trim();
  const summary = String(explanation?.summary || "").trim();
  const modelBreakdown = explanation?.model_breakdown && typeof explanation.model_breakdown === "object"
    ? Object.entries(explanation.model_breakdown)
    : [];
  const factors = Array.isArray(explanation?.factors) ? explanation.factors : [];
  const featureImportance = Array.isArray(fpFilter?.feature_importance)
    ? fpFilter.feature_importance
    : Array.isArray(explanation?.feature_importance)
      ? explanation.feature_importance
      : [];
  const evidence = evidencePayload(alert);
  const showEvidenceButton =
    Boolean(onViewEvidence) &&
    Boolean(alert?.alert_id) &&
    alertType !== "PREDICTIVE_ALERT" &&
    (Boolean(evidence.path) || evidence.status !== "not_requested" || ["HIGH", "CRITICAL"].includes(String(severity).toUpperCase()));
  const evidenceButtonLabel = evidence.path
    ? "View Evidence"
    : evidence.status === "failed"
      ? "Evidence Error"
      : evidence.status === "processing"
        ? "Evidence Pending"
        : "View Evidence";
  const canLabelAlert = Boolean(alert?.alert_id) && (Boolean(onConfirmThreat) || Boolean(onMarkFalsePositive));
  const feedbackLabel = feedback?.label ? humanizeKey(feedback.label) : "";

  return (
    <article
      title={reason}
      className="rounded-2xl border border-white/10 bg-slate-950/70 px-4 py-4"
    >
      <div className="flex items-start justify-between gap-3">
        <div>
          <p className="text-sm font-semibold text-slate-100">{alert?.alert_id || "Alert"}</p>
          <p className="mt-1 text-xs text-slate-500">{formatCompactTime(alert?.timestamp)}</p>
        </div>
        <SeverityBadge level={severity} />
      </div>

      <p className="mt-4 text-sm font-medium text-slate-100">Reason: {reason}</p>
      {summary ? <p className="mt-2 text-sm text-slate-400">{summary}</p> : null}

      {fpFilter ? (
        <div className="mt-4 flex flex-wrap items-center gap-2">
          <span className={`rounded-full border px-3 py-1 text-[11px] font-semibold uppercase tracking-[0.22em] ${decisionTone(fpDecision)}`}>
            {fpDecision ? humanizeKey(fpDecision) : "Accepted"}
          </span>
          {alertType === "OPERATOR_REVIEW_ALERT" ? (
            <span className="rounded-full border border-amber-300/30 bg-amber-300/10 px-3 py-1 text-[11px] font-semibold uppercase tracking-[0.22em] text-amber-50">
              Operator Review
            </span>
          ) : null}
          {feedbackLabel ? (
            <span className="rounded-full border border-cyan-400/25 bg-cyan-400/10 px-3 py-1 text-[11px] font-semibold uppercase tracking-[0.22em] text-cyan-100">
              Feedback {feedbackLabel}
            </span>
          ) : null}
        </div>
      ) : null}

      <div className="mt-4">
        <ConfidenceBar
          label="Final Threat Score"
          value={finalScore}
          accentColor={palette.accent}
          helper={`Final score ${(finalScore * 100).toFixed(1)}%`}
        />
      </div>

      {threatProbability != null ? (
        <div className="mt-4">
          <ConfidenceBar
            label="Threat Probability"
            value={threatProbability}
            accentColor="#f59e0b"
            helper={
              thresholds
                ? `Accept ${(toNumber(thresholds.accept, 0) * 100).toFixed(0)}% | Review ${(toNumber(thresholds.uncertain, 0) * 100).toFixed(0)}%`
                : "ML classifier output"
            }
          />
        </div>
      ) : null}

      {fpFilter ? (
        <div className="mt-4">
          <ConfidenceBar
            label="Detector Confidence"
            value={detectorScore}
            accentColor="#06b6d4"
            helper={`Raw detector score ${(detectorScore * 100).toFixed(1)}%`}
          />
        </div>
      ) : null}

      <div className="mt-4 flex items-center justify-between gap-3 text-xs text-slate-500">
        <span>
          {humanizeKey(alert?.top_weapon || alert?.event?.weapon || "Threat")}
          {evidence.duration != null ? ` | Clip ${Number(evidence.duration).toFixed(1)}s` : ""}
        </span>
        <div className="flex flex-wrap items-center justify-end gap-2">
          {showEvidenceButton ? (
            <button
              type="button"
              onClick={() => onViewEvidence?.(alert)}
              disabled={evidenceLoading}
              className="rounded-full border border-cyan-400/25 bg-cyan-400/10 px-3 py-1.5 font-semibold uppercase tracking-[0.2em] text-cyan-100 transition hover:bg-cyan-400/20 disabled:cursor-not-allowed disabled:border-white/10 disabled:bg-white/5 disabled:text-slate-500"
            >
              {evidenceLoading ? "Loading" : evidenceButtonLabel}
            </button>
          ) : null}
          {canLabelAlert ? (
            <button
              type="button"
              onClick={() => onConfirmThreat?.(alert?.alert_id)}
              disabled={feedbackLoading}
              className={`rounded-full border px-3 py-1.5 font-semibold uppercase tracking-[0.2em] transition ${
                feedback?.label === "true"
                  ? "border-emerald-400/35 bg-emerald-400/15 text-emerald-50"
                  : "border-emerald-400/25 bg-emerald-400/10 text-emerald-100 hover:bg-emerald-400/20"
              } disabled:cursor-not-allowed disabled:border-white/10 disabled:bg-white/5 disabled:text-slate-500`}
            >
              {feedbackLoading && feedback?.label !== "true" ? "Saving" : feedback?.label === "true" ? "Threat Confirmed" : "Confirm Threat"}
            </button>
          ) : null}
          {canLabelAlert ? (
            <button
              type="button"
              onClick={() => onMarkFalsePositive?.(alert?.alert_id)}
              disabled={feedbackLoading}
              className={`rounded-full border px-3 py-1.5 font-semibold uppercase tracking-[0.2em] transition ${
                feedback?.label === "false"
                  ? "border-rose-400/35 bg-rose-400/15 text-rose-50"
                  : "border-rose-400/25 bg-rose-400/10 text-rose-100 hover:bg-rose-400/20"
              } disabled:cursor-not-allowed disabled:border-white/10 disabled:bg-white/5 disabled:text-slate-500`}
            >
              {feedbackLoading && feedback?.label !== "false" ? "Saving" : feedback?.label === "false" ? "Marked False" : "Mark False Positive"}
            </button>
          ) : null}
          <button
            type="button"
            onClick={onToggle}
            className="rounded-full border border-white/10 bg-white/5 px-3 py-1.5 font-semibold uppercase tracking-[0.2em] text-slate-300 transition hover:bg-white/10"
          >
            {expanded ? "Hide XAI" : "Show XAI"}
          </button>
        </div>
      </div>

      {expanded && (
        <div className="mt-4 grid gap-4 border-t border-white/10 pt-4">
          {fpFilter ? (
            <div className="rounded-2xl border border-white/10 bg-white/5 px-4 py-4">
              <div className="flex items-start justify-between gap-3">
                <div>
                  <p className="text-[11px] uppercase tracking-[0.28em] text-slate-500">
                    False Positive Filter
                  </p>
                  <p className="mt-2 text-sm text-slate-300">{reason}</p>
                </div>
                <span className={`rounded-full border px-3 py-1 text-[11px] font-semibold uppercase tracking-[0.22em] ${decisionTone(fpDecision)}`}>
                  {fpDecision ? humanizeKey(fpDecision) : "Accepted"}
                </span>
              </div>
              {feedbackLabel ? (
                <p className="mt-3 text-xs uppercase tracking-[0.2em] text-cyan-200/80">
                  Operator feedback: {feedbackLabel}
                </p>
              ) : null}
            </div>
          ) : null}

          <div className="grid gap-3">
            <p className="text-[11px] uppercase tracking-[0.28em] text-slate-500">
              Model Breakdown
            </p>
            {modelBreakdown.length ? (
              modelBreakdown.map(([key, value]) => (
                <ConfidenceBar
                  key={key}
                  label={humanizeKey(key)}
                  value={toNumber(value, 0)}
                  accentColor={palette.accent}
                />
              ))
            ) : (
              <p className="text-sm text-slate-500">No model breakdown available.</p>
            )}
          </div>

          <div className="grid gap-3">
            <p className="text-[11px] uppercase tracking-[0.28em] text-slate-500">
              Feature Importance
            </p>
            <FeatureImportanceChart items={featureImportance} />
          </div>

          <div className="grid gap-3">
            <p className="text-[11px] uppercase tracking-[0.28em] text-slate-500">
              Factors
            </p>
            {factors.length ? (
              factors.map((factor) => (
                <div
                  key={`${factor.name}-${factor.value}`}
                  className="flex items-center justify-between gap-3 rounded-xl border border-white/10 bg-white/5 px-3 py-2 text-sm"
                >
                  <span className="text-slate-300">
                    {humanizeKey(factor.name)}: {String(factor.value)}
                  </span>
                  <span className="text-slate-500">
                    {(Math.max(0, toNumber(factor.impact, 0)) * 100).toFixed(0)}%
                  </span>
                </div>
              ))
            ) : (
              <p className="text-sm text-slate-500">No factor list available.</p>
            )}
          </div>
        </div>
      )}
    </article>
  );
}
