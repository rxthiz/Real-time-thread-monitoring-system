import { buildApiUrl } from "../lib/api";
import { formatTimestamp } from "./zoneDashboardUtils";

function normalizeEvidencePayload(state) {
  const payload = state?.payload && typeof state.payload === "object" ? state.payload : {};
  const nested = payload?.evidence_clip && typeof payload.evidence_clip === "object" ? payload.evidence_clip : {};
  const alertId = state?.alertId || payload?.alert_id || "";
  const clipPath = nested.path || payload.clip_path || null;
  const status = nested.status || payload.status || (clipPath ? "ready" : "not_requested");
  const downloadUrl =
    nested.download_url ||
    payload.download_url ||
    (clipPath && alertId ? `/api/alerts/${encodeURIComponent(alertId)}/evidence?download=1` : null);
  const thumbnailUrl =
    nested.thumbnail_url ||
    payload.thumbnail_url ||
    (nested.thumbnail_path && alertId ? `/api/alerts/${encodeURIComponent(alertId)}/evidence?thumbnail=1` : null);

  return {
    alertId,
    clipPath,
    status,
    duration: nested.duration ?? payload.duration ?? null,
    frames: nested.frames ?? payload.frame_count ?? null,
    createdAt: nested.created_at || payload.created_at || null,
    sha256: nested.sha256 || payload.sha256 || null,
    error: nested.error || payload.error || null,
    downloadUrl,
    thumbnailUrl,
  };
}

export default function EvidenceModal({ state, onClose, onRefresh }) {
  if (!state?.open) {
    return null;
  }

  const evidence = normalizeEvidencePayload(state);
  const videoUrl = evidence.downloadUrl ? buildApiUrl(evidence.downloadUrl) : "";
  const posterUrl = evidence.thumbnailUrl ? buildApiUrl(evidence.thumbnailUrl) : undefined;

  return (
    <div className="fixed inset-0 z-[80] flex items-center justify-center bg-slate-950/80 px-4 py-6 backdrop-blur-sm">
      <div className="absolute inset-0" onClick={onClose} aria-hidden="true" />
      <section className="relative z-[81] w-full max-w-4xl rounded-[1.8rem] border border-white/10 bg-slate-950/95 p-5 shadow-[0_28px_90px_rgba(0,0,0,0.6)]">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div>
            <p className="text-[11px] uppercase tracking-[0.32em] text-slate-500">
              Evidence Clip
            </p>
            <h2 className="mt-2 text-xl font-semibold text-slate-100">
              {evidence.alertId || "Alert Evidence"}
            </h2>
            <p className="mt-2 text-sm text-slate-400">
              Pre-event and post-event incident capture for evidence review.
            </p>
          </div>
          <div className="flex items-center gap-2">
            <button
              type="button"
              onClick={onRefresh}
              className="rounded-full border border-cyan-400/25 bg-cyan-400/10 px-4 py-2 text-xs font-semibold uppercase tracking-[0.22em] text-cyan-100 transition hover:bg-cyan-400/20"
            >
              Refresh
            </button>
            <button
              type="button"
              onClick={onClose}
              className="rounded-full border border-white/10 bg-white/5 px-4 py-2 text-xs font-semibold uppercase tracking-[0.22em] text-slate-300 transition hover:bg-white/10"
            >
              Close
            </button>
          </div>
        </div>

        <div className="mt-5">
          {state.loading ? (
            <div className="rounded-[1.4rem] border border-white/10 bg-white/5 px-5 py-10 text-center text-sm text-slate-400">
              Loading evidence metadata...
            </div>
          ) : state.error ? (
            <div className="rounded-[1.4rem] border border-rose-400/20 bg-rose-400/10 px-5 py-8 text-sm text-rose-100">
              {state.error}
            </div>
          ) : evidence.status !== "ready" || !videoUrl ? (
            <div className="rounded-[1.4rem] border border-white/10 bg-white/5 px-5 py-8">
              <p className="text-sm font-semibold uppercase tracking-[0.24em] text-slate-300">
                Status: {String(evidence.status || "unknown").replace(/_/g, " ")}
              </p>
              {evidence.error ? (
                <p className="mt-3 text-sm text-rose-200">{evidence.error}</p>
              ) : (
                <p className="mt-3 text-sm text-slate-400">
                  The clip is not ready yet. Use refresh to check the latest recorder state.
                </p>
              )}
            </div>
          ) : (
            <div className="grid gap-4">
              <video
                controls
                autoPlay
                crossOrigin="use-credentials"
                poster={posterUrl}
                className="w-full rounded-[1.4rem] border border-white/10 bg-black"
                src={videoUrl}
              />
              <div className="grid gap-3 md:grid-cols-2 xl:grid-cols-4">
                <div className="rounded-2xl border border-white/10 bg-white/5 px-4 py-3">
                  <p className="text-[11px] uppercase tracking-[0.22em] text-slate-500">Created</p>
                  <p className="mt-2 text-sm font-semibold text-slate-100">{formatTimestamp(evidence.createdAt)}</p>
                </div>
                <div className="rounded-2xl border border-white/10 bg-white/5 px-4 py-3">
                  <p className="text-[11px] uppercase tracking-[0.22em] text-slate-500">Duration</p>
                  <p className="mt-2 text-sm font-semibold text-slate-100">
                    {evidence.duration != null ? `${Number(evidence.duration).toFixed(1)}s` : "--"}
                  </p>
                </div>
                <div className="rounded-2xl border border-white/10 bg-white/5 px-4 py-3">
                  <p className="text-[11px] uppercase tracking-[0.22em] text-slate-500">Frames</p>
                  <p className="mt-2 text-sm font-semibold text-slate-100">{evidence.frames ?? "--"}</p>
                </div>
                <div className="rounded-2xl border border-white/10 bg-white/5 px-4 py-3">
                  <p className="text-[11px] uppercase tracking-[0.22em] text-slate-500">Integrity</p>
                  <p className="mt-2 break-all text-xs text-slate-300">{evidence.sha256 || "--"}</p>
                </div>
              </div>
            </div>
          )}
        </div>
      </section>
    </div>
  );
}
