import { normalizeSeverity, severityStyle } from "../lib/severity";

export function SeverityBadge({ level }) {
  const palette = severityStyle(level);
  return (
    <span
      className="inline-flex items-center rounded-full border px-2.5 py-1 text-[11px] font-semibold uppercase tracking-[0.24em]"
      style={{
        color: palette.text,
        borderColor: `${palette.accent}55`,
        backgroundColor: palette.fill,
      }}
    >
      {normalizeSeverity(level)}
    </span>
  );
}

export function MetricCard({ label, value, helper }) {
  return (
    <article className="rounded-2xl border border-white/10 bg-white/5 px-4 py-4 shadow-glow">
      <p className="text-[11px] uppercase tracking-[0.3em] text-slate-400">
        {label}
      </p>
      <p className="mt-3 text-2xl font-semibold text-slate-100">{value}</p>
      <p className="mt-1 text-xs text-slate-500">{helper}</p>
    </article>
  );
}
