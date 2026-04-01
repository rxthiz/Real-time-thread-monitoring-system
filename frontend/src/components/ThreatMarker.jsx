import { severityStyle } from "../lib/severity";
import { formatCompactTime } from "./zoneDashboardUtils";

export default function ThreatMarker({
  marker,
  layoutRect,
  isSelected = false,
  onSelect,
}) {
  if (!layoutRect || !marker) {
    return null;
  }

  const palette = severityStyle(marker.severity);
  const left = layoutRect.x + layoutRect.width * marker.x;
  const top = layoutRect.y + layoutRect.height * marker.y;
  const explanation = marker?.explanation?.reason || "";

  return (
    <button
      type="button"
      title={explanation || `${marker.label} ${formatCompactTime(marker.timestamp)}`}
      onClick={() => onSelect?.(marker)}
      className="group absolute z-20 -translate-x-1/2 -translate-y-1/2"
      style={{
        left: `${left}%`,
        top: `${top}%`,
      }}
    >
      <span
        className={`threat-marker-pulse absolute inset-0 rounded-full ${isSelected ? "opacity-100" : "opacity-80"}`}
        style={{
          backgroundColor: palette.glow,
        }}
      />
      <span
        className="absolute left-1/2 top-1/2 h-6 w-6 -translate-x-1/2 -translate-y-1/2 rounded-full border"
        style={{
          borderColor: `${palette.accent}66`,
          backgroundColor: `${palette.fill}`,
          boxShadow: `0 0 18px ${palette.glow}`,
        }}
      />
      <span
        className="relative flex h-3.5 w-3.5 items-center justify-center rounded-full border border-slate-950"
        style={{
          backgroundColor: palette.accent,
          boxShadow: `0 0 16px ${palette.glow}`,
        }}
      />
    </button>
  );
}
