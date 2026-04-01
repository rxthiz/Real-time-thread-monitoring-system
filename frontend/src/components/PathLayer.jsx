import { severityStyle } from "../lib/severity";

function segmentOpacity(index, total, emphasis) {
  const base = total <= 1 ? 1 : (index + 1) / total;
  return Math.max(0.12, base * emphasis);
}

export default function PathLayer({ tracks }) {
  const overlays = Array.isArray(tracks) ? tracks : [];
  if (!overlays.length) {
    return null;
  }

  return (
    <svg
      className="pointer-events-none absolute inset-0 z-10 h-full w-full overflow-visible"
      viewBox="0 0 100 100"
      preserveAspectRatio="none"
      aria-hidden="true"
    >
      {overlays.map((track) => {
        const palette = severityStyle(track.severity);
        const emphasis = track.isSelected ? 1 : track.isZoneMatch ? 0.82 : 0.52;
        return (
          <g key={track.track_id} opacity={track.opacity}>
            {track.points.slice(1).map((point, index) => {
              const prev = track.points[index];
              if (!prev) {
                return null;
              }
              const opacity = segmentOpacity(index, track.points.length - 1, emphasis);
              return (
                <line
                  key={`${track.track_id}-seg-${index}`}
                  x1={prev.map_x}
                  y1={prev.map_y}
                  x2={point.map_x}
                  y2={point.map_y}
                  stroke={palette.accent}
                  strokeWidth={track.stroke_width}
                  strokeLinecap="round"
                  opacity={opacity}
                  className="trajectory-flow"
                />
              );
            })}

            {track.points.map((point, index) => {
              const isLast = index === track.points.length - 1;
              return (
                <circle
                  key={`${track.track_id}-${point.zone_key}-${point.ts || index}-${index}`}
                  cx={point.map_x}
                  cy={point.map_y}
                  r={isLast ? 0.44 : 0.16}
                  fill={isLast ? palette.accent : palette.text}
                  opacity={isLast ? 1 : segmentOpacity(index, track.points.length, 0.9)}
                />
              );
            })}

            {track.last_point ? (
              <circle
                className="trajectory-ping"
                cx={track.last_point.map_x}
                cy={track.last_point.map_y}
                r={track.isSelected ? 1.45 : 1.0}
                fill={palette.glow}
              />
            ) : null}

            {track.isSelected && track.last_point ? (
              <text
                x={Math.min(96, track.last_point.map_x + 1.2)}
                y={Math.max(4, track.last_point.map_y - 1.1)}
                fill={palette.text}
                fontSize="2.2"
                fontWeight="600"
                letterSpacing="0.08em"
              >
                {track.track_id}
              </text>
            ) : null}

            {track.predictive?.risk_score > 0 ? (
              <g>
                <title>{track.predictive.reason || `Predictive risk ${(track.predictive.risk_score * 100).toFixed(0)}%`}</title>
                <rect
                  x={Math.min(92, track.last_point.map_x + 0.65)}
                  y={Math.max(2.2, track.last_point.map_y + 0.5)}
                  rx="1.2"
                  ry="1.2"
                  width={track.predictive.pre_alert ? 8.6 : 7.3}
                  height="3.5"
                  fill={palette.fill}
                  stroke={palette.accent}
                  strokeWidth="0.18"
                  opacity={0.96}
                />
                <text
                  x={Math.min(95.8, track.last_point.map_x + 1.05)}
                  y={Math.max(4.65, track.last_point.map_y + 2.78)}
                  fill={palette.text}
                  fontSize="1.85"
                  fontWeight="700"
                  letterSpacing="0.06em"
                >
                  {`${Math.round(track.predictive.risk_score * 100)}%`}
                </text>
              </g>
            ) : null}
          </g>
        );
      })}
    </svg>
  );
}
