import { severityStyle } from "../lib/severity";
import { formatCompactTime, formatZoneLabel } from "./zoneDashboardUtils";
import { SeverityBadge } from "./DashboardPrimitives";

export default function ZoneLayer({
  zoneEntries,
  layout,
  selectedZoneKey,
  editMode,
  onSelectZone,
  onHoverZone,
  onLeaveZone,
  onStartDrag,
}) {
  return (
    <>
      {zoneEntries.map(([zoneKey, zone]) => {
        const rect = layout[zoneKey] || {
          x: 4,
          y: 4,
          width: 20,
          height: 20,
        };
        const palette = severityStyle(zone.severity);
        const isSelected = zoneKey === selectedZoneKey;
        const isThreat = zone.severity && zone.severity !== "LOW";
        const hasRealtimeTarget = Boolean(zone.recent_packet?.detections?.length);
        const heatOpacity = 0.14 + (zone.heat_ratio || 0) * 0.62;

        return (
          <button
            key={zoneKey}
            type="button"
            onClick={() => onSelectZone(zoneKey)}
            onMouseEnter={(event) => onHoverZone(zoneKey, event)}
            onMouseMove={(event) => onHoverZone(zoneKey, event)}
            onMouseLeave={onLeaveZone}
            onPointerDown={(event) => onStartDrag(zoneKey, event)}
            className={`group absolute overflow-hidden rounded-[1.25rem] border text-left transition duration-200 ${
              isThreat ? "zone-threat-border" : ""
            } ${editMode ? "cursor-grab active:cursor-grabbing" : "cursor-pointer"} ${
              isSelected ? "scale-[1.01]" : "hover:scale-[1.01]"
            }`}
            style={{
              left: `${rect.x}%`,
              top: `${rect.y}%`,
              width: `${rect.width}%`,
              height: `${rect.height}%`,
              borderColor: `${palette.accent}99`,
              background:
                "linear-gradient(180deg, rgba(8, 16, 24, 0.96) 0%, rgba(4, 10, 18, 0.98) 100%)",
              boxShadow: isSelected
                ? `0 0 0 1px ${palette.accent}, 0 0 34px ${palette.glow}`
                : "0 0 0 1px rgba(255,255,255,0.04), 0 18px 40px rgba(0,0,0,0.34)",
            }}
          >
            <span
              className="absolute inset-0"
              style={{
                background: `radial-gradient(circle at 50% 45%, ${palette.glow} 0%, rgba(0, 0, 0, 0) 72%)`,
                opacity: heatOpacity,
              }}
            />
            <span className="absolute inset-x-0 top-0 h-1" style={{ backgroundColor: palette.accent }} />
            {hasRealtimeTarget ? (
              <span className="zone-threat-dot absolute" style={{ backgroundColor: palette.accent }} />
            ) : null}

            <div className="relative flex h-full flex-col justify-between p-4">
              <div className="flex items-start justify-between gap-3">
                <div>
                  <p className="text-[11px] uppercase tracking-[0.34em] text-slate-500">
                    {formatZoneLabel(zoneKey)}
                  </p>
                  <h3 className="mt-2 text-lg font-semibold text-slate-100">{zoneKey}</h3>
                </div>
                <SeverityBadge level={zone.severity} />
              </div>

              <div className="grid grid-cols-2 gap-3 text-sm">
                <div>
                  <p className="text-[11px] uppercase tracking-[0.28em] text-slate-500">
                    Active Alerts
                  </p>
                  <p className="mt-2 text-xl font-semibold text-slate-100">{zone.alert_count}</p>
                </div>
                <div>
                  <p className="text-[11px] uppercase tracking-[0.28em] text-slate-500">
                    Threshold
                  </p>
                  <p className="mt-2 text-xl font-semibold text-slate-100">
                    {zone.current_threshold != null ? Number(zone.current_threshold).toFixed(2) : "--"}
                  </p>
                </div>
              </div>

              <div className="flex items-center justify-between text-xs text-slate-400">
                <span>Heat load {zone.heat_count}</span>
                <span>{formatCompactTime(zone.last_updated)}</span>
              </div>
            </div>
          </button>
        );
      })}
    </>
  );
}
