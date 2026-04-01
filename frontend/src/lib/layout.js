const STORAGE_KEY = "zone-map-dashboard-layout-v1";

function clamp(value, min, max) {
  return Math.min(max, Math.max(min, value));
}

function numeric(value, fallback) {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : fallback;
}

export function buildAutoLayout(zoneKeys) {
  const keys = [...zoneKeys].sort();
  if (!keys.length) {
    return {};
  }

  const columns =
    keys.length <= 2 ? 2 : keys.length <= 4 ? 2 : keys.length <= 9 ? 3 : Math.ceil(Math.sqrt(keys.length));
  const rows = Math.ceil(keys.length / columns);
  const gap = 2.4;
  const width = (100 - gap * (columns + 1)) / columns;
  const height = (100 - gap * (rows + 1)) / rows;

  const layout = {};
  keys.forEach((zoneKey, index) => {
    const column = index % columns;
    const row = Math.floor(index / columns);
    layout[zoneKey] = {
      x: gap + column * (width + gap),
      y: gap + row * (height + gap),
      width,
      height,
    };
  });
  return layout;
}

function normalizeRect(rect, fallback) {
  const width = clamp(numeric(rect?.width, fallback.width), 12, 48);
  const height = clamp(numeric(rect?.height, fallback.height), 12, 48);
  return {
    x: clamp(numeric(rect?.x, fallback.x), 0, 100 - width),
    y: clamp(numeric(rect?.y, fallback.y), 0, 100 - height),
    width,
    height,
  };
}

export function layoutFromCoordinates(records) {
  const layout = {};
  for (const item of Array.isArray(records) ? records : []) {
    const zoneKey = String(item?.zone_key || "").trim();
    const coordinates = Array.isArray(item?.coordinates) ? item.coordinates : [];
    if (!zoneKey || coordinates.length !== 4) {
      continue;
    }
    const [x1, y1, x2, y2] = coordinates.map((value) => numeric(value, 0));
    const width = Math.max(12, x2 - x1);
    const height = Math.max(12, y2 - y1);
    layout[zoneKey] = {
      x: clamp(x1, 0, 100 - width),
      y: clamp(y1, 0, 100 - height),
      width: clamp(width, 12, 48),
      height: clamp(height, 12, 48),
    };
  }
  return layout;
}

export function syncLayout(zoneKeys, existingLayout = {}, baseLayout = {}) {
  const autoLayout = Object.keys(baseLayout || {}).length ? baseLayout : buildAutoLayout(zoneKeys);
  const next = {};
  for (const zoneKey of [...zoneKeys].sort()) {
    const base = autoLayout[zoneKey] || buildAutoLayout([zoneKey])[zoneKey];
    next[zoneKey] = normalizeRect(existingLayout[zoneKey] || {}, base);
  }
  return next;
}

export function loadSavedLayout() {
  try {
    const raw = window.localStorage.getItem(STORAGE_KEY);
    if (!raw) {
      return {};
    }
    const parsed = JSON.parse(raw);
    return parsed && typeof parsed === "object" ? parsed : {};
  } catch (_error) {
    return {};
  }
}

export function saveLayout(layout) {
  window.localStorage.setItem(STORAGE_KEY, JSON.stringify(layout, null, 2));
}

export function clearSavedLayout() {
  window.localStorage.removeItem(STORAGE_KEY);
}
