export const SEVERITY_ORDER = {
  LOW: 0,
  MEDIUM: 1,
  HIGH: 2,
  CRITICAL: 3,
};

export const SEVERITY_STYLES = {
  LOW: {
    label: "Low",
    text: "#87f7c1",
    accent: "#24c97c",
    fill: "rgba(36, 201, 124, 0.2)",
    glow: "rgba(36, 201, 124, 0.28)",
  },
  MEDIUM: {
    label: "Medium",
    text: "#fff08a",
    accent: "#f4cc3b",
    fill: "rgba(244, 204, 59, 0.2)",
    glow: "rgba(244, 204, 59, 0.28)",
  },
  HIGH: {
    label: "High",
    text: "#ffbf79",
    accent: "#ff8c37",
    fill: "rgba(255, 140, 55, 0.24)",
    glow: "rgba(255, 140, 55, 0.34)",
  },
  CRITICAL: {
    label: "Critical",
    text: "#ff8f98",
    accent: "#ff4d5f",
    fill: "rgba(255, 77, 95, 0.28)",
    glow: "rgba(255, 77, 95, 0.38)",
  },
};

export function normalizeSeverity(level, score = 0) {
  const token = String(level || "LOW").trim().toUpperCase();
  if (token === "CRITICAL") {
    return "CRITICAL";
  }
  if (token === "HIGH" && Number(score) >= 0.9) {
    return "CRITICAL";
  }
  if (token in SEVERITY_ORDER) {
    return token;
  }
  return "LOW";
}

export function compareSeverity(left, right) {
  return (SEVERITY_ORDER[normalizeSeverity(left)] || 0) - (SEVERITY_ORDER[normalizeSeverity(right)] || 0);
}

export function severityStyle(level) {
  return SEVERITY_STYLES[normalizeSeverity(level)] || SEVERITY_STYLES.LOW;
}
