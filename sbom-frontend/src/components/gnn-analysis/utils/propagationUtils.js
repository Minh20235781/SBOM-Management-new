import { normalizeScore } from "./graphRiskUtils";

export function normalizePropagation(value) {
  return normalizeScore(value, 0, 1);
}

export function getPropagationIntensity(value) {
  const intensity = normalizePropagation(value);
  return Math.round(20 + intensity * 80);
}

export function getPropagationClass(value, threshold = 0.65) {
  return normalizePropagation(value) >= threshold ? "gnn-analysis-propagation-high" : "";
}
