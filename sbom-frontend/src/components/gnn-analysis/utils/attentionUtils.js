import { normalizeScore } from "./graphRiskUtils";

export function normalizeAttention(value) {
  return normalizeScore(value, 0, 1);
}

export function getAttentionGlow(value) {
  const intensity = normalizeAttention(value);
  const blur = Math.round(6 + intensity * 16);
  const alpha = 0.35 + intensity * 0.45;
  return `0 0 ${blur}px rgba(59, 130, 246, ${alpha})`;
}

export function getAttentionClass(value, threshold = 0.6) {
  return normalizeAttention(value) >= threshold ? "gnn-analysis-attention-high" : "";
}
