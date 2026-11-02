import { RISK_COLORS } from "../constants/riskColors";

export const RISK_LEVELS = ["LOW", "MEDIUM", "HIGH"];

export function normalizeScore(value, min = 0, max = 1) {
  if (value === null || value === undefined || Number.isNaN(value)) {
    return 0;
  }
  if (max <= min) return 0;
  return Math.min(1, Math.max(0, (value - min) / (max - min)));
}

export function getRiskLevel(label) {
  const normalized = String(label || "").toUpperCase();
  if (RISK_LEVELS.includes(normalized)) return normalized;
  return "LOW";
}

export function getRiskColor(label) {
  const key = getRiskLevel(label);
  return RISK_COLORS[key] || RISK_COLORS.LOW;
}

export function buildExplainabilityIndex(items = []) {
  const index = new Map();
  (items || []).forEach((item) => {
    if (!item || !item.packageName) return;
    index.set(item.packageName.toLowerCase(), item);
  });
  return index;
}

export function getAttentionScore(item) {
  return Number(item?.attentionScores?.selfAttention ?? item?.attentionScore ?? 0);
}

export function getPropagationScore(item) {
  return Number(item?.attentionScores?.propagationRisk ?? item?.propagationRisk ?? 0);
}

export function getEpssScore(item) {
  return Number(item?.attentionScores?.maxEpss ?? item?.maxEpss ?? 0);
}

export function deriveExploitExposure(item) {
  const propagation = getPropagationScore(item);
  const epss = getEpssScore(item);
  return Math.max(propagation, epss);
}

export function toGnnGraphExport(graphData) {
  if (!graphData || !Array.isArray(graphData.nodes)) {
    return null;
  }

  const nodes = graphData.nodes;
  const edges = Array.isArray(graphData.edges) ? graphData.edges : [];

  const alreadyExported = nodes.some((node) => node && node.nodeId !== undefined && node.moduleRank !== undefined);
  if (alreadyExported) {
    return graphData;
  }

  const nodeIdMap = new Map();
  const exportNodes = nodes.map((node, index) => {
    const nodeId = index + 1;
    const nodeKey = node?.id ?? node?.name ?? nodeId;
    nodeIdMap.set(String(nodeKey), nodeId);

    return {
      nodeId,
      packageName: node?.packageName || node?.name || node?.id || `node-${nodeId}`,
      moduleRank: Number(node?.moduleRank ?? node?.rank ?? node?.rankScore ?? 0),
      maxCvss: Number(node?.maxCvss ?? 0),
      avgCvss: Number(node?.avgCvss ?? 0),
      maxEpss: Number(node?.maxEpss ?? 0),
      avgEpss: Number(node?.avgEpss ?? 0),
      kevCount: Number(node?.kevCount ?? 0),
      vulnerabilityCount: Number(node?.vulnerabilityCount ?? 0),
      severityWeight: Number(node?.severityWeight ?? 0)
    };
  });

  const exportEdges = edges
    .map((edge) => {
      const sourceKey = edge?.source ?? edge?.from;
      const targetKey = edge?.target ?? edge?.to;
      if (sourceKey === undefined || targetKey === undefined) {
        return null;
      }
      const source = nodeIdMap.get(String(sourceKey));
      const target = nodeIdMap.get(String(targetKey));
      if (!source || !target) {
        return null;
      }
      return { source, target };
    })
    .filter(Boolean);

  return {
    nodes: exportNodes,
    edges: exportEdges
  };
}
