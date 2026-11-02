/* Helper utilities for preparing graph data and small utility functions
   Preserve original logic while making helpers reusable. */

export function getRiskLevel(value) {
  if (value <= 0.3) return "LOW";
  if (value <= 0.6) return "MEDIUM";
  if (value <= 0.9) return "HIGH";
  return "CRITICAL";
}

export function buildRiskMap(riskData = []) {
  const map = {};
  (riskData || []).forEach(r => {
    if (r.packageName) {
      map[r.packageName.toLowerCase()] = r;
    }
  });
  return map;
}

export function prepareNodesAndLinks(data = [], riskData = []) {
  const riskMap = buildRiskMap(riskData);

  const nodes = (data.nodes || []).map((n, index) => {
    const risk = riskMap[n.name?.toLowerCase()] || riskMap[n.id?.toLowerCase()];
    const displayName = n.name || n.id || `node-${index}`;
    return {
      ...n,
      id: n.id || `node-${index}`,
      displayName,
      ...(risk || {}),
      vulnAnomaly: risk?.vulnAnomaly ?? 0,
      hubAnomaly: risk?.hubAnomaly ?? 0,
      rankScore: n.rankScore || n.rank || risk?.rankScore,
      riskLevel: getRiskLevel(Math.max(risk?.vulnAnomaly ?? 0, risk?.hubAnomaly ?? 0))
    };
  });

  const nodeMap = {};
  nodes.forEach(n => nodeMap[n.id] = n);

  const edgeSet = new Set();
  const links = (data.edges || [])
    .map(e => {
      const s = nodeMap[e.source ?? e.from];
      const t = nodeMap[e.target ?? e.to];
      if (!s || !t) return null;
      const edgeKey = `${s.id}-${t.id}`;
      if (edgeSet.has(edgeKey)) return null;
      edgeSet.add(edgeKey);
      return { source: s, target: t, id: edgeKey };
    })
    .filter(Boolean);

  return { nodes, links };
}
