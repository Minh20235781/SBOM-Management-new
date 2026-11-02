import { useMemo } from "react";
import {
  getAttentionScore,
  getEpssScore,
  getPropagationScore,
  getRiskLevel,
  normalizeScore
} from "./utils/graphRiskUtils";
import "./GnnExplainabilityPanel.css";

// Explainability panel for graph AI predictions.
export default function GnnExplainabilityPanel({
  items = [],
  selectedPackage,
  onSelectPackage
}) {
  const selected = useMemo(() => {
    if (!items.length) return null;
    if (selectedPackage) {
      return items.find((item) => item.packageName === selectedPackage) || null;
    }
    return items.find((item) => getRiskLevel(item.predictedRisk) === "HIGH") || items[0];
  }, [items, selectedPackage]);

  if (!selected) {
    return <div className="gnn-analysis-panel-empty">No explainability details yet.</div>;
  }

  const attention = getAttentionScore(selected);
  const propagation = getPropagationScore(selected);
  const epss = getEpssScore(selected);
  const neighbors = selected.influentialNeighbors || [];
  const riskLevel = getRiskLevel(selected.predictedRisk);

  return (
    <div className="gnn-analysis-panel">
      <div className="gnn-analysis-panel-header">
        <div>
          <h5>{selected.packageName}</h5>
          <div className="gnn-analysis-panel-tags">
            <span className={`gnn-risk-tag gnn-level-${riskLevel.toLowerCase()}`}>
              {riskLevel} risk
            </span>
            <span className="gnn-focus-tag">Primary node</span>
          </div>
        </div>
        <button
          className="gnn-analysis-panel-reset"
          onClick={() => onSelectPackage?.(null)}
        >
          Reset Focus
        </button>
      </div>

      <div className="gnn-analysis-panel-grid">
        <div>
          <h6>Influential Neighbors</h6>
          <div className="gnn-neighbor-list">
            {neighbors.length === 0 && (
              <div className="gnn-neighbor-empty">No influential neighbors detected.</div>
            )}
            {neighbors.map((neighbor, idx) => {
              const neighborRisk = getRiskLevel(neighbor.riskLevel || neighbor.predictedRisk);
              return (
                <div key={`${selected.packageName}-${neighbor.packageName}-${idx}`} className="gnn-neighbor-chip">
                  <span className={`gnn-risk-dot gnn-level-${neighborRisk.toLowerCase()}`}></span>
                  <span>{neighbor.packageName}</span>
                  <span className={`gnn-neighbor-risk gnn-level-${neighborRisk.toLowerCase()}`}>
                    {neighborRisk}
                  </span>
                </div>
              );
            })}
          </div>
        </div>

        <div>
          <h6>Signal Breakdown</h6>
          <div className="gnn-signal-row">
            <div className="gnn-signal-label">Attention</div>
            <div className="gnn-signal-track">
              <div
                className="gnn-signal-fill gnn-signal-attention"
                style={{ width: `${Math.round(normalizeScore(attention) * 100)}%` }}
              ></div>
            </div>
            <div className="gnn-signal-value">{Math.round(normalizeScore(attention) * 100)}%</div>
          </div>
          <div className="gnn-signal-row">
            <div className="gnn-signal-label">Propagation</div>
            <div className="gnn-signal-track">
              <div
                className="gnn-signal-fill gnn-signal-propagation"
                style={{ width: `${Math.round(normalizeScore(propagation) * 100)}%` }}
              ></div>
            </div>
            <div className="gnn-signal-value">{Math.round(normalizeScore(propagation) * 100)}%</div>
          </div>
          <div className="gnn-signal-row">
            <div className="gnn-signal-label">EPSS</div>
            <div className="gnn-signal-track">
              <div
                className="gnn-signal-fill gnn-signal-epss"
                style={{ width: `${Math.round(normalizeScore(epss) * 100)}%` }}
              ></div>
            </div>
            <div className="gnn-signal-value">{Math.round(normalizeScore(epss) * 100)}%</div>
          </div>
        </div>
      </div>

      <div className="gnn-analysis-panel-explanation">
        <h6>Explanation</h6>
        {String(selected.explanationText || "")
          .split("\n")
          .map((line, idx) => (
            <p key={idx}>{line}</p>
          ))}
      </div>
    </div>
  );
}
