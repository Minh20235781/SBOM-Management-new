import { useEffect, useMemo, useState } from "react";
import { fetchGnnExplainability } from "./api/gnnAnalysisApi";
import GnnRiskTable from "./GnnRiskTable";
import GnnExplainabilityPanel from "./GnnExplainabilityPanel";
import GnnPropagationGraph from "./GnnPropagationGraph";
import {
  buildExplainabilityIndex,
  deriveExploitExposure,
  getAttentionScore,
  getPropagationScore,
  getRiskLevel,
  normalizeScore,
  toGnnGraphExport
} from "./utils/graphRiskUtils";
import "./GnnRiskDashboard.css";

// Experimental GNN explainability dashboard.
export default function GnnRiskDashboard({ graphPayload, title = "Experimental GNN Risk Summary" }) {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [explanations, setExplanations] = useState([]);
  const [selectedPackage, setSelectedPackage] = useState(null);
  const [modelChoice, setModelChoice] = useState("gat");

  const exportPayload = useMemo(
    () => toGnnGraphExport(graphPayload),
    [graphPayload]
  );

  const requestPayload = useMemo(() => {
    if (!exportPayload) return null;
    return { ...exportPayload, model: modelChoice };
  }, [exportPayload, modelChoice]);

  useEffect(() => {
    if (!requestPayload) {
      setExplanations([]);
      setSelectedPackage(null);
      return;
    }

    let isActive = true;

    const loadExplainability = async () => {
      try {
        setLoading(true);
        setError(null);
        const result = await fetchGnnExplainability(requestPayload);
        if (isActive) {
          setExplanations(result || []);
        }
      } catch (err) {
        if (isActive) {
          setError(err.message || "Failed to load GNN explainability");
          setExplanations([]);
        }
      } finally {
        if (isActive) {
          setLoading(false);
        }
      }
    };

    loadExplainability();

    return () => {
      isActive = false;
    };
  }, [requestPayload]);

  const summary = useMemo(() => {
    const total = explanations.length;
    const highRisk = explanations.filter((item) =>
      getRiskLevel(item.predictedRisk) === "HIGH"
    );
    const avgAttention = total
      ? explanations.reduce((sum, item) => sum + getAttentionScore(item), 0) / total
      : 0;
    const avgPropagation = total
      ? explanations.reduce((sum, item) => sum + getPropagationScore(item), 0) / total
      : 0;

    return {
      total,
      highRisk: highRisk.length,
      avgAttention,
      avgPropagation
    };
  }, [explanations]);

  const explainabilityIndex = useMemo(
    () => buildExplainabilityIndex(explanations),
    [explanations]
  );

  const highRiskChains = useMemo(() => {
    return explanations
      .filter((item) => getRiskLevel(item.predictedRisk) === "HIGH")
      .map((item) => ({
        packageName: item.packageName,
        exposure: deriveExploitExposure(item),
        neighbors: item.influentialNeighbors || []
      }))
      .sort((a, b) => b.exposure - a.exposure)
      .slice(0, 6);
  }, [explanations]);


  return (
    <section className="gnn-analysis-dashboard">
      <div className="gnn-analysis-header">
        <div>
          <h3>{title}</h3>
          <p>Experimental graph-AI explainability layer (non-production).</p>
        </div>
        <div className="gnn-analysis-header-actions">
          <div className="gnn-model-toggle">
            <button
              className={`gnn-model-btn ${modelChoice === "gat" ? "active" : ""}`}
              onClick={() => setModelChoice("gat")}
              type="button"
            >
              GAT
            </button>
            <button
              className={`gnn-model-btn ${modelChoice === "gcn" ? "active" : ""}`}
              onClick={() => setModelChoice("gcn")}
              type="button"
            >
              GCN
            </button>
          </div>
          <span className="gnn-analysis-badge">Graph AI Research</span>
        </div>
      </div>

      {!requestPayload && (
        <div className="gnn-analysis-empty">
          Provide an experimental graph payload to render GNN insights.
        </div>
      )}

      {loading && (
        <div className="gnn-analysis-loading">Loading explainability signals...</div>
      )}

      {error && !loading && (
        <div className="gnn-analysis-error">{error}</div>
      )}

      {!loading && !error && requestPayload && (
        <>
          <div className="gnn-analysis-summary">
            <div className="gnn-analysis-stat">
              <span>Total Packages</span>
              <strong>{summary.total}</strong>
            </div>
            <div className="gnn-analysis-stat">
              <span>High Risk</span>
              <strong>{summary.highRisk}</strong>
            </div>
            <div className="gnn-analysis-stat">
              <span>Avg Attention</span>
              <strong>{Math.round(normalizeScore(summary.avgAttention) * 100)}%</strong>
            </div>
            <div className="gnn-analysis-stat">
              <span>Avg Propagation</span>
              <strong>{Math.round(normalizeScore(summary.avgPropagation) * 100)}%</strong>
            </div>
          </div>

          <div className="gnn-analysis-section">
            <h4>Graph Propagation Visualization</h4>
            <GnnPropagationGraph
              graphPayload={requestPayload}
              explainabilityIndex={explainabilityIndex}
            />
          </div>

          <div className="gnn-analysis-section">
            <h4>Attention-Based Risk Table</h4>
            <GnnRiskTable
              items={explanations}
              onSelectPackage={setSelectedPackage}
            />
          </div>

          <div className="gnn-analysis-section">
            <h4>Explainability Analysis</h4>
            <GnnExplainabilityPanel
              items={explanations}
              selectedPackage={selectedPackage}
              onSelectPackage={setSelectedPackage}
            />
          </div>

          <div className="gnn-analysis-section">
            <h4>High-Risk Dependency Chains</h4>
            <div className="gnn-analysis-chain-grid">
              {highRiskChains.length === 0 ? (
                <div className="gnn-analysis-empty">No high-risk chains detected yet.</div>
              ) : (
                highRiskChains.map((chain) => (
                  <div key={chain.packageName} className="gnn-analysis-chain-card">
                    <div className="gnn-analysis-chain-title">{chain.packageName}</div>
                    <div className="gnn-analysis-chain-score">
                      Exposure {Math.round(normalizeScore(chain.exposure) * 100)}%
                    </div>
                    <div className="gnn-analysis-chain-flow">
                      <span className="gnn-chain-node gnn-risk-high">{chain.packageName}</span>
                      {(chain.neighbors || []).slice(0, 3).map((neighbor) => {
                        const neighborRisk = getRiskLevel(neighbor.riskLevel || neighbor.predictedRisk);
                        return (
                          <span key={`${chain.packageName}-${neighbor.packageName}`} className="gnn-chain-step">
                            <span className="gnn-chain-arrow">→</span>
                            <span className={`gnn-chain-node gnn-risk-${neighborRisk.toLowerCase()}`}>
                              {neighbor.packageName}
                            </span>
                          </span>
                        );
                      })}
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>
        </>
      )}
    </section>
  );
}
