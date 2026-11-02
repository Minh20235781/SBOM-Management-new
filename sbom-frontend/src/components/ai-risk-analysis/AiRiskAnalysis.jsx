import { useEffect, useMemo, useState } from "react";
import { fetchAiRiskAnalysis } from "../../api/aiRiskApi";
import "./AiRiskAnalysis.css";

const RISK_LABELS = {
  high: "High",
  medium: "Medium",
  low: "Low"
};

function formatPercent(value) {
  if (value === null || value === undefined || Number.isNaN(value)) {
    return "0%";
  }
  return `${Math.round(value * 100)}%`;
}

export default function AiRiskAnalysis({ repoName }) {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [predictions, setPredictions] = useState([]);

  useEffect(() => {
    if (!repoName) {
      setPredictions([]);
      return;
    }

    let isActive = true;

    const loadPredictions = async () => {
      try {
        setLoading(true);
        setError(null);
        const result = await fetchAiRiskAnalysis(repoName);
        if (isActive) {
          setPredictions(result || []);
        }
      } catch (err) {
        if (isActive) {
          setError(err.message || "Failed to load AI risk analysis");
          setPredictions([]);
        }
      } finally {
        if (isActive) {
          setLoading(false);
        }
      }
    };

    loadPredictions();

    return () => {
      isActive = false;
    };
  }, [repoName]);

  const sortedPredictions = useMemo(() => {
    return [...predictions].sort((a, b) => b.confidence - a.confidence);
  }, [predictions]);

  return (
    <section className="ai-risk-analysis">
      <div className="ai-risk-header">
        <div>
          <h3>AI Risk Analysis</h3>
          <p>Random Forest model predictions per package</p>
        </div>
        {repoName && (
          <span className="ai-risk-repo">Repo: {repoName}</span>
        )}
      </div>

      {!repoName && (
        <div className="ai-risk-empty">Select a repository to view AI risk predictions.</div>
      )}

      {loading && (
        <div className="ai-risk-loading">Loading AI predictions...</div>
      )}

      {error && !loading && (
        <div className="ai-risk-error">{error}</div>
      )}

      {!loading && !error && repoName && (
        <div className="ai-risk-table-wrapper">
          <table className="ai-risk-table">
            <thead>
              <tr>
                <th>Package</th>
                <th>Version</th>
                <th>Predicted Risk</th>
                <th>Confidence</th>
                <th>Low</th>
                <th>Medium</th>
                <th>High</th>
              </tr>
            </thead>
            <tbody>
              {sortedPredictions.length === 0 ? (
                <tr>
                  <td colSpan={7} className="ai-risk-empty-row">
                    No AI predictions available for this repo.
                  </td>
                </tr>
              ) : (
                sortedPredictions.map((item) => (
                  <tr key={`${item.packageName}-${item.version}`}>
                    <td>{item.packageName}</td>
                    <td>{item.version || "-"}</td>
                    <td>
                      <span className={`risk-pill risk-${item.predictedRisk}`}>
                        {RISK_LABELS[item.predictedRisk] || item.predictedRisk}
                      </span>
                    </td>
                    <td>{formatPercent(item.confidence)}</td>
                    <td>{formatPercent(item.probabilityLow)}</td>
                    <td>{formatPercent(item.probabilityMedium)}</td>
                    <td>{formatPercent(item.probabilityHigh)}</td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
}
