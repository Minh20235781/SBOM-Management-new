import { useEffect, useMemo, useState } from "react";
import {
  ResponsiveContainer,
  BarChart,
  Bar,
  XAxis,
  YAxis,
  Tooltip,
  PieChart,
  Pie,
  Cell
} from "recharts";
import { fetchAiComparison, fetchAiPredictions } from "../../api/aiPredictionApi";
import "./AiRiskComparison.css";

const RISK_COLORS = {
  high: "#ef4444",
  medium: "#f59e0b",
  low: "#22c55e"
};

const MATCH_COLORS = ["#22c55e", "#ef4444"];

const emptyDistribution = [
  { name: "low", value: 0 },
  { name: "medium", value: 0 },
  { name: "high", value: 0 }
];

function formatPercent(value) {
  if (value === null || value === undefined || Number.isNaN(value)) {
    return "0%";
  }
  return `${Math.round(value * 100)}%`;
}

export default function AiRiskComparison({ repoName }) {
  const [activeTab, setActiveTab] = useState("rule");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [aiPredictions, setAiPredictions] = useState([]);
  const [comparison, setComparison] = useState([]);
  const [packageCount, setPackageCount] = useState(0);

  useEffect(() => {
    if (!repoName) {
      setAiPredictions([]);
      setComparison([]);
      return;
    }

    let isActive = true;

    const loadData = async () => {
      try {
        setLoading(true);
        setError(null);

        const aiData = await fetchAiPredictions(repoName);
        if (!isActive) return;
        const predictions = aiData?.items || [];
        const aiCount = aiData?.packageCount ?? predictions.length;
        setAiPredictions(predictions);
        setPackageCount(aiCount);

        if (predictions.length === 0) {
          setComparison([]);
          return;
        }

        const compareData = await fetchAiComparison(repoName);
        if (isActive) {
          setComparison(compareData?.items || []);
          if (compareData?.packageCount !== undefined) {
            setPackageCount(compareData.packageCount);
          }
        }
      } catch (err) {
        if (isActive) {
          setError(err.message || "Failed to load AI prediction data");
          setAiPredictions([]);
          setComparison([]);
        }
      } finally {
        if (isActive) {
          setLoading(false);
        }
      }
    };

    loadData();

    return () => {
      isActive = false;
    };
  }, [repoName]);

  const aiDistribution = useMemo(() => {
    if (!aiPredictions.length) return emptyDistribution;
    const counts = { low: 0, medium: 0, high: 0 };
    aiPredictions.forEach((item) => {
      const key = (item.predictedRisk || "").toLowerCase();
      if (counts[key] !== undefined) {
        counts[key] += 1;
      }
    });
    return Object.entries(counts).map(([name, value]) => ({ name, value }));
  }, [aiPredictions]);

  const ruleDistribution = useMemo(() => {
    if (!comparison.length) return emptyDistribution;
    const counts = { low: 0, medium: 0, high: 0 };
    comparison.forEach((item) => {
      const key = (item.ruleRisk || "").toLowerCase();
      if (counts[key] !== undefined) {
        counts[key] += 1;
      }
    });
    return Object.entries(counts).map(([name, value]) => ({ name, value }));
  }, [comparison]);

  const matchDistribution = useMemo(() => {
    if (!comparison.length) {
      return [
        { name: "Match", value: 0 },
        { name: "Different", value: 0 }
      ];
    }
    const matches = comparison.filter((item) => item.samePrediction).length;
    return [
      { name: "Match", value: matches },
      { name: "Different", value: comparison.length - matches }
    ];
  }, [comparison]);

  const aiSorted = useMemo(() => {
    return [...aiPredictions].sort((a, b) => b.confidence - a.confidence);
  }, [aiPredictions]);

  const ruleSorted = useMemo(() => {
    return [...comparison].sort((a, b) => b.ruleScore - a.ruleScore);
  }, [comparison]);

  return (
    <section className="ai-compare">
      <div className="ai-compare-header">
        <div>
          <h3>AI vs Rule-Based Risk</h3>
          <p>Compare heuristic anomalies with Random Forest predictions</p>
        </div>
        {repoName && (
          <span className="ai-compare-repo">
            Repo: {repoName} | Packages: {packageCount}
          </span>
        )}
      </div>

      <div className="ai-compare-tabs">
        <button
          className={`ai-tab ${activeTab === "rule" ? "active" : ""}`}
          onClick={() => setActiveTab("rule")}
        >
          Rule-Based
        </button>
        <button
          className={`ai-tab ${activeTab === "ai" ? "active" : ""}`}
          onClick={() => setActiveTab("ai")}
        >
          AI Prediction
        </button>
        <button
          className={`ai-tab ${activeTab === "compare" ? "active" : ""}`}
          onClick={() => setActiveTab("compare")}
        >
          Comparison
        </button>
      </div>

      {!repoName && (
        <div className="ai-compare-empty">Select a repository to compare AI and rule-based risks.</div>
      )}

      {loading && <div className="ai-compare-loading">Loading predictions...</div>}

      {error && !loading && <div className="ai-compare-error">{error}</div>}

      {!loading && !error && repoName && (
        <>
          <div className="ai-compare-charts">
            <div className="chart-card">
              <h4>Rule-Based Distribution</h4>
              <ResponsiveContainer width="100%" height={220}>
                <BarChart data={ruleDistribution}>
                  <XAxis dataKey="name" />
                  <YAxis allowDecimals={false} />
                  <Tooltip />
                  <Bar dataKey="value" fill="#2563eb" />
                </BarChart>
              </ResponsiveContainer>
            </div>
            <div className="chart-card">
              <h4>AI Prediction Distribution</h4>
              <ResponsiveContainer width="100%" height={220}>
                <BarChart data={aiDistribution}>
                  <XAxis dataKey="name" />
                  <YAxis allowDecimals={false} />
                  <Tooltip />
                  <Bar dataKey="value">
                    {aiDistribution.map((entry) => (
                      <Cell key={entry.name} fill={RISK_COLORS[entry.name] || "#94a3b8"} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            </div>
            <div className="chart-card">
              <h4>Match vs Different</h4>
              <ResponsiveContainer width="100%" height={220}>
                <PieChart>
                  <Pie data={matchDistribution} dataKey="value" nameKey="name" outerRadius={80}>
                    {matchDistribution.map((entry, index) => (
                      <Cell key={entry.name} fill={MATCH_COLORS[index]} />
                    ))}
                  </Pie>
                  <Tooltip />
                </PieChart>
              </ResponsiveContainer>
            </div>
          </div>

          {activeTab === "rule" && (
            <div className="ai-compare-table-wrapper">
              <table className="ai-compare-table">
                <thead>
                  <tr>
                    <th>Package</th>
                    <th>Version</th>
                    <th>Rule Risk</th>
                    <th>Rule Score</th>
                  </tr>
                </thead>
                <tbody>
                  {ruleSorted.length === 0 ? (
                    <tr>
                      <td colSpan={4} className="ai-empty-row">No rule-based data available.</td>
                    </tr>
                  ) : (
                    ruleSorted.map((item) => (
                      <tr key={`${item.packageName}-${item.version}-rule`}>
                        <td>{item.packageName}</td>
                        <td>{item.version || "-"}</td>
                        <td>
                          <span className={`risk-pill risk-${item.ruleRisk}`}>
                            {item.ruleRisk}
                          </span>
                        </td>
                        <td>{item.ruleScore.toFixed(3)}</td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          )}

          {activeTab === "ai" && (
            <div className="ai-compare-table-wrapper">
              <table className="ai-compare-table">
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
                  {aiSorted.length === 0 ? (
                    <tr>
                      <td colSpan={7} className="ai-empty-row">No AI predictions available.</td>
                    </tr>
                  ) : (
                    aiSorted.map((item) => (
                      <tr key={`${item.packageName}-${item.version}-ai`}>
                        <td>{item.packageName}</td>
                        <td>{item.version || "-"}</td>
                        <td>
                          <span className={`risk-pill risk-${item.predictedRisk}`}>
                            {item.predictedRisk}
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

          {activeTab === "compare" && (
            <div className="ai-compare-table-wrapper">
              <table className="ai-compare-table">
                <thead>
                  <tr>
                    <th>Package</th>
                    <th>Version</th>
                    <th>Rule Risk</th>
                    <th>AI Prediction</th>
                    <th>Confidence</th>
                    <th>Low</th>
                    <th>Medium</th>
                    <th>High</th>
                  </tr>
                </thead>
                <tbody>
                  {comparison.length === 0 ? (
                    <tr>
                      <td colSpan={8} className="ai-empty-row">No comparison data available.</td>
                    </tr>
                  ) : (
                    comparison.map((item) => (
                      <tr key={`${item.packageName}-${item.version}-compare`}>
                        <td>{item.packageName}</td>
                        <td>{item.version || "-"}</td>
                        <td>
                          <span className={`risk-pill risk-${item.ruleRisk}`}>
                            {item.ruleRisk}
                          </span>
                        </td>
                        <td>
                          <span className={`risk-pill risk-${item.aiRisk}`}>
                            {item.aiRisk}
                          </span>
                        </td>
                        <td>{formatPercent(item.aiConfidence)}</td>
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
        </>
      )}
    </section>
  );
}
