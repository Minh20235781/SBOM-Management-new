import { useEffect, useMemo, useState } from "react";
import {
  Bar,
  BarChart,
  CartesianGrid,
  Legend,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis
} from "recharts";
import { fetchAiComparison } from "../../api/aiPredictionApi";
import { fetchGnnExplainability } from "../gnn-analysis/api/gnnAnalysisApi";
import { toGnnGraphExport } from "../gnn-analysis/utils/graphRiskUtils";
import "./ComparisonDashboard.css";

const RISK_ORDER = ["HIGH", "MEDIUM", "LOW"];

const MODEL_COLORS = {
  gat: "#0ea5a4",
  gcn: "#38bdf8",
  ml: "#f97316",
  rule: "#94a3b8"
};

function normalizeRisk(label) {
  const value = String(label || "").toUpperCase();
  if (value === "HIGH" || value === "MEDIUM" || value === "LOW") {
    return value;
  }
  return "LOW";
}

function countByRisk(items, extractor) {
  const counts = { HIGH: 0, MEDIUM: 0, LOW: 0 };
  (items || []).forEach((item) => {
    const key = normalizeRisk(extractor(item));
    counts[key] += 1;
  });
  return counts;
}

function buildRiskRow(name, counts) {
  return {
    name,
    HIGH: counts.HIGH,
    MEDIUM: counts.MEDIUM,
    LOW: counts.LOW
  };
}

export default function ComparisonDashboard({ repoName, graphPayload }) {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [gatResults, setGatResults] = useState([]);
  const [gcnResults, setGcnResults] = useState([]);
  const [mlCompare, setMlCompare] = useState([]);

  const exportPayload = useMemo(() => toGnnGraphExport(graphPayload), [graphPayload]);

  useEffect(() => {
    if (!repoName || !exportPayload) {
      setGatResults([]);
      setGcnResults([]);
      setMlCompare([]);
      return;
    }

    let isActive = true;

    const loadAll = async () => {
      try {
        setLoading(true);
        setError(null);

        const gatPayload = { ...exportPayload, model: "GAT" };
        const gcnPayload = { ...exportPayload, model: "GCN" };

        const [gatData, gcnData, compareData] = await Promise.all([
          fetchGnnExplainability(gatPayload),
          fetchGnnExplainability(gcnPayload),
          fetchAiComparison(repoName)
        ]);

        if (!isActive) return;
        setGatResults(gatData || []);
        setGcnResults(gcnData || []);
        setMlCompare(compareData?.items || []);
      } catch (err) {
        if (isActive) {
          setError(err.message || "Failed to load comparison data");
          setGatResults([]);
          setGcnResults([]);
          setMlCompare([]);
        }
      } finally {
        if (isActive) {
          setLoading(false);
        }
      }
    };

    loadAll();

    return () => {
      isActive = false;
    };
  }, [repoName, exportPayload]);

  const chartData = useMemo(() => {
    const gatCounts = countByRisk(gatResults, (item) => item.predictedRisk);
    const gcnCounts = countByRisk(gcnResults, (item) => item.predictedRisk);
    const mlCounts = countByRisk(mlCompare, (item) => item.aiRisk);
    const ruleCounts = countByRisk(mlCompare, (item) => item.ruleRisk);

    return RISK_ORDER.map((risk) => ({
      risk,
      gat: gatCounts[risk],
      gcn: gcnCounts[risk],
      ml: mlCounts[risk],
      rule: ruleCounts[risk]
    }));
  }, [gatResults, gcnResults, mlCompare]);

  const tableRows = useMemo(() => {
    const rows = new Map();

    const ensureRow = (key, base) => {
      if (!rows.has(key)) {
        rows.set(key, {
          packageName: base.packageName || key,
          version: base.version || "-",
          gat: "-",
          gcn: "-",
          ml: "-",
          rule: "-"
        });
      }
      return rows.get(key);
    };

    gatResults.forEach((item) => {
      const key = item.packageName || "unknown";
      const row = ensureRow(key, item);
      row.gat = normalizeRisk(item.predictedRisk);
    });

    gcnResults.forEach((item) => {
      const key = item.packageName || "unknown";
      const row = ensureRow(key, item);
      row.gcn = normalizeRisk(item.predictedRisk);
    });

    mlCompare.forEach((item) => {
      const key = item.packageName || "unknown";
      const row = ensureRow(key, item);
      row.version = item.version || row.version;
      row.ml = normalizeRisk(item.aiRisk);
      row.rule = normalizeRisk(item.ruleRisk);
    });

    return Array.from(rows.values()).sort((a, b) =>
      a.packageName.localeCompare(b.packageName)
    );
  }, [gatResults, gcnResults, mlCompare]);

  const hasConflict = (row) => {
    const values = [row.gat, row.gcn, row.ml, row.rule].filter((v) => v && v !== "-");
    const set = new Set(values);
    return set.has("HIGH") && set.has("LOW");
  };

  const badgeClass = (value) => {
    if (!value || value === "-") return "risk-unknown";
    return `risk-${value.toLowerCase()}`;
  };

  return (
    <section className="compare-dashboard">
      <div className="compare-header">
        <div>
          <h3>Comparison Dashboard</h3>
          <p>Side-by-side risk outputs for GAT, GCN, ML, and Rule-based methods.</p>
        </div>
        {repoName && <span className="compare-repo">Repo: {repoName}</span>}
      </div>

      {!repoName && (
        <div className="compare-empty">Select a repository to view comparison results.</div>
      )}

      {loading && (
        <>
          <div className="compare-skeleton-chart"></div>
          <div className="compare-skeleton-table">
            {Array.from({ length: 6 }).map((_, idx) => (
              <div key={idx} className="compare-skeleton-row"></div>
            ))}
          </div>
        </>
      )}

      {error && !loading && <div className="compare-error">{error}</div>}

      {!loading && !error && repoName && (
        <>
          <div className="compare-chart-card">
            <div className="compare-chart-title">Risk Alert Distribution</div>
            <ResponsiveContainer width="100%" height={260}>
              <BarChart data={chartData} barCategoryGap={12} barGap={4}>
                <CartesianGrid strokeDasharray="3 3" vertical={false} />
                <XAxis dataKey="risk" />
                <YAxis allowDecimals={false} />
                <Tooltip />
                <Legend />
                <Bar dataKey="gat" name="GAT" fill={MODEL_COLORS.gat} radius={[6, 6, 0, 0]} />
                <Bar dataKey="gcn" name="GCN" fill={MODEL_COLORS.gcn} radius={[6, 6, 0, 0]} />
                <Bar dataKey="ml" name="ML" fill={MODEL_COLORS.ml} radius={[6, 6, 0, 0]} />
                <Bar dataKey="rule" name="Rule" fill={MODEL_COLORS.rule} radius={[6, 6, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>

          <div className="compare-table-wrapper">
            <table className="compare-table">
              <thead>
                <tr>
                  <th>Package</th>
                  <th>GAT</th>
                  <th>GCN</th>
                  <th>ML</th>
                  <th>Rule</th>
                </tr>
              </thead>
              <tbody>
                {tableRows.length === 0 ? (
                  <tr>
                    <td colSpan={5} className="compare-empty-row">
                      No comparison data available.
                    </td>
                  </tr>
                ) : (
                  tableRows.map((row) => (
                    <tr
                      key={`${row.packageName}-${row.version}`}
                      className={hasConflict(row) ? "compare-row conflict" : "compare-row"}
                    >
                      <td>
                        <div className="compare-package">
                          <span>{row.packageName}</span>
                          {hasConflict(row) && <span className="compare-warning">⚠️</span>}
                        </div>
                      </td>
                      <td><span className={`risk-badge ${badgeClass(row.gat)}`}>{row.gat}</span></td>
                      <td><span className={`risk-badge ${badgeClass(row.gcn)}`}>{row.gcn}</span></td>
                      <td><span className={`risk-badge ${badgeClass(row.ml)}`}>{row.ml}</span></td>
                      <td><span className={`risk-badge ${badgeClass(row.rule)}`}>{row.rule}</span></td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </>
      )}
    </section>
  );
}
