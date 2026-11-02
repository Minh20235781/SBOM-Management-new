import { useMemo, useState } from "react";
import {
  deriveExploitExposure,
  getAttentionScore,
  getPropagationScore,
  getRiskColor,
  getRiskLevel,
  normalizeScore
} from "./utils/graphRiskUtils";
import { getAttentionClass } from "./utils/attentionUtils";
import { getPropagationClass } from "./utils/propagationUtils";
import "./GnnRiskTable.css";

function deriveConfidence(item) {
  if (item?.confidenceScore !== undefined && item?.confidenceScore !== null) {
    return Number(item.confidenceScore);
  }
  const attention = getAttentionScore(item);
  const propagation = getPropagationScore(item);
  return (attention + propagation) / 2;
}

export default function GnnRiskTable({ items = [], onSelectPackage }) {
  const [sortKey, setSortKey] = useState("predictedRisk");
  const [sortDir, setSortDir] = useState("desc");
  const [riskFilter, setRiskFilter] = useState("ALL");
  const [query, setQuery] = useState("");

  const rows = useMemo(() => {
    return (items || []).map((item) => {
      const attention = getAttentionScore(item);
      const propagation = getPropagationScore(item);
      const confidence = deriveConfidence(item);

      // percentileRank: "Top X%" format (0-100 scale)
      // Backend trả về percentile (ví dụ: 85.5 = Top 85.5%)
      const percentileRank = item.percentileRank ?? null;

      return {
        ...item,
        attention,
        propagation,
        confidence,
        percentileRank,
        riskLevel: getRiskLevel(item.predictedRisk)
      };
    });
  }, [items]);

  const filtered = useMemo(() => {
    return rows.filter((row) => {
      if (riskFilter !== "ALL" && row.riskLevel !== riskFilter) {
        return false;
      }
      if (query && !row.packageName?.toLowerCase().includes(query.toLowerCase())) {
        return false;
      }
      return true;
    });
  }, [rows, riskFilter, query]);

  const sorted = useMemo(() => {
    const multiplier = sortDir === "asc" ? 1 : -1;
    return [...filtered].sort((a, b) => {
      const aValue = a[sortKey] ?? 0;
      const bValue = b[sortKey] ?? 0;
      if (typeof aValue === "string") {
        return aValue.localeCompare(bValue) * multiplier;
      }
      return (aValue - bValue) * multiplier;
    });
  }, [filtered, sortKey, sortDir]);

  const toggleSort = (key) => {
    if (sortKey === key) {
      setSortDir((prev) => (prev === "asc" ? "desc" : "asc"));
    } else {
      setSortKey(key);
      setSortDir("desc");
    }
  };

  return (
    <div className="gnn-analysis-table">
      <div className="gnn-analysis-table-controls">
        <input
          className="gnn-analysis-input"
          placeholder="Filter package..."
          value={query}
          onChange={(event) => setQuery(event.target.value)}
        />
        <select
          className="gnn-analysis-select"
          value={riskFilter}
          onChange={(event) => setRiskFilter(event.target.value)}
        >
          <option value="ALL">All Risk Levels</option>
          <option value="HIGH">High Risk</option>
          <option value="MEDIUM">Medium Risk</option>
          <option value="LOW">Low Risk</option>
        </select>
      </div>

      <div className="gnn-analysis-table-wrapper">
        <table>
          <thead>
            <tr>
              <th onClick={() => toggleSort("packageName")}>Package</th>
              <th onClick={() => toggleSort("predictedRisk")}>Risk</th>
              <th onClick={() => toggleSort("confidence")}>Confidence</th>
              <th onClick={() => toggleSort("attention")}>Self</th>
              <th onClick={() => toggleSort("propagation")}>Prop</th>
              <th onClick={() => toggleSort("percentileRank")}>Rank</th>
            </tr>
          </thead>
          <tbody>
            {sorted.length === 0 ? (
              <tr>
                <td colSpan={6} className="gnn-analysis-empty-row">
                  No explainability data available.
                </td>
              </tr>
            ) : (
              sorted.map((row, index) => (
                <tr
                  key={`${row.packageName || "package"}-${row.nodeId ?? index}`}
                  className={`gnn-analysis-row ${
                    row.riskLevel === "HIGH" ? "gnn-analysis-row-high" : ""
                  }`}
                  onClick={() => onSelectPackage?.(row.packageName)}
                >
                  <td>{row.packageName}</td>
                  <td>
                    <span
                      className="gnn-analysis-risk-pill"
                      style={{ background: getRiskColor(row.riskLevel) }}
                    >
                      {row.riskLevel}
                    </span>
                  </td>
                  <td>
                    <span
                      className="gnn-analysis-score"
                      style={{
                        boxShadow: `0 0 12px rgba(56, 189, 248, ${normalizeScore(
                          row.confidence
                        )})`
                      }}
                    >
                      {Math.round(normalizeScore(row.confidence) * 100)}%
                    </span>
                  </td>
                  <td className={getAttentionClass(row.attention)}>
                    {Math.round(normalizeScore(row.attention) * 100)}%
                  </td>
                  <td className={getPropagationClass(row.propagation)}>
                    {Math.round(normalizeScore(row.propagation) * 100)}%
                  </td>
                  <td>
                    {row.percentileRank != null
                      ? `Top ${row.percentileRank.toFixed(1)}%`
                      : "—"}
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  );
}
