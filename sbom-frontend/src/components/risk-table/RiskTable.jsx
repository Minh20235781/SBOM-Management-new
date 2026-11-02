import React, { useState } from "react";
import "./RiskTable.css";
import { fetchSbomTable } from "../../api/sbomApi";

export default function RiskTable({ data, topN = 10, onSelectPackage, repoName = '' }) {
  if (!data || data.length === 0) {
    return (
      <div className="risk-table-container">
        <h3>Top Risky Packages</h3>
        <div className="empty-state">
          <p className="empty-text">No risk data available</p>
        </div>
      </div>
    );
  }

  // --- Allow selecting how many top packages to show ---
  const [selectedTopN, setSelectedTopN] = useState(topN);

  // --- Sort data by weighted score (vulnAnomaly + hubAnomaly) desc ---
  const sortedData = [...data]
    .sort(
      (a, b) =>
        (b.vulnAnomaly + b.hubAnomaly) -
        (a.vulnAnomaly + a.hubAnomaly)
    )
    .slice(0, selectedTopN);

  // --- Helper: get risk level class ---
  const getRiskLevelClass = (val) => {
    if (val > 0.7) return "high-risk";
    if (val > 0.4) return "medium-risk";
    return "low-risk";
  };

  // --- Helper: get color based on value ---
  const getColor = (val) => {
    if (val > 0.7) return "#F44336";
    if (val > 0.4) return "#FFC107";
    return "#4CAF50";
  };

  const [exporting, setExporting] = useState(false);
  const [exportProgress, setExportProgress] = useState(0);

  // --- Export helpers ---
  const toCsv = (arr) => {
    if (!arr || arr.length === 0) return "";
    // use union of all keys to ensure columns present
    const keySet = new Set();
    arr.forEach(r => Object.keys(r).forEach(k => keySet.add(k)));
    const keys = Array.from(keySet);
    const escape = (v) => {
      if (v === null || v === undefined) return '';
      const s = String(v);
      if (s.includes('"') || s.includes(',') || s.includes('\n')) {
        return '"' + s.replace(/"/g, '""') + '"';
      }
      return s;
    };
    const lines = [keys.join(',')];
    for (const row of arr) {
      lines.push(keys.map(k => escape(row[k])).join(','));
    }
    return lines.join('\n');
  };

  const download = (filename, content, type = 'text/csv') => {
    const blob = new Blob([content], { type });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  };

  const handleExport = async (format) => {
    try {
      setExporting(true);
      setExportProgress(10);
      const table = await fetchSbomTable(repoName);
      setExportProgress(60);
      if (!table || table.length === 0) {
        alert('No data to export');
        setExporting(false);
        setExportProgress(0);
        return;
      }
      // Ensure export shows "Secure" for missing vulnerability fields
      const tableForExport = table.map(r => {
        const copy = { ...r };
        ['vulnerabilities', 'severity', 'cvss'].forEach(k => {
          if (copy[k] === null || copy[k] === undefined) copy[k] = 'Secure';
          if (typeof copy[k] === 'string' && copy[k].trim() === '') copy[k] = 'Secure';
        });
        return copy;
      });

      if (format === 'csv') {
        const csv = toCsv(tableForExport);
        setExportProgress(85);
        download('sbom.csv', csv, 'text/csv');
      } else {
        setExportProgress(85);
        download('sbom.json', JSON.stringify(tableForExport, null, 2), 'application/json');
      }
      setExportProgress(100);
    } catch (err) {
      console.error('Export failed', err);
      alert('Export failed: ' + (err.message || err));
    } finally {
      setTimeout(() => {
        setExporting(false);
        setExportProgress(0);
      }, 600);
    }
  };

  return (
    <div className="risk-table-container">
      <div className="risk-table-header">
        <h3>Top {selectedTopN} Risky Packages</h3>
        <div className="topn-select">
          <label htmlFor="topn">Show:</label>
          <select
            id="topn"
            value={selectedTopN}
            onChange={(e) => setSelectedTopN(Number(e.target.value))}
          >
            <option value={5}>5</option>
            <option value={10}>10</option>
            <option value={15}>15</option>
          </select>
        </div>
        <div className="export-actions">
          <button className="export-btn" disabled={exporting} onClick={() => handleExport('csv')}>
            {exporting ? 'Exporting...' : 'Export CSV'}
          </button>
          <button className="export-btn" disabled={exporting} onClick={() => handleExport('json')}>
            {exporting ? 'Exporting...' : 'Export JSON'}
          </button>
        </div>
      </div>

      {exporting && (
        <div className="export-progress">
          <div className="export-progress-bar">
            <div className="export-progress-fill" style={{ width: `${exportProgress}%` }} />
          </div>
          <div className="export-progress-text">Exporting... {exportProgress}%</div>
        </div>
      )}

      <div className="table-wrapper">
        <table>
          <thead>
            <tr>
              <th>Package</th>
              <th>Version</th>
              <th>Vuln Count</th>
              <th>High</th>
              <th>CVSS Max</th>
              <th>Rank</th>
              <th>Vuln Anomaly</th>
              <th>Hub Anomaly</th>
            </tr>
          </thead>

          <tbody>
            {sortedData.map((p, idx) => {
              const vulnRiskClass = getRiskLevelClass(p.vulnAnomaly ?? 0);
              const hubRiskClass = getRiskLevelClass(p.hubAnomaly ?? 0);
              const weightedScore = (p.vulnAnomaly + p.hubAnomaly).toFixed(2);
              
              return (
                <tr
                  key={idx}
                  onClick={() => onSelectPackage?.(p.packageName)}
                  className="risk-row"
                  title={`Click to view details\nWeighted Score: ${weightedScore}`}
                >
                  <td>{p.packageName}</td>
                  <td>{p.version || "-"}</td>
                  <td>{p.vulnCount || 0}</td>
                  <td>{p.highSeverity || 0}</td>
                  <td>{p.cvssMax?.toFixed(1) || "-"}</td>
                  <td>{p.rankScore?.toFixed(4) || "0.0000"}</td>

                  <td>
                    <div 
                      className="progress-container"
                      data-tooltip={`Vuln Risk: ${((p.vulnAnomaly ?? 0) * 100).toFixed(1)}%`}
                    >
                      <div className="progress-bar">
                        <div
                          className={`progress-fill ${vulnRiskClass}`}
                          style={{
                            width: `${(p.vulnAnomaly ?? 0) * 100}%`,
                            backgroundColor: getColor(p.vulnAnomaly ?? 0),
                          }}
                        >
                          {(p.vulnAnomaly ?? 0).toFixed(2)}
                        </div>
                      </div>
                    </div>
                  </td>

                  <td>
                    <div 
                      className="progress-container"
                      data-tooltip={`Hub Risk: ${((p.hubAnomaly ?? 0) * 100).toFixed(1)}%`}
                    >
                      <div className="progress-bar">
                        <div
                          className={`progress-fill ${hubRiskClass}`}
                          style={{
                            width: `${(p.hubAnomaly ?? 0) * 100}%`,
                            backgroundColor: getColor(p.hubAnomaly ?? 0),
                          }}
                        >
                          {(p.hubAnomaly ?? 0).toFixed(2)}
                        </div>
                      </div>
                    </div>
                  </td>
                </tr>
              );
            })}
          </tbody>
        </table>
      </div>

      <p className="hint">
        Click any package row to view detailed risk analysis and vulnerabilities
      </p>
    </div>
  );
}