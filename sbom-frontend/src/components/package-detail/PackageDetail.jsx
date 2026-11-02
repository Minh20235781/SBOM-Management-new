import { useEffect, useState } from "react";
import {
  fetchPackageDetails,
  fetchLocalDependencyGraph,
  fetchTopRisky,
} from "../../api/sbomApi";
import DependencyGraph from "../dependency-graph/DependencyGraph";
import VulnerabilityTable from "../vulnerability-table/VulnerabilityTable";
import "./PackageDetail.css";

export default function PackageDetail({ packageName, repoName }) {
  const [pkg, setPkg] = useState(null);
  const [vulns, setVulns] = useState([]);
  const [graphData, setGraphData] = useState(null);
  const [riskData, setRiskData] = useState([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (!packageName) return;

    async function load() {
      setLoading(true);
      try {
        const detail = await fetchPackageDetails(packageName, repoName);
        setPkg(detail.packageInfo);
        setVulns(detail.vulnerabilities || []);

        const graph = await fetchLocalDependencyGraph(packageName);
        setGraphData(graph);

        const risky = await fetchTopRisky(200, repoName);
        setRiskData(risky);
      } catch (e) {
        console.error("Load PackageDetail failed", e);
      } finally {
        setLoading(false);
      }
    }

    load();
  }, [packageName]);

  if (loading) {
    return (
      <div className="loading-state">
        <div className="loading-spinner"></div>
        <p className="loading-text">Loading package details...</p>
      </div>
    );
  }
  
  if (!pkg) {
    return (
      <div className="error-state">
        <h2 className="error-title">Package Not Found</h2>
        <p className="error-message">
          The package "{packageName}" could not be found. Please check the package name and try again.
        </p>
      </div>
    );
  }

  return (
    <div className="package-detail">
      {/* Header */}
      <div className="package-header">
        <h1 className="package-title">
          {pkg.name} {pkg.version && `v${pkg.version}`}
        </h1>
        <p className="package-subtitle">
          Repository: {pkg.repoName}
        </p>
      </div>

      {/* Metrics */}
      <div className="metrics-grid">
            {/* Depth data not available - removed */}
        <InfoCard title="Repo Count" value={pkg.repoCount} />
        <InfoCard title="Rank" value={pkg.rankScore?.toFixed(4)} />
        <InfoCard
          title="Vuln Risk"
          value={`${(pkg.vulnAnomaly * 100).toFixed(1)}%`}
          progress={pkg.vulnAnomaly}
        />
        <InfoCard
          title="Hub Risk"
          value={`${(pkg.hubAnomaly * 100).toFixed(1)}%`}
          progress={pkg.hubAnomaly}
        />
      </div>

      {/* Vulnerabilities */}
      <VulnerabilityTable vulns={vulns} />

      {/* Dependency Graph */}
      {graphData && (
        <div className="graph-section">
          <div className="graph-header">
            <h2 className="graph-title">Local Dependency Graph</h2>
          </div>
          <DependencyGraph data={graphData} riskData={riskData} />
        </div>
      )}
    </div>
  );
}

/* ===== Info Card ===== */
function InfoCard({ title, value, progress }) {
  return (
    <div className="metric-card">
      <div className="metric-label">
        {title}
      </div>
      <div className="metric-value">{value || "N/A"}</div>
      {progress !== undefined && (
        <div className="metric-progress">
          <div className="progress-container">
            <span className="progress-label">Risk Level</span>
            <span className="progress-percentage">
              {(progress * 100).toFixed(1)}%
            </span>
          </div>
          <div className="progress-bar">
            <div
              className="progress-fill"
              style={{ width: `${progress * 100}%` }}
            />
          </div>
        </div>
      )}
    </div>
  );
}