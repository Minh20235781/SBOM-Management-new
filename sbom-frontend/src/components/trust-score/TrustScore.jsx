import { useEffect, useState } from "react";
import { fetchSbomValidation, fetchSbomValidationByProject } from "../../api/sbomApi";
import "./TrustScore.css";

const dependencyCellStyle = {
  padding: "0.5rem 0.75rem",
  verticalAlign: "middle",
};

const mutedDashStyle = {
  color: "#cbd5e1",
  fontWeight: 600,
  fontSize: "0.875rem",
};

const truthBadgeStyle = {
  display: "inline-flex",
  alignItems: "center",
  gap: "0.3rem",
  padding: "0.2rem 0.6rem",
  borderRadius: "9999px",
  border: "1px solid #bbf7d0",
  backgroundColor: "#f0fdf4",
  color: "#15803d",
  fontSize: "0.7rem",
  fontWeight: 600,
  lineHeight: 1,
  whiteSpace: "nowrap",
  letterSpacing: "0.01em",
};

const typeTagBaseStyle = {
  display: "inline-flex",
  alignItems: "center",
  padding: "0.2rem 0.6rem",
  borderRadius: "9999px",
  fontSize: "0.7rem",
  fontWeight: 600,
  lineHeight: 1,
  whiteSpace: "nowrap",
  letterSpacing: "0.01em",
};

const typeTagStyles = {
  blue: {
    backgroundColor: "#eff6ff",
    color: "#1d4ed8",
    border: "1px solid #bfdbfe",
  },
  purple: {
    backgroundColor: "#faf5ff",
    color: "#7e22ce",
    border: "1px solid #e9d5ff",
  },
};

/* =========================
   Utility Functions
   ========================= */

/**
 * Normalize package key to groupId:artifactId format
 * Backend now returns keys in this format
 */
function normalizePackageKey(packageName, groupId = null, artifactId = null) {
  // If already in groupId:artifactId format, return as-is
  if (packageName && packageName.includes(":")) {
    return packageName;
  }
  // If we have separate groupId and artifactId, combine them
  if (groupId && artifactId) {
    return `${groupId}:${artifactId}`;
  }
  // Fallback: return the packageName
  return packageName || "";
}

/**
 * Extract display name from package key (show artifactId only for brevity)
 * For full groupId:artifactId format, shows artifactId
 * For legacy format, shows as-is
 */
function getDisplayName(packageKey) {
  if (!packageKey) return "-";
  if (packageKey.includes(":")) {
    const parts = packageKey.split(":");
    return parts[parts.length - 1]; // Return artifactId (last part)
  }
  return packageKey;
}

/**
 * Ecosystem Badge Component
 * Displays ecosystem type with appropriate color coding
 */
function EcosystemBadge({ ecosystem }) {
  const ecosystemStyles = {
    maven: {
      backgroundColor: "#eff6ff",
      color: "#1d4ed8",
      border: "1px solid #bfdbfe",
    },
    npm: {
      backgroundColor: "#f0fdf4",
      color: "#15803d",
      border: "1px solid #bbf7d0",
    },
    pypi: {
      backgroundColor: "#fefce8",
      color: "#a16207",
      border: "1px solid #fef08a",
    },
    golang: {
      backgroundColor: "#f0f9ff",
      color: "#0369a1",
      border: "1px solid #bae6fd",
    },
    nuget: {
      backgroundColor: "#fdf4ff",
      color: "#a21caf",
      border: "1px solid #e9d5ff",
    },
    native: {
      backgroundColor: "#f9fafb",
      color: "#374151",
      border: "1px solid #e5e7eb",
    },
    other: {
      backgroundColor: "#f5f5f5",
      color: "#737373",
      border: "1px solid #e5e5e5",
    },
  };

  const style = ecosystemStyles[ecosystem?.toLowerCase()] || ecosystemStyles.other;
  const label = ecosystem?.toLowerCase() || "other";

  return (
    <span
      style={{
        display: "inline-flex",
        alignItems: "center",
        padding: "0.15rem 0.5rem",
        borderRadius: "9999px",
        fontSize: "0.7rem",
        fontWeight: 600,
        lineHeight: 1,
        letterSpacing: "0.01em",
        whiteSpace: "nowrap",
        ...style,
      }}
    >
      {label}
    </span>
  );
}

export default function TrustScore({
  repoName,
  repoUrl,
  projectId,
  refreshKey = 0,
  // Controlled mode: parent owns the fetch and passes the
  // result in. When provided, the child skips its own
  // useEffect-driven fetch and just renders what it's given.
  controlledData = null,
  controlledLoading = false,
  controlledError = null,
}) {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [data, setData] = useState(null);

  useEffect(() => {
    // Skip the internal fetch entirely when the parent is
    // driving validation (TrustScore page owns the fetch so
    // it can chain it right after the Trivy scan completes).
    if (controlledData !== null || controlledLoading || controlledError) {
      return;
    }
    console.log("[TrustScore] useEffect triggered", { projectId, repoName, repoUrl, refreshKey });
    // projectId is the preferred key: the backend can derive
    // repoName + a best-effort repoUrl from the project row
    // alone, so this works for projects with no snapshot history
    // (e.g. the legacy "Default Project" seed). We fall back
    // to the legacy (repoUrl, repoName) entry point for
    // callers that haven't migrated yet.
    //
    // refreshKey lets the parent force a re-fetch without
    // changing projectId/repoName/repoUrl (e.g. after a fresh
    // Trivy scan completes). The parent increments the key
    // and we treat it as a re-run signal.
    if (!projectId && !repoName && !repoUrl) {
      console.log("[TrustScore] no inputs, returning early");
      return;
    }

    let mounted = true;
    async function load() {
      console.log("[TrustScore] load() starting");
      setLoading(true);
      setError(null);
      try {
        const res = projectId
          ? await fetchSbomValidationByProject(projectId)
          : await fetchSbomValidation(repoUrl, repoName);
        console.log("[TrustScore] load() got response", res ? "OK" : "null");
        if (mounted) setData(res);
      } catch (err) {
        console.error("[TrustScore] load() error", err);
        if (mounted) setError(err.message || "Failed to load validation data");
      } finally {
        if (mounted) setLoading(false);
      }
    }

    load();
    return () => {
      mounted = false;
    };
  }, [projectId, repoName, repoUrl, refreshKey, controlledData, controlledLoading, controlledError]);

  if (!projectId && !repoName && !repoUrl) {
    return (
      <div className="trust-score-container">
        <div className="trust-empty">
          <p className="trust-empty-text">Analyze a repository to view SBOM trust validation.</p>
        </div>
      </div>
    );
  }

  // Controlled mode: parent's data/error/loading wins so the
  // child never lags a step behind the latest scan. Falls
  // through to the legacy self-fetch path when no controlled
  // values are provided.
  const renderData = controlledData !== null ? controlledData : data;
  const renderLoading = controlledLoading || loading;
  const renderError = controlledError || error;

  if (renderLoading) {
    console.log("[TrustScore] render: loading");
    return (
      <div className="trust-score-container">
        <div className="trust-loading">
          <div className="loading-spinner"></div>
          <p className="loading-text">Validating SBOM trust score...</p>
        </div>
      </div>
    );
  }

  if (renderError) {
    console.log("[TrustScore] render: error", renderError);
    return (
      <div className="trust-score-container">
        <div className="trust-error">
          <div className="trust-error-text">{renderError}</div>
        </div>
      </div>
    );
  }

  if (!renderData) {
    console.log("[TrustScore] render: no data, returning null");
    return null;
  }

  console.log("[TrustScore] render: data ready", {
    score: renderData.structuralTrustScore,
    quality: renderData.structuralTrustQuality,
    deps: (renderData.dependencies || []).length,
    issues: (renderData.issues || []).length,
  });

  const scorePercent = Math.round((renderData.structuralTrustScore || 0) * 100);
  const quality = (renderData.structuralTrustQuality || "LOW").toUpperCase();
  const summary = renderData.summary || {};
  const issues = renderData.issues || [];
  const dependencies = renderData.dependencies || [];
  const visibility = renderData.runtimeSupplyChainVisibility || {};
  const buildCoverage = renderData.buildDependencyCoverage;
  const graphConsistency = renderData.dependencyGraphConsistency;
  const scannerAlignment = renderData.externalScannerAlignment;
  const securityAvailability = renderData.securityMetadataAvailability;
  const buildAvailable = renderData.buildValidationAvailable;
  const interpretation = renderData.validationInterpretation || "";

  const hasBuildCoverage = buildAvailable && buildCoverage !== null && buildCoverage !== undefined;
  const hasDirectValidation = buildAvailable;
  const skippedConfig = [];
  if (!hasBuildCoverage) {
    skippedConfig.push("Build Dependency Coverage is unavailable");
  }
  if (!hasDirectValidation) {
    skippedConfig.push("Direct Maven Validation was skipped");
  }

  return (
    <div className="trust-score-container">
      <div className="trust-header">
        <h3 className="trust-title">Trust Score</h3>
        <p className="trust-subtitle">Multi-source SBOM validation across graph, build, and scanner data.</p>
      </div>

      <div className="trust-score-card">
        <div className="trust-score-main">
          <div className="trust-score-value">{scorePercent}%</div>
          <div className={`trust-score-badge ${quality.toLowerCase()}`}>{quality}</div>
        </div>
        <div className="trust-score-meta">
          <div className="trust-score-label">Structural Trust Score</div>
          <div className="trust-score-note">
            Weighted by runtime dependency alignment, dependency graph consistency, build-system verification, and metadata completeness.
          </div>
        </div>
      </div>

      <div className="trust-metric-grid">
        {hasBuildCoverage && (
          <MetricCard
            label="Build Dependency Coverage"
            value={formatPercent(buildCoverage, buildAvailable)}
            note="Direct Maven dependencies visible in runtime scanner"
          />
        )}
        <MetricCard
          label="Dependency Graph Consistency"
          value={formatPercent(graphConsistency)}
          note="Internal graph alignment with scanner runtime"
        />
        <MetricCard
          label="External Scanner Alignment"
          value={formatPercent(scannerAlignment)}
          note="Resolved runtime deps that appear in scanner"
        />
        <MetricCard
          label="Security Metadata Availability"
          value={formatPercent(securityAvailability)}
          note="Packages with advisory metadata"
        />
      </div>

      <div className="trust-metric-grid">
        {hasDirectValidation && (
          <MetricCard
            label="Direct Maven Validation"
            value="Available"
            note={renderData.buildFallbackReason ? `Build Resolution Fallback: ${renderData.buildFallbackReason}` : ""}
          />
        )}
        <MetricCard
          label="Ecosystem Detected"
          value={renderData.ecosystemDetected ? "Yes" : "No"}
          note={renderData.mavenDetected ? "Maven ecosystem detected" : "Maven not detected"}
        />
      </div>

      {skippedConfig.length > 0 && (
        <details className="trust-config-toggle">
          <summary>
            <span className="trust-config-icon">⚠️</span>
            Thông tin cấu hình hệ thống (Bị bỏ qua)
          </summary>
          <div className="trust-config-content">
            <ul>
              {skippedConfig.map((item) => (
                <li key={item}>{item}</li>
              ))}
              {renderData.buildFallbackReason && (
                <li>Build Resolution Fallback: {renderData.buildFallbackReason}</li>
              )}
            </ul>
          </div>
        </details>
      )}

      <div className="trust-summary-grid">
        <SummaryCard label="High Confidence" value={summary.highConfidence || 0} tone="high" />
        <SummaryCard label="Medium Confidence" value={summary.mediumConfidence || 0} tone="medium" />
        <SummaryCard label="Low Confidence" value={summary.lowConfidence || 0} tone="low" />
      </div>

      <div className="trust-visibility">
        <h4 className="trust-section-title">Runtime Supply Chain Visibility</h4>
        <div className="trust-visibility-grid">
          {Object.keys(visibility).length === 0 ? (
            <div className="trust-empty-row">No runtime ecosystem data</div>
          ) : (
            Object.entries(visibility).map(([key, value]) => (
              <div key={key} className="trust-visibility-card">
                <div className="trust-visibility-label">{formatVisibilityLabel(key)}</div>
                <div className="trust-visibility-value">{value}</div>
              </div>
            ))
          )}
        </div>
      </div>

      {interpretation && (
        <div className="trust-interpretation">
          <div className="trust-interpretation-title">Interpretation</div>
          <p className="trust-interpretation-text">{interpretation}</p>
        </div>
      )}

      <div className="trust-table-section">
        <h4 className="trust-section-title">Validation Issues</h4>
        <div className="trust-table trust-table-scroll-issues">
          <table>
            <thead>
              <tr>
                <th>Package</th>
                <th>Issue Type</th>
                <th>Severity</th>
              </tr>
            </thead>
            <tbody>
              {issues.length === 0 ? (
                <tr>
                  <td colSpan="3" className="trust-empty-row">No validation issues detected</td>
                </tr>
              ) : (
                issues.map((issue, idx) => (
                  <tr key={`${issue.packageName}-${idx}`}>
                    <td>{issue.packageName}</td>
                    <td>{formatIssueType(issue.type)}</td>
                    <td>
                      <span className={`issue-badge ${issue.severity?.toLowerCase() || "low"}`}>
                        {issue.severity || "LOW"}
                      </span>
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      <div className="trust-table-section">
        <h4 className="trust-section-title">Dependency Validation</h4>
        <div className="trust-table trust-table-scroll">
          <table>
            <thead>
              <tr>
                <th style={dependencyCellStyle}>Package</th>
                <th style={dependencyCellStyle}>Version</th>
                <th style={dependencyCellStyle}>Ecosystem</th>
                <th style={dependencyCellStyle}>Graph</th>
                <th style={dependencyCellStyle}>Scanner</th>
                <th style={dependencyCellStyle}>Confidence</th>
                <th style={dependencyCellStyle}>Provenance</th>
              </tr>
            </thead>
            <tbody>
              {dependencies.length === 0 ? (
                <tr>
                  <td colSpan="7" className="trust-empty-row" style={dependencyCellStyle}>No dependencies available</td>
                </tr>
              ) : (
                dependencies.map((dep, idx) => {
                  // Normalize key for consistency with backend (groupId:artifactId format)
                  const normalizedKey = normalizePackageKey(dep.packageName, dep.groupId, dep.artifactId);
                  const displayName = getDisplayName(normalizedKey);

                  return (
                    <tr
                      key={`dep-${idx}-${normalizedKey}`}
                      className={idx % 2 === 0 ? "dep-row-even" : "dep-row-odd"}
                    >
                      <td style={dependencyCellStyle}>{displayName}</td>
                      <td style={dependencyCellStyle}>{dep.version || "-"}</td>
                      <td style={dependencyCellStyle}>
                        <EcosystemBadge ecosystem={dep.ecosystem} />
                      </td>
                      <td style={dependencyCellStyle}>{formatBool(dep.graphPresent || dep.inGraph)}</td>
                      <td style={dependencyCellStyle}>{formatBool(dep.detectedByScanner || dep.inScanner)}</td>
                      <td style={dependencyCellStyle}>
                        <span className={`confidence-badge ${dep.confidence?.toLowerCase() || "low"}`}>
                          {dep.confidence || "LOW"}
                        </span>
                      </td>
                      <td style={dependencyCellStyle}>
                        <div className="source-badges">
                          {(dep.provenanceCategories || []).map((src) => (
                            <span key={src} className={`source-badge ${src.toLowerCase()}`}>
                              {src}
                            </span>
                          ))}
                        </div>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

function SummaryCard({ label, value, tone }) {
  return (
    <div className={`trust-summary-card ${tone}`}>
      <div className="trust-summary-label">{label}</div>
      <div className="trust-summary-value">{value}</div>
    </div>
  );
}

function MetricCard({ label, value, note }) {
  return (
    <div className="trust-metric-card">
      <div className="trust-metric-label">{label}</div>
      <div className="trust-metric-value">{value}</div>
      {note ? <div className="trust-metric-note">{note}</div> : null}
    </div>
  );
}

function formatPercent(value, available = true) {
  if (!available) return "N/A";
  if (value === null || value === undefined || Number.isNaN(value)) return "-";
  return `${Math.round(Number(value) * 100)}%`;
}

function formatBool(value) {
  return value ? "Yes" : "No";
}

function renderTruthBadge(value, label) {
  if (!value) {
    return <span style={mutedDashStyle}>—</span>;
  }
  return (
    <span style={truthBadgeStyle}>
      <svg width="12" height="12" viewBox="0 0 12 12" fill="none" xmlns="http://www.w3.org/2000/svg" aria-hidden="true">
        <path d="M10 3L4.5 8.5L2 6" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round"/>
      </svg>
      <span>{label}</span>
    </span>
  );
}

function renderTypeTag(value, label, tone) {
  if (!value) {
    return <span style={mutedDashStyle}>—</span>;
  }

  const toneStyle = typeTagStyles[tone] || typeTagStyles.blue;
  return <span style={{ ...typeTagBaseStyle, ...toneStyle }}>{label}</span>;
}

function formatScore(score) {
  if (score === null || score === undefined || Number.isNaN(score)) return "-";
  return Number(score).toFixed(2);
}

function formatIssueType(type) {
  if (!type) return "-";
  return type.replace(/_/g, " ");
}

function formatVisibilityLabel(label) {
  const normalized = String(label || "").toLowerCase();
  if (normalized === "unknown") {
    return "Non-Maven Packages";
  }
  return label;
}
