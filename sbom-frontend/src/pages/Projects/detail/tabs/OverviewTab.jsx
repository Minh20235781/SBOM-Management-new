import { useState } from "react";
import StatCard from "../../../../components/shared/StatCard";
import Button from "../../../../components/shared/Button";
import ErrorBanner from "../../../../components/shared/ErrorBanner";
import RiskTrendChart from "../../../../components/charts/RiskTrendChart";
import RecentCommits from "../../../../components/projects/detail/RecentCommits";
import projectApi from "../../../../api/projectApi";
import styles from "./OverviewTab.module.css";

/**
 * Top-level "Overview" tab for a project workspace. Shows the
 * latest risk snapshot, module/repo counts, vuln status, and a
 * small trend chart spanning the last scans.
 */
export default function OverviewTab({ project, modules, latestRisk, vulnStats, riskRows, onDataChanged }) {
 const score = latestRisk?.score;
 const grade = latestRisk?.grade;
 const [recomputing, setRecomputing] = useState(false);
 const [recomputeError, setRecomputeError] = useState(null);
 const [recomputeOk, setRecomputeOk] = useState(false);
 // pendingCount is owned by the tab (not the hook) because the
 // value comes from RecentCommits which fetches on its own
 // schedule. null = "not loaded yet" → render skeleton.
 const [pendingCount, setPendingCount] = useState(null);

 const handleRecompute = async () => {
 if (!project?.id) return;
 setRecomputing(true);
 setRecomputeError(null);
 setRecomputeOk(false);
 try {
 await projectApi.recomputeRisk(project.id);
 setRecomputeOk(true);
 // Ask the parent page to refetch risk / vuln data so the
 // score and trend refresh without a manual page reload.
 if (typeof onDataChanged === "function") onDataChanged();
 } catch (err) {
 setRecomputeError(err?.response?.data?.message || err?.message || "Recompute failed");
 } finally {
 setRecomputing(false);
 }
 };

 return (
 <div>
 <div className={styles.grid}>
 <StatCard label="Modules" value={modules.length} subValue="Logical units inside this project" />
 <StatCard
 label="Awaiting scan"
 value={pendingCount == null ? "—" : pendingCount}
 subValue="Commits newer than last scan"
 accent={pendingCount == null ? "neutral" : (pendingCount > 0 ? "info" : "neutral")}
 />
 <StatCard label="Packages" value={project.packageCount ?? "—"} subValue="Tracked by the latest scan" accent="primary" />
 <StatCard
 label="Open Vulnerabilities"
 value={(vulnStats.new || 0) + (vulnStats.stillOpen || 0)}
 subValue="NEW + STILL_OPEN"
 accent="warning"
 />
 <StatCard label="Fixed" value={vulnStats.fixed || 0} accent="success" />
 <StatCard
 label="Latest Score"
 value={score == null ? "—" : score.toFixed(1)}
 subValue={grade ? `Grade ${grade}` : "No scans yet"}
 accent={scoreTone(score)}
 />
 </div>

 <div className={styles.card}>
 <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", gap: "var(--space-3)", flexWrap: "wrap" }}>
 <div>
 <h3 className={styles.cardTitle} style={{ margin: 0 }}>Risk snapshot</h3>
 <p className={styles.subtle} style={{ margin: "4px 0 0 0" }}>
 Compute a fresh risk assessment for this project from the packages/vulns already in the database — useful when a scan ran before the auto-snapshot wiring, or after a manual data fix.
 </p>
 </div>
 <Button
 type="button"
 variant="secondary"
 size="sm"
 onClick={handleRecompute}
 disabled={recomputing}
 title="Recompute the latest risk score and vuln diff from existing data, no Trivy scan"
 >
 {recomputing ? "Recomputing…" : "Recompute snapshot"}
 </Button>
 </div>
 {recomputeError && (
 <div style={{ marginTop: "var(--space-3)" }}>
 <ErrorBanner error={recomputeError} />
 </div>
 )}
 {recomputeOk && !recomputeError && (
 <p className={styles.subtle} style={{ marginTop: "var(--space-3)", color: "var(--color-success, #15803d)" }}>
 Snapshot updated. The cards above and the trend chart will refresh in a moment.
 </p>
 )}
 </div>

 {latestRisk && (
 <div className={styles.card}>
 <h3 className={styles.cardTitle}>Latest scan</h3>
 <p className={styles.subtle}>
 {latestRisk.assessedAt ? new Date(latestRisk.assessedAt).toLocaleString() : "—"}
 </p>
 <div className={styles.metricRow}>
 <span>Critical: <b>{latestRisk.criticalCount}</b></span>
 <span>High: <b>{latestRisk.highCount}</b></span>
 <span>Medium: <b>{latestRisk.mediumCount}</b></span>
 <span>Low: <b>{latestRisk.lowCount}</b></span>
 <span>Total: <b>{latestRisk.totalVulnerabilities}</b></span>
 <span>Packages: <b>{latestRisk.totalPackages}</b></span>
 </div>
 </div>
 )}

 <div className={styles.card}>
 <h3 className={styles.cardTitle}>Risk trend</h3>
 <p className={styles.subtle}>
 Score, vulnerability count, and critical findings across all scans for this project.
 </p>
 <RiskTrendChart rows={riskRows} height={260} />
 </div>

 <RecentCommits
 project={project}
 moduleId={modules?.[0]?.id ?? null}
 onRescanned={typeof onDataChanged === "function" ? onDataChanged : undefined}
 onPendingCountChange={setPendingCount}
 />
 </div>
 );
}

function scoreTone(score) {
 if (score == null) return "neutral";
 if (score >= 80) return "success";
 if (score >= 60) return "warning";
 return "danger";
}
