import { useEffect, useState } from "react";
import {
 CartesianGrid,
 Legend,
 Line,
 LineChart,
 ResponsiveContainer,
 Tooltip,
 XAxis,
 YAxis,
} from "recharts";
import { Link } from "react-router-dom";
import PageHeader from "../../components/shared/PageHeader";
import StatCard from "../../components/shared/StatCard";
import StatusBadge from "../../components/shared/StatusBadge";
import Button from "../../components/shared/Button";
import projectApi from "../../api/projectApi";
import auditApi from "../../api/auditApi";
import { safeArray } from "../../utils/safe";
import styles from "./MainDashboard.module.css";

/**
 * Central hub. Loads every project in parallel, then for each one
 * pulls its risk assessments + vuln stats. We aggregate per-project
 * numbers into system-wide stats and concatenate the assessment
 * history to render the trend chart.
 *
 * Recent activity is the union of all audit-timeline events
 * across all projects, sorted DESC and capped to 20.
 */
export default function MainDashboard() {
 const [stats, setStats] = useState(null);
 const [trend, setTrend] = useState([]);
 const [activity, setActivity] = useState([]);
 const [loading, setLoading] = useState(true);
 const [error, setError] = useState(null);

 useEffect(() => {
 let cancelled = false;
 (async () => {
 setLoading(true);
 setError(null);
 try {
 const projects = safeArray(await projectApi.list());
 if (cancelled) return;

 // Pull risk + vuln stats in parallel per project.
 const perProject = await Promise.all(
 projects.map(async (p) => {
 try {
 const [ra, vs] = await Promise.all([
 projectApi.riskAssessments(p.id, 200).catch(() => []),
 projectApi.vulnStats(p.id).catch(() => ({
 new: 0, stillOpen: 0, fixed: 0, reopened: 0,
 })),
 ]);
 return { project: p, assessments: ra, vulnStats: vs };
 } catch {
 return { project: p, assessments: [], vulnStats: { new: 0, stillOpen: 0, fixed: 0, reopened: 0 } };
 }
 })
 );

 // Aggregate.
 let totalCritical = 0;
 let totalHigh = 0;
 let totalVulns = 0;
 const allAssessments = [];
 let scoreSum = 0;
 let scoreCount = 0;
 for (const { assessments, vulnStats } of perProject) {
 totalVulns += vulnStats.stillOpen + vulnStats.new;
 for (const ra of assessments) {
 totalCritical += ra.criticalCount || 0;
 totalHigh += ra.highCount || 0;
 if (typeof ra.score === "number") {
 scoreSum += ra.score;
 scoreCount++;
 }
 allAssessments.push(ra);
 }
 }
 const avgScore = scoreCount > 0 ? scoreSum / scoreCount : null;

 // Sort assessments by time ASC for the trend chart.
 const trendData = [...allAssessments]
 .sort((a, b) => new Date(a.assessedAt) - new Date(b.assessedAt))
 .map((ra) => ({
 when: new Date(ra.assessedAt),
 label: new Date(ra.assessedAt).toLocaleString(undefined, {
 month: "short",
 day: "2-digit",
 hour: "2-digit",
 minute: "2-digit",
 }),
 score: ra.score,
 vulns: ra.totalVulnerabilities,
 critical: ra.criticalCount,
 }));

 // Recent activity: top 20 events across all projects.
 const activityLists = await Promise.all(
 projects.map((p) =>
 auditApi
 .timeline({ projectId: p.id, limit: 20 })
 .catch(() => [])
 .then((events) => events.map((e) => ({ ...e, projectName: p.name })))
 )
 );
 const merged = activityLists
 .flat()
 .filter((e) => e && e.timestamp)
 .sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp))
 .slice(0, 20);

 if (cancelled) return;
 setStats({
 totalProjects: projects.length,
 totalCritical,
 totalHigh,
 totalVulns,
 avgScore,
 recentScans: allAssessments.length,
 });
 setTrend(trendData);
 setActivity(merged);
 } catch (e) {
 if (!cancelled) setError(e?.message || "Failed to load dashboard");
 } finally {
 if (!cancelled) setLoading(false);
 }
 })();
 return () => {
 cancelled = true;
 };
 }, []);

 return (
 <div>
 <PageHeader
 title="Dashboard"
 description="System-wide view of projects, vulnerabilities, and scan history."
 actions={
 <Button variant="secondary" size="sm" onClick={() => window.location.reload()}>
 Refresh
 </Button>
 }
 />

 {error && (
 <div style={{ padding: "12px 16px", background: "var(--color-danger-soft)", color: "var(--color-danger)", borderRadius: "var(--radius-md)", marginBottom: 16 }}>
 {error}
 </div>
 )}

 <div className={styles.statGrid}>
 <StatCard
 label="Total Projects"
 value={stats?.totalProjects ?? "—"}
 subValue="Across all workspaces"
 accent="primary"
 />
 <StatCard
 label="Open Vulnerabilities"
 value={stats?.totalVulns ?? "—"}
 subValue="NEW + STILL_OPEN"
 accent="warning"
 />
 <StatCard
 label="Critical Findings"
 value={stats?.totalCritical ?? "—"}
 subValue="Across latest scans"
 accent="danger"
 />
 <StatCard
 label="Average Score"
 value={stats?.avgScore == null ? "—" : stats.avgScore.toFixed(1)}
 subValue={stats?.recentScans ? `${stats.recentScans} scans tracked` : "No scans yet"}
 accent={scoreTone(stats?.avgScore)}
 />
 </div>

 <div className={styles.grid}>
 <div className={styles.chartCard}>
 <div className={styles.chartHeader}>
 <div>
 <h2 className={styles.chartTitle}>Risk score trend</h2>
 <p className={styles.chartSubtitle}>
 Score over time across all projects, with vulnerability count overlay.
 </p>
 </div>
 <div className={styles.legend}>
 <LegendItem color="#2563eb" label="Score" />
 <LegendItem color="#94a3b8" label="Vulns" />
 <LegendItem color="#dc2626" label="Critical" />
 </div>
 </div>
 {trend.length === 0 ? (
 <div className={styles.empty}>No scans yet. Run a scan to populate the trend.</div>
 ) : (
 <ResponsiveContainer width="100%" height={300}>
 <LineChart data={trend} margin={{ top: 8, right: 16, bottom: 8, left: 0 }}>
 <CartesianGrid strokeDasharray="3 3" stroke="var(--border-subtle)" />
 <XAxis
 dataKey="label"
 stroke="var(--text-muted)"
 fontSize={11}
 tickLine={false}
 />
 <YAxis
 yAxisId="left"
 stroke="var(--color-primary)"
 fontSize={11}
 domain={[0, 100]}
 tickLine={false}
 />
 <YAxis
 yAxisId="right"
 orientation="right"
 stroke="var(--text-muted)"
 fontSize={11}
 tickLine={false}
 />
 <Tooltip
 contentStyle={{
 fontSize: "var(--text-sm)",
 border: "1px solid var(--border-subtle)",
 borderRadius: "var(--radius-md)",
 boxShadow: "var(--shadow-md)",
 }}
 />
 <Line yAxisId="left" type="monotone" dataKey="score" stroke="#2563eb" strokeWidth={2} dot={{ r: 3 }} name="Score" />
 <Line yAxisId="right" type="monotone" dataKey="vulns" stroke="#94a3b8" strokeWidth={1.5} dot={{ r: 2 }} name="Vulns" />
 <Line yAxisId="right" type="monotone" dataKey="critical" stroke="#dc2626" strokeWidth={1.5} dot={{ r: 2 }} name="Critical" />
 </LineChart>
 </ResponsiveContainer>
 )}
 </div>

 <div className={styles.activityCard}>
 <div className={styles.cardHeader}>
 <h2 className={styles.cardTitle}>Recent activity</h2>
 <Link to="/audit" style={{ fontSize: "var(--text-xs)" }}>
 View all →
 </Link>
 </div>
 {activity.length === 0 ? (
 <div className={styles.empty}>No activity yet.</div>
 ) : (
 <div className={styles.activityList}>
 {activity.map((e, idx) => (
 <div key={idx} className={styles.activityItem}>
 <div
 className={styles.activityDot}
 style={{ background: typeColor(e.type) }}
 aria-hidden="true"
 />
 <div className={styles.activityBody}>
 <p className={styles.activitySummary}>{e.summary || e.action || e.type}</p>
 <div className={styles.activityMeta}>
 <StatusBadge status={e.type} withDot={false} />
 {e.projectName && <span>· {e.projectName}</span>}
 <span>· {e.timestamp ? new Date(e.timestamp).toLocaleString() : "—"}</span>
 </div>
 </div>
 </div>
 ))}
 </div>
 )}
 </div>
 </div>
 </div>
 );
}

function LegendItem({ color, label }) {
 return (
 <span className={styles.legendItem}>
 <span className={styles.legendSwatch} style={{ background: color }} />
 {label}
 </span>
 );
}

function scoreTone(score) {
 if (score == null) return "neutral";
 if (score >= 80) return "success";
 if (score >= 60) return "warning";
 return "danger";
}

function typeColor(t) {
 switch (t) {
 case "PROJECT": return "#2563eb";
 case "MODULE": return "#0ea5e9";
 case "REPO_CONFIG": return "#8b5cf6";
 case "SBOM_FILE": return "#16a34a";
 case "RISK_ASSESSMENT": return "#ea580c";
 case "VULN": return "#dc2626";
 default: return "#64748b";
 }
}
