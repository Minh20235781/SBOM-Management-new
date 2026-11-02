import { useEffect, useState } from "react";
import PageHeader from "../../components/shared/PageHeader";
import DataTable from "../../components/shared/DataTable";
import ErrorBanner from "../../components/shared/ErrorBanner";
import Spinner from "../../components/shared/Spinner";
import EmptyState from "../../components/shared/EmptyState";
import legacyApi from "../../api/legacyApi";
import projectApi from "../../api/projectApi";
import { safeArray } from "../../utils/safe";

/**
 * Insights: a single flat table of the most "interesting" packages
 * across the workspace. Each row carries a composite score that
 * combines vulnerability count and CVSS so a single sort by
 * score (desc) surfaces the worst offenders first.
 *
 * The user picks a project from the dropdown at the top. Without
 * a selection, we default to the project with the most packages
 * (the most useful "all repos" view). The score is computed
 * client-side from the per-package stats payload.
 */
const COLUMNS = [
 { key: "packageName", header: "Package", render: (r) => <b>{r.packageName || r.name}</b> },
 { key: "version", header: "Version", render: (r) => r.version || "—" },
 {
 key: "vulnCount",
 header: "Vulns",
 width: 80,
 align: "right",
 render: (r) => r.vulnCount ?? r.vulnerabilityCount ?? "—",
 },
 {
 key: "highSeverity",
 header: "High",
 width: 80,
 align: "right",
 render: (r) => r.highSeverity ?? "—",
 },
 {
 key: "cvssMax",
 header: "CVSS",
 width: 80,
 align: "right",
 render: (r) => (r.cvssMax != null ? Number(r.cvssMax).toFixed(1) : (r.cvssScore != null ? r.cvssScore.toFixed(1) : "—")),
 },
 {
 key: "score",
 header: "Score",
 width: 100,
 align: "right",
 render: (r) => <b style={{ color: scoreColor(r.score) }}>{r.score != null ? r.score.toFixed(1) : "—"}</b>,
 },
 {
 key: "anomaly",
 header: "Anomaly",
 width: 110,
 align: "right",
 render: (r) => (r.vulnAnomaly != null ? Number(r.vulnAnomaly).toFixed(2) : "—"),
 },
];

/**
 * Composite risk score (0-100). We use a log-scaled blend of
 * vulnerability count and CVSS-max so a single package with
 * 1000 vulns and CVSS 10 doesn't sit at 100 (clamped) while a
 * cleaner package with 5 vulns and CVSS 9 also sits at 100.
 *
 * Components:
 * - vuln density: log10(1 + vulnCount) * 25 → caps at ~100 for 10000 vulns
 * - severity: cvssMax * 10 (cvss 10 = 100)
 * - combined: 60% vuln density + 40% severity, capped at 100
 */
function scoreFor(row) {
 if (typeof row.score === "number") return row.score;
 const v = row.vulnCount || row.vulnerabilityCount || 0;
 const c = row.cvssMax || row.cvssScore || 0;
 const vulnDensity = Math.min(100, Math.log10(1 + v) * 25);
 const severity = c > 0 ? c * 10 : 0;
 return Math.min(100, vulnDensity * 0.6 + severity * 0.4);
}

function scoreColor(score) {
 if (score == null) return "var(--text-muted)";
 if (score >= 70) return "var(--color-danger)";
 if (score >= 40) return "var(--color-warning)";
 return "var(--text-primary)";
}

export default function InsightsPage() {
 const [projects, setProjects] = useState([]);
 const [projectsLoading, setProjectsLoading] = useState(true);
 const [projectId, setProjectId] = useState("");
 const [rows, setRows] = useState([]);
 const [stats, setStats] = useState(null);
 const [loading, setLoading] = useState(true);
 const [error, setError] = useState(null);

 useEffect(() => {
 let cancelled = false;
 (async () => {
 setProjectsLoading(true);
 try {
 const list = safeArray(await projectApi.list());
 if (cancelled) return;
 setProjects(list);
 // Auto-pick the richest project so the page is useful on first
 // paint. User can change it from the dropdown.
 if (list.length > 0 && !projectId) {
 const richest = [...list].sort((a, b) => (b.packageCount || 0) - (a.packageCount || 0))[0];
 setProjectId(richest.id);
 }
 } catch (e) {
 if (!cancelled) setError(e?.message || "Failed to load projects");
 } finally {
 if (!cancelled) setProjectsLoading(false);
 }
 })();
 return () => { cancelled = true; };
 // eslint-disable-next-line react-hooks/exhaustive-deps
 }, []);

 const selectedProject = projects.find((p) => p.id === projectId);

 useEffect(() => {
 // Wait until projects have loaded and a selection exists.
 if (projectsLoading) return;
 if (projects.length > 0 && !selectedProject) {
 // No project picked (empty list) → clear results.
 setRows([]);
 setStats(null);
 return;
 }
 let cancelled = false;
 (async () => {
 setLoading(true);
 setError(null);
 try {
 const [data, st] = await Promise.all([
 legacyApi.topRisky(10, selectedProject?.name || null),
 legacyApi.debugStats(selectedProject?.name || null).catch(() => null),
 ]);
 if (cancelled) return;
 const sorted = safeArray(data)
 .map((r) => ({ ...r, score: scoreFor(r) }))
 .sort((a, b) => (b.score || 0) - (a.score || 0))
 .slice(0, 10);
 setRows(sorted);
 setStats(st);
 } catch (e) {
 if (!cancelled) setError(e?.response?.data || e?.message || "Failed to load insights");
 } finally {
 if (!cancelled) setLoading(false);
 }
 })();
 return () => { cancelled = true; };
 }, [projectId, selectedProject?.name, projectsLoading]);

 return (
 <div>
 <PageHeader
 title="Insights"
 description="Top-ranked packages across the workspace, sorted by composite risk score."
 />

 <div
 style={{
 display: "grid",
 gridTemplateColumns: "repeat(auto-fit, minmax(160px, 1fr))",
 gap: "var(--space-3)",
 marginBottom: "var(--space-4)",
 }}
 >
 <Stat label="Total packages" value={stats?.totalPackages ?? "—"} />
 <Stat label="With vulns" value={stats?.countWithVuln ?? "—"} accent="danger" />
 <Stat label="Without vulns" value={stats?.countWithoutVuln ?? "—"} accent="success" />
 <Stat label="Top scored" value={rows[0]?.score != null ? rows[0].score.toFixed(2) : "—"} accent="warning" />
 </div>

 <div
 style={{
 display: "flex",
 gap: "var(--space-2)",
 alignItems: "center",
 justifyContent: "flex-end",
 marginBottom: "var(--space-3)",
 }}
 >
 <label style={{ fontSize: "var(--text-sm)", color: "var(--text-secondary)" }}>Project</label>
 <select
 value={projectId}
 onChange={(e) => setProjectId(e.target.value ? Number(e.target.value) : "")}
 disabled={projectsLoading || projects.length === 0}
 style={{
 height: 36, padding: "0 12px", border: "1px solid var(--border-default)",
 borderRadius: "var(--radius-md)", fontSize: "var(--text-sm)", background: "var(--bg-surface)", minWidth: 240,
 }}
 >
 {projects.length === 0 && <option value="">(no projects)</option>}
 {projects.map((p) => (
 <option key={p.id} value={p.id}>
 {p.name}{p.packageCount != null ? ` (${p.packageCount} packages)` : ""}
 </option>
 ))}
 </select>
 </div>

 <ErrorBanner error={error} />

 {loading ? (
 <Spinner center size="md" label="Loading insights…" />
 ) : projects.length === 0 && !projectsLoading ? (
 <EmptyState
 title="No projects yet"
 hint="Run a scan from the Scan page to populate insights."
 />
 ) : rows.length === 0 ? (
 <EmptyState
 title={selectedProject ? `No insights for ${selectedProject.name}` : "No insights yet"}
 hint="Trigger a scan to populate package rankings."
 />
 ) : (
 <DataTable
 columns={COLUMNS}
 rows={rows}
 emptyTitle="No packages match the filter"
 />
 )}
 </div>
 );
}

function Stat({ label, value, accent }) {
 const color = {
 danger: "var(--color-danger)",
 success: "var(--color-success)",
 warning: "var(--color-warning)",
 neutral: "var(--text-primary)",
 }[accent || "neutral"];
 return (
 <div
 style={{
 background: "var(--bg-surface)",
 border: "1px solid var(--border-subtle)",
 borderRadius: "var(--radius-lg)",
 padding: "var(--space-4)",
 boxShadow: "var(--shadow-xs)",
 }}
 >
 <div style={{ fontSize: "var(--text-xs)", color: "var(--text-muted)", textTransform: "uppercase", letterSpacing: "0.04em" }}>{label}</div>
 <div style={{ fontSize: "var(--text-2xl)", fontWeight: "var(--weight-semibold)", color, marginTop: 4 }}>{value}</div>
 </div>
 );
}
