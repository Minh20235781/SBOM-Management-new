import { useEffect, useMemo, useState } from "react";
import PageHeader from "../../components/shared/PageHeader";
import DataTable from "../../components/shared/DataTable";
import StatusBadge from "../../components/shared/StatusBadge";
import StatCard from "../../components/shared/StatCard";
import ErrorBanner from "../../components/shared/ErrorBanner";
import Spinner from "../../components/shared/Spinner";
import EmptyState from "../../components/shared/EmptyState";
import projectApi from "../../api/projectApi";
import legacyApi from "../../api/legacyApi";
import { safeArray } from "../../utils/safe";
import styles from "./VulnsPage.module.css";

/**
 * Per-project vulnerabilities page.
 *
 * Two data sources are merged:
 * - /api/projects/{id}/vuln-history: per-CVE status history
 * (NEW / STILL_OPEN / FIXED / REOPENED). Populated by
 * VulnDiffService when a project is re-scanned, so it can be
 * empty for projects that have only been scanned once (e.g.
 * a freshly imported retrofit).
 * - /api/sbom-table: flat per-(package, vulnerability) row
 * list. Always populated for scanned projects, so we use it
 * as a fallback when vuln-history is empty.
 *
 * Rows are keyed by CVE id + package so the same vuln seen in
 * both sources doesn't double-count.
 */
export default function VulnsPage() {
 const [projects, setProjects] = useState([]);
 const [projectId, setProjectId] = useState(null);
 const [status, setStatus] = useState("");
 const [rows, setRows] = useState([]);
 const [stats, setStats] = useState({ new: 0, stillOpen: 0, fixed: 0, reopened: 0 });
 const [loading, setLoading] = useState(false);
 const [error, setError] = useState(null);
 const [source, setSource] = useState("");

 useEffect(() => {
 projectApi
 .list()
 .then((data) => {
 const list = safeArray(data);
 setProjects(list);
 if (list.length > 0) setProjectId(list[0].id);
 })
 .catch((e) => setError(e?.message || "Failed to load projects"));
 }, []);

 useEffect(() => {
 if (projectId == null) return;
 let cancelled = false;
 (async () => {
 setLoading(true);
 setError(null);
 try {
 const [history, statsPayload, sbom] = await Promise.all([
 projectApi.vulnHistory(projectId, status || null, 500).catch(() => []),
 projectApi.vulnStats(projectId).catch(() => null),
 legacyApi.sbomTable(
 projects.find((p) => p.id === projectId)?.name
 ).catch(() => []),
 ]);
 if (cancelled) return;

 const historyRows = safeArray(history);
 // Build a set of (cveId, packagePurl) tuples the history
 // already covers so we don't duplicate them from the SBOM
 // fallback.
 const covered = new Set();
 for (const r of historyRows) {
 covered.add(`${r.vulnId || ""}::${r.packagePurl || ""}`);
 }

 // History rows: full status + first/last seen timestamps.
 const historyDisplay = historyRows.map((r) => ({
 key: `hist-${r.vulnId || ""}-${r.packagePurl || ""}`,
 source: "history",
 vulnId: r.vulnId,
 status: r.status,
 severity: r.severity,
 cvssScore: r.cvssScore,
 packagePurl: r.packagePurl,
 packageName: extractName(r.packagePurl),
 version: extractVersion(r.packagePurl),
 firstSeenAt: r.firstSeenAt,
 lastSeenAt: r.lastSeenAt,
 }));

 // SBOM fallback rows: only include ones not already covered
 // by history. SBOM rows don't carry a status because they
 // predate the diff service; we mark them STILL_OPEN.
 const sbomDisplay = safeArray(sbom)
 .filter((r) => r.vulnerabilities)
 .map((r) => {
 const cve = String(r.vulnerabilities).trim();
 const key = `${cve}::${r.purl || ""}`;
 if (covered.has(key)) return null;
 return {
 key: `sbom-${cve}-${r.purl || r.package_name || Math.random()}`,
 source: "sbom",
 vulnId: cve,
 status: "STILL_OPEN",
 severity: r.severity,
 cvssScore: r.cvss != null ? Number(r.cvss) : null,
 packagePurl: r.purl,
 packageName: r.package_name,
 version: r.version,
 firstSeenAt: null,
 lastSeenAt: null,
 };
 })
 .filter(Boolean);

 const combined = [...historyDisplay, ...sbomDisplay];
 setRows(combined);
 setSource(historyDisplay.length > 0 ? "history" : "sbom");

 // Stats: prefer backend stats; fall back to deriving from
 // the rendered rows.
 if (statsPayload && typeof statsPayload === "object") {
 setStats({
 new: statsPayload.new || 0,
 stillOpen: statsPayload.stillOpen || 0,
 fixed: statsPayload.fixed || 0,
 reopened: statsPayload.reopened || 0,
 });
 } else {
 const counts = { NEW: 0, STILL_OPEN: 0, FIXED: 0, REOPENED: 0 };
 combined.forEach((r) => { if (counts[r.status] != null) counts[r.status]++; });
 setStats({ new: counts.NEW, stillOpen: counts.STILL_OPEN, fixed: counts.FIXED, reopened: counts.REOPENED });
 }
 } catch (e) {
 if (!cancelled) setError(e?.response?.data?.message || e?.message || "Failed to load");
 } finally {
 if (!cancelled) setLoading(false);
 }
 })();
 return () => {
 cancelled = true;
 };
 // eslint-disable-next-line react-hooks/exhaustive-deps
 }, [projectId, status]);

 const filteredRows = useMemo(() => {
 if (!status) return rows;
 return rows.filter((r) => r.status === status);
 }, [rows, status]);

 const columns = [
 {
 key: "vulnId",
 header: "Vulnerability",
 width: 200,
 render: (r) => <code style={{ fontSize: "var(--text-xs)" }}>{r.vulnId || "—"}</code>,
 },
 {
 key: "status",
 header: "Status",
 width: 130,
 render: (r) => <StatusBadge status={r.status} />,
 },
 {
 key: "severity",
 header: "Severity",
 width: 110,
 render: (r) => r.severity || "—",
 },
 {
 key: "cvss",
 header: "CVSS",
 width: 80,
 align: "right",
 render: (r) => (r.cvssScore != null ? r.cvssScore.toFixed(1) : "—"),
 },
 {
 key: "packagePurl",
 header: "Package",
 render: (r) => (
 <span className={styles.purl} title={r.packagePurl || r.packageName || ""}>
 {r.packageName || r.packagePurl || "—"}
 {r.version ? <span style={{ color: "var(--text-muted)", marginLeft: 6 }}>@{r.version}</span> : null}
 </span>
 ),
 },
 {
 key: "firstSeenAt",
 header: "First seen",
 width: 180,
 render: (r) => (r.firstSeenAt ? new Date(r.firstSeenAt).toLocaleString() : r.source === "sbom" ? "From initial scan" : "—"),
 },
 {
 key: "lastSeenAt",
 header: "Last seen",
 width: 180,
 render: (r) => (r.lastSeenAt ? new Date(r.lastSeenAt).toLocaleString() : r.source === "sbom" ? "From initial scan" : "—"),
 },
 ];

 return (
 <div>
 <PageHeader
 title="Vulnerabilities"
 description="Per-project vulnerability status history across the workspace. When a project has only been scanned once, we fall back to the SBOM table so the page is never empty."
 />

 <div
 style={{
 display: "grid",
 gridTemplateColumns: "repeat(auto-fit, minmax(160px, 1fr))",
 gap: "var(--space-3)",
 marginBottom: "var(--space-4)",
 }}
 >
 <StatCard label="New" value={stats.new || 0} accent="info" />
 <StatCard label="Still open" value={stats.stillOpen || 0} accent="warning" />
 <StatCard label="Fixed" value={stats.fixed || 0} accent="success" />
 <StatCard label="Reopened" value={stats.reopened || 0} accent="danger" />
 </div>

 <div className={styles.filters}>
 <select
 className={styles.select}
 value={projectId ?? ""}
 onChange={(e) => setProjectId(Number(e.target.value))}
 >
 {projects.length === 0 && <option value="">(no projects)</option>}
 {projects.map((p) => (
 <option key={p.id} value={p.id}>{p.name}</option>
 ))}
 </select>
 <select
 className={styles.select}
 value={status}
 onChange={(e) => setStatus(e.target.value)}
 >
 <option value="">All statuses</option>
 <option value="NEW">NEW</option>
 <option value="STILL_OPEN">STILL_OPEN</option>
 <option value="FIXED">FIXED</option>
 <option value="REOPENED">REOPENED</option>
 </select>
 {source && (
 <span className={styles.sourceHint}>
 {source === "history"
 ? "From vuln-history (project re-scanned)"
 : "From SBOM table (initial scan only)"}
 </span>
 )}
 </div>

 <ErrorBanner error={error} />

 <DataTable
 columns={columns}
 rows={filteredRows}
 loading={loading}
 emptyTitle="No vulnerability rows"
 emptyHint="Run a scan against the selected project to populate the table."
 />
 </div>
 );
}

/* "pkg:npm/astro@5.18.1" → "astro" / "5.18.1" */
function extractName(purl) {
 if (!purl) return null;
 const m = String(purl).match(/@?([^@/]+)@([^/]+)$/);
 if (m) return m[1];
 return String(purl).split("/").pop() || null;
}
function extractVersion(purl) {
 if (!purl) return null;
 const m = String(purl).match(/@([^/]+)$/);
 return m ? m[1] : null;
}
