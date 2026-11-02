import { useEffect, useState } from "react";
import StatCard from "../../../../components/shared/StatCard";
import DataTable from "../../../../components/shared/DataTable";
import StatusBadge from "../../../../components/shared/StatusBadge";
import ErrorBanner from "../../../../components/shared/ErrorBanner";
import Spinner from "../../../../components/shared/Spinner";
import projectApi from "../../../../api/projectApi";
import { safeArray } from "../../../../utils/safe";

export default function VulnsTab({ project }) {
 const [status, setStatus] = useState("");
 const [rows, setRows] = useState([]);
 const [stats, setStats] = useState({ new: 0, stillOpen: 0, fixed: 0, reopened: 0 });
 const [loading, setLoading] = useState(true);
 const [error, setError] = useState(null);

 useEffect(() => {
 let cancelled = false;
 (async () => {
 setLoading(true);
 setError(null);
 try {
 const [data, st] = await Promise.all([
 projectApi.vulnHistory(project.id, status || null, 200),
 projectApi.vulnStats(project.id),
 ]);
 if (cancelled) return;
 setRows(safeArray(data));
 setStats(st);
 } catch (e) {
 if (!cancelled) setError(e?.response?.data?.message || e?.message || "Failed to load");
 } finally {
 if (!cancelled) setLoading(false);
 }
 })();
 return () => { cancelled = true; };
 }, [project.id, status]);

 const columns = [
 { key: "vulnId", header: "Vulnerability", width: 220, render: (r) => <code style={{ fontSize: "var(--text-xs)" }}>{r.vulnId}</code> },
 { key: "status", header: "Status", width: 130, render: (r) => <StatusBadge status={r.status} /> },
 { key: "severity", header: "Severity", width: 110, render: (r) => r.severity || "—" },
 { key: "cvss", header: "CVSS", width: 80, align: "right", render: (r) => (r.cvssScore != null ? r.cvssScore.toFixed(1) : "—") },
 {
 key: "packagePurl",
 header: "Package",
 render: (r) => (
 <span style={{ display: "inline-block", maxWidth: 320, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap", verticalAlign: "bottom" }} title={r.packagePurl || ""}>
 {r.packagePurl || "—"}
 </span>
 ),
 },
 { key: "firstSeenAt", header: "First seen", width: 180, render: (r) => (r.firstSeenAt ? new Date(r.firstSeenAt).toLocaleString() : "—") },
 { key: "lastSeenAt", header: "Last seen", width: 180, render: (r) => (r.lastSeenAt ? new Date(r.lastSeenAt).toLocaleString() : "—") },
 ];

 if (loading) return <Spinner center size="md" label="Loading vulnerabilities…" />;

 return (
 <div>
 <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(160px, 1fr))", gap: "var(--space-3)", marginBottom: "var(--space-4)" }}>
 <StatCard label="New" value={stats.new || 0} accent="info" />
 <StatCard label="Still open" value={stats.stillOpen || 0} accent="warning" />
 <StatCard label="Fixed" value={stats.fixed || 0} accent="success" />
 <StatCard label="Reopened" value={stats.reopened || 0} accent="danger" />
 </div>

 <ErrorBanner error={error} />

 <div style={{ display: "flex", justifyContent: "flex-end", marginBottom: "var(--space-3)" }}>
 <select
 value={status}
 onChange={(e) => setStatus(e.target.value)}
 style={{
 height: 36, padding: "0 12px", border: "1px solid var(--border-default)",
 borderRadius: "var(--radius-md)", fontSize: "var(--text-sm)", background: "var(--bg-surface)",
 }}
 >
 <option value="">All statuses</option>
 <option value="NEW">NEW</option>
 <option value="STILL_OPEN">STILL_OPEN</option>
 <option value="FIXED">FIXED</option>
 <option value="REOPENED">REOPENED</option>
 </select>
 </div>

 <DataTable
 columns={columns}
 rows={rows}
 emptyTitle="No vulnerability rows"
 emptyHint="Run a scan against this project to populate the vuln history."
 />
 </div>
 );
}
