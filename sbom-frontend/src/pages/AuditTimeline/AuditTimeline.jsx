import { useEffect, useState } from "react";
import PageHeader from "../../components/shared/PageHeader";
import StatusBadge from "../../components/shared/StatusBadge";
import ErrorBanner from "../../components/shared/ErrorBanner";
import projectApi from "../../api/projectApi";
import auditApi from "../../api/auditApi";
import { safeArray } from "../../utils/safe";
import styles from "./AuditTimeline.module.css";

/**
 * Global audit timeline. User picks a project (and optionally a
 * type filter) and gets a vertical timeline of cross-entity
 * events. Capped at 200 events for performance.
 */
export default function AuditTimeline() {
 const [projects, setProjects] = useState([]);
 const [projectId, setProjectId] = useState(null);
 const [type, setType] = useState("");
 const [events, setEvents] = useState([]);
 const [loading, setLoading] = useState(false);
 const [error, setError] = useState(null);

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
 const data = await auditApi.timeline({ projectId, type: type || undefined, limit: 200 });
 if (!cancelled) setEvents(safeArray(data));
 } catch (e) {
 if (!cancelled) setError(e?.response?.data?.message || e?.message || "Failed to load timeline");
 } finally {
 if (!cancelled) setLoading(false);
 }
 })();
 return () => {
 cancelled = true;
 };
 }, [projectId, type]);

 return (
 <div>
 <PageHeader
 title="Audit Timeline"
 description="Cross-entity history: project, module, repo, SBOM, scan, and vulnerability changes."
 />

 <div className={styles.filters}>
 <label style={{ fontSize: "var(--text-sm)", color: "var(--text-secondary)" }}>Project</label>
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

 <label style={{ fontSize: "var(--text-sm)", color: "var(--text-secondary)" }}>Type</label>
 <select
 className={styles.select}
 value={type}
 onChange={(e) => setType(e.target.value)}
 >
 <option value="">All types</option>
 <option value="PROJECT">Project</option>
 <option value="MODULE">Module</option>
 <option value="REPO_CONFIG">Repo config</option>
 <option value="SBOM_FILE">SBOM file</option>
 <option value="RISK_ASSESSMENT">Risk assessment</option>
 <option value="VULN">Vulnerability</option>
 </select>
 </div>

 <ErrorBanner error={error} />

 {loading ? (
 <div style={{ color: "var(--text-muted)", padding: "var(--space-6) 0" }}>Loading…</div>
 ) : events.length === 0 ? (
 <div
 style={{
 background: "var(--bg-surface)",
 border: "1px dashed var(--border-default)",
 borderRadius: "var(--radius-lg)",
 padding: "var(--space-10)",
 textAlign: "center",
 color: "var(--text-muted)",
 }}
 >
 No events to show.
 </div>
 ) : (
 <div
 style={{
 background: "var(--bg-surface)",
 border: "1px solid var(--border-subtle)",
 borderRadius: "var(--radius-lg)",
 boxShadow: "var(--shadow-xs)",
 }}
 >
 <ul className={styles.timeline}>
 {events.map((e, idx) => (
 <li key={idx} className={styles.item}>
 <span
 className={styles.dot}
 style={{ background: typeColor(e.type) }}
 aria-hidden="true"
 />
 <div className={styles.meta}>
 <StatusBadge status={e.type} withDot={false} />
 {e.action && <StatusBadge status={e.action} withDot={false} />}
 <span className={styles.timestamp}>
 {e.timestamp ? new Date(e.timestamp).toLocaleString() : "—"}
 </span>
 </div>
 <p className={styles.summary}>{e.summary}</p>
 </li>
 ))}
 </ul>
 </div>
 )}
 </div>
 );
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
