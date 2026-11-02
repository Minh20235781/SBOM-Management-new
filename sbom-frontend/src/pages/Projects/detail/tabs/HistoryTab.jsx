import { useEffect, useState } from "react";
import StatusBadge from "../../../../components/shared/StatusBadge";
import ErrorBanner from "../../../../components/shared/ErrorBanner";
import Spinner from "../../../../components/shared/Spinner";
import projectApi from "../../../../api/projectApi";
import auditApi from "../../../../api/auditApi";
import styles from "./HistoryTab.module.css";

/**
 * History tab. Two side-by-side panels: per-mutation project
 * history and the cross-entity audit timeline (Phase 5).
 */
export default function HistoryTab({ project }) {
 const [projectHistory, setProjectHistory] = useState([]);
 const [auditEvents, setAuditEvents] = useState([]);
 const [loading, setLoading] = useState(true);
 const [error, setError] = useState(null);

 useEffect(() => {
 let cancelled = false;
 (async () => {
 setLoading(true);
 setError(null);
 try {
 const [ph, ae] = await Promise.all([
 projectApi.history(project.id).catch(() => []),
 auditApi.timeline({ projectId: project.id, limit: 100 }).catch(() => []),
 ]);
 if (cancelled) return;
 setProjectHistory(ph);
 setAuditEvents(ae);
 } catch (e) {
 if (!cancelled) setError(e?.message || "Failed to load history");
 } finally {
 if (!cancelled) setLoading(false);
 }
 })();
 return () => { cancelled = true; };
 }, [project.id]);

 if (loading) return <Spinner center size="md" label="Loading history…" />;
 if (error) return <ErrorBanner error={error} />;

 return (
 <div className={styles.grid}>
 <div className={styles.card}>
 <div className={styles.cardHeader}><h3 className={styles.cardTitle}>Project history</h3></div>
 <div className={styles.cardBody}>
 {projectHistory.length === 0 ? (
 <div style={{ padding: "var(--space-6)", color: "var(--text-muted)", textAlign: "center" }}>No project changes yet.</div>
 ) : (
 <ul className={styles.timeline}>
 {projectHistory.map((h) => (
 <li key={h.id} className={styles.timelineItem}>
 <span className={styles.timelineDot} style={{ background: typeColor(h.changeType) }} aria-hidden="true" />
 <div className={styles.timelineMeta}>
 <StatusBadge status={h.changeType} withDot={false} />
 <span className={styles.timestamp}>{h.changedAt ? new Date(h.changedAt).toLocaleString() : "—"}</span>
 <span className={styles.timestamp}>· v{h.version}</span>
 </div>
 </li>
 ))}
 </ul>
 )}
 </div>
 </div>

 <div className={styles.card}>
 <div className={styles.cardHeader}><h3 className={styles.cardTitle}>Audit timeline</h3></div>
 <div className={styles.cardBody}>
 {auditEvents.length === 0 ? (
 <div style={{ padding: "var(--space-6)", color: "var(--text-muted)", textAlign: "center" }}>No events yet.</div>
 ) : (
 <ul className={styles.timeline}>
 {auditEvents.map((e, idx) => (
 <li key={idx} className={styles.timelineItem}>
 <span className={styles.timelineDot} style={{ background: typeColor(e.type) }} aria-hidden="true" />
 <div className={styles.timelineMeta}>
 <StatusBadge status={e.type} withDot={false} />
 {e.action && <StatusBadge status={e.action} withDot={false} />}
 <span className={styles.timestamp}>{e.timestamp ? new Date(e.timestamp).toLocaleString() : "—"}</span>
 </div>
 <p className={styles.timelineSummary}>{e.summary}</p>
 </li>
 ))}
 </ul>
 )}
 </div>
 </div>
 </div>
 );
}

function typeColor(t) {
 switch (t) {
 case "PROJECT": case "CREATED": return "#2563eb";
 case "MODULE": return "#0ea5e9";
 case "REPO_CONFIG": case "UPDATED": return "#8b5cf6";
 case "SBOM_FILE": return "#16a34a";
 case "RISK_ASSESSMENT": case "SCORED": return "#ea580c";
 case "FIXED": return "#16a34a";
 case "REOPENED": case "DELETED": return "#dc2626";
 case "NEW": return "#0ea5e9";
 default: return "#64748b";
 }
}
