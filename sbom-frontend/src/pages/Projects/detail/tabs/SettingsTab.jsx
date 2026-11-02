import { useState } from "react";
import Button from "../../../../components/shared/Button";
import Modal from "../../../../components/shared/Modal";
import StatusBadge from "../../../../components/shared/StatusBadge";
import ErrorBanner from "../../../../components/shared/ErrorBanner";
import ProjectFormModal from "../../../../components/modals/ProjectFormModal";
import projectApi from "../../../../api/projectApi";
import styles from "./SettingsTab.module.css";

/**
 * Settings tab. Shows the project's metadata and a "Reset
 * project data" card. Edits are handled by re-opening the
 * shared ProjectFormModal.
 *
 * The previous "Delete project" + Danger zone was removed:
 * the backend always refused deletion once any package was
 * linked (HTTP 409), so the UI button was effectively dead.
 * To start over, use Reset + a fresh Trivy scan instead.
 */
export default function SettingsTab({ project, onChanged }) {
 const [editing, setEditing] = useState(false);
 const [confirmingReset, setConfirmingReset] = useState(false);
 const [resetting, setResetting] = useState(false);
 const [resetError, setResetError] = useState(null);
 const [resetResult, setResetResult] = useState(null);

 const handleSave = async (payload) => {
 await projectApi.update(project.id, payload);
 setEditing(false);
 onChanged?.();
 };

 const handleReset = async () => {
 setResetting(true);
 setResetError(null);
 setResetResult(null);
 try {
 const result = await projectApi.reset(project.id);
 setResetResult(result);
 // Refresh the page-level data so the stat cards, trend
 // chart, and vulns tab all reflect the wiped state.
 if (typeof onChanged === "function") onChanged();
 } catch (e) {
 setResetError(e?.response?.data?.message || e?.message || "Reset failed");
 } finally {
 setResetting(false);
 setConfirmingReset(false);
 }
 };

 return (
 <div>
 <div className={styles.section}>
 <h3 className={styles.sectionTitle}>Project metadata</h3>
 <p className={styles.sectionSubtitle}>Read-only summary. Click "Edit" to change.</p>

 <div className={styles.metaRow}><div className={styles.metaLabel}>Name</div><div className={styles.metaValue}>{project.name}</div></div>
 <div className={styles.metaRow}><div className={styles.metaLabel}>Description</div><div className={styles.metaValue}>{project.description || <em style={{ color: "var(--text-muted)" }}>No description</em>}</div></div>
 <div className={styles.metaRow}><div className={styles.metaLabel}>Status</div><div className={styles.metaValue}><StatusBadge status={project.status} /></div></div>
 <div className={styles.metaRow}><div className={styles.metaLabel}>Version</div><div className={styles.metaValue}>v{project.version}</div></div>
 <div className={styles.metaRow}><div className={styles.metaLabel}>Created</div><div className={styles.metaValue}>{project.createdAt ? new Date(project.createdAt).toLocaleString() : "—"}</div></div>
 <div className={styles.metaRow}><div className={styles.metaLabel}>Last updated</div><div className={styles.metaValue}>{project.updatedAt ? new Date(project.updatedAt).toLocaleString() : "—"}</div></div>

 <div className={styles.actions}><Button variant="primary" size="sm" onClick={() => setEditing(true)}>Edit project</Button></div>
 </div>

 <div className={styles.section}>
 <h3 className={styles.sectionTitle}>Reset project data</h3>
 <p className={styles.sectionSubtitle}>
 Use this when you want to re-scan a project from a clean slate. The project row, its description, and the audit history are kept — but every package link, vulnerability row, dependency-graph edge, risk snapshot, and vuln-status history is wiped. Run a fresh Trivy scan afterwards to repopulate.
 </p>
 {resetResult && (
 <p className={styles.sectionSubtitle} style={{ color: "var(--color-success, #15803d)" }}>
 Cleared: {JSON.stringify(resetResult.cleared)}
 </p>
 )}
 <div className={styles.actions}>
 <Button variant="secondary" size="sm" onClick={() => setConfirmingReset(true)}>
 Reset data
 </Button>
 </div>
 </div>

 {editing && <ProjectFormModal initial={project} onClose={() => setEditing(false)} onSave={handleSave} />}

 {confirmingReset && (
 <Modal
 title="Reset project data"
 onClose={() => !resetting && setConfirmingReset(false)}
 size="sm"
 footer={
 <>
 <Button variant="secondary" onClick={() => setConfirmingReset(false)} disabled={resetting}>Cancel</Button>
 <Button variant="danger" onClick={handleReset} disabled={resetting}>{resetting ? "Resetting…" : "Reset"}</Button>
 </>
 }
 >
 <p style={{ color: "var(--text-secondary)", margin: 0 }}>
 This will wipe every package, vulnerability, dependency edge, risk snapshot, and vuln-status row linked to <strong>{project.name}</strong>. The project row itself stays. You'll need to run a fresh Trivy scan afterwards to repopulate the data.
 </p>
 <ErrorBanner error={resetError} />
 </Modal>
 )}
 </div>
 );
}
