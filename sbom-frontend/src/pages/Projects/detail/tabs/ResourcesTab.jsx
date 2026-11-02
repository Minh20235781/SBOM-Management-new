import { useEffect, useState } from "react";
import DataTable from "../../../../components/shared/DataTable";
import Button from "../../../../components/shared/Button";
import StatusBadge from "../../../../components/shared/StatusBadge";
import Modal from "../../../../components/shared/Modal";
import ErrorBanner from "../../../../components/shared/ErrorBanner";
import ConfirmDialog, { useConfirm } from "../../../../components/shared/ConfirmDialog";
import { toast } from "../../../../components/shared/Toaster";
import { Field, Input } from "../../../../components/shared/Form";
import RecentCommits from "../../../../components/projects/detail/RecentCommits";
import projectDetailApi from "../../../../api/projectDetailApi";
import { safeArray } from "../../../../utils/safe";
import styles from "./ResourcesTab.module.css";

/**
 * Resources tab: modules + SBOM files + recent upstream commits.
 * The "Repo configs" section was removed — the same data is now
 * surfaced through {@link RecentCommits}, which decorates each
 * commit with the project-local scan state (new / scanned /
 * no-impact). Trivy scans pick the upstream URL straight from
 * the project description, so no RepoConfig row is required.
 */
export default function ResourcesTab({ project, onChanged }) {
 const [modules, setModules] = useState([]);
 const [loading, setLoading] = useState(true);
 const [error, setError] = useState(null);
 const [moduleId, setModuleId] = useState(null);
 const [files, setFiles] = useState([]);
 const [modal, setModal] = useState(null);
 const [detect, setDetect] = useState(null);
 const [detecting, setDetecting] = useState(false);
 const [detectError, setDetectError] = useState(null);
 const [addingDetected, setAddingDetected] = useState(false);
 const { confirm: confirmDialog, node: confirmNode } = useConfirm();

 const loadAll = async () => {
 setLoading(true);
 setError(null);
 try {
 const mods = await projectDetailApi.listModules(project.id).catch(() => []);
 setModules(safeArray(mods));
 if (!moduleId && mods.length > 0) setModuleId(mods[0].id);
 } catch (e) {
 setError(e?.response?.data?.message || e?.message || "Failed to load");
 } finally {
 setLoading(false);
 }
 };

 const loadFiles = async (mid) => {
 if (mid == null) {
 setFiles([]);
 return;
 }
 try {
 setFiles(safeArray(await projectDetailApi.listSbomFiles(project.id, mid)));
 } catch (e) {
 setFiles([]);
 }
 };

 const loadDetected = async () => {
 setDetecting(true);
 setDetectError(null);
 try {
 const res = await projectDetailApi.autoDetectModules(project.id);
 setDetect(res);
 } catch (e) {
 setDetectError(e?.response?.data?.message || e?.message || "Auto-detect failed");
 setDetect(null);
 } finally {
 setDetecting(false);
 }
 };

 const addDetectedAsModule = async (mod) => {
 setAddingDetected(true);
 try {
 await projectDetailApi.createModule(project.id, {
 name: mod.name,
 pathInRepo: mod.pathInRepo || null,
 sbomPattern: "**/sbom.json",
 });
 await loadAll();
 await loadDetected();
 onChanged?.();
 } catch (e) {
 alert(e?.response?.data?.message || e?.message || "Could not add module");
 } finally {
 setAddingDetected(false);
 }
 };

 const addAllDetectedAsModules = async () => {
 if (!detect || !Array.isArray(detect.modules) || detect.modules.length === 0) return;
 // Skip ones already present (same name + path).
 const existing = new Set(
 modules.map((m) => `${m.name}::${m.pathInRepo || ""}`)
 );
 const toAdd = detect.modules.filter(
 (m) => !existing.has(`${m.name}::${m.pathInRepo || ""}`)
 );
 if (toAdd.length === 0) {
 toast("All suggested modules are already added.", { icon: "ℹ️" });
 return;
 }
 const ok = await confirmDialog(
 `Add ${toAdd.length} module(s) to this project?\n\n` +
 toAdd.map((m) => `• ${m.name}`).slice(0, 20).join("\n") +
 (toAdd.length > 20 ? `\n…and ${toAdd.length - 20} more` : ""),
 { title: "Add all modules", confirmText: "Add all", tone: "primary" }
 );
 if (!ok) return;
 setAddingDetected(true);
 let added = 0;
 let failed = 0;
 for (const m of toAdd) {
 try {
 await projectDetailApi.createModule(project.id, {
 name: m.name,
 pathInRepo: m.pathInRepo || null,
 sbomPattern: "**/sbom.json",
 });
 added++;
 } catch (e) {
 failed++;
 }
 }
 setAddingDetected(false);
 await loadAll();
 await loadDetected();
 onChanged?.();
 if (failed > 0) {
 toast.error(`Added ${added} module(s). ${failed} failed (likely duplicates).`);
 } else {
 toast.success(`Added ${added} module(s).`);
 }
 };

 useEffect(() => {
 loadAll();
 // eslint-disable-next-line react-hooks/exhaustive-deps
 }, [project.id]);

 useEffect(() => {
 loadFiles(moduleId);
 // eslint-disable-next-line react-hooks/exhaustive-deps
 }, [moduleId]);

 const onSaveModule = async (payload) => {
 if (modal.mode === "edit") {
 // No update endpoint exposed in current API; use create as a fallback.
 await projectDetailApi.createModule(project.id, payload);
 } else {
 await projectDetailApi.createModule(project.id, payload);
 }
 setModal(null);
 await loadAll();
 onChanged?.();
 };

 const onDeleteModule = async (m) => {
 const ok = await confirmDialog(
 `Delete module "${m.name}"? This will fail if SBOM files still reference it.`,
 { title: "Delete module", confirmText: "Delete", tone: "danger" }
 );
 if (!ok) return;
 try {
 await projectDetailApi.deleteModule(project.id, m.id);
 await loadAll();
 toast.success(`Module "${m.name}" deleted.`);
 onChanged?.();
 } catch (e) {
 toast.error(e?.response?.data?.message || e?.message || "Delete failed");
 }
 };

 const onDeleteFile = async (f) => {
 const ok = await confirmDialog(
 `Delete SBOM file "${f.fileName}"?`,
 { title: "Delete SBOM file", confirmText: "Delete", tone: "danger" }
 );
 if (!ok) return;
 try {
 await projectDetailApi.deleteSbomFile(project.id, moduleId, f.id);
 await loadFiles(moduleId);
 toast.success("SBOM file deleted.");
 onChanged?.();
 } catch (e) {
 toast.error(e?.response?.data?.message || e?.message || "Delete failed");
 }
 };

 const [scanFsModuleId, setScanFsModuleId] = useState(null);
 const [scanModuleError, setScanModuleError] = useState(null);
 const [lastScanResult, setLastScanResult] = useState(null);

 const handleScanModuleFs = async (m) => {
 const ok = await confirmDialog(
 `Run a per-module Trivy scan? This will shallow-clone the repo (1-2 min) then run trivy fs on the module's subdir (3-5 min) so the SBOM contains only the packages declared by "${m.name}".`,
 { title: `Per-module scan "${m.name}"`, confirmText: "Clone + scan", tone: "primary" }
 );
 if (!ok) return;
 setScanFsModuleId(m.id);
 setScanModuleError(null);
 const loadingToast = toast.loading(`Cloning + scanning ${m.name}…`, { duration: Infinity });
 try {
 const res = await projectDetailApi.scanModuleFs(project.id, m.id);
 setLastScanResult({ moduleId: m.id, ...res, mode: "fs" });
 toast.dismiss(loadingToast);
 toast.success(
 `Per-module scan complete: ${res.fileName} · ${Math.round((res.sizeBytes || 0) / 1024)} KB · ${res.packages ?? 0} packages.`
 );
 await loadFiles(m.id);
 if (typeof onChanged === "function") onChanged();
 } catch (e) {
 toast.dismiss(loadingToast);
 const msg = e?.response?.data?.message || e?.message || "Per-module scan failed";
 setScanModuleError(`${m.name} (fs): ${msg}`);
 toast.error(msg, { duration: 8000 });
 } finally {
 setScanFsModuleId(null);
 }
 };

 if (loading) return <div style={{ color: "var(--text-muted)" }}>Loading…</div>;

 const moduleColumns = [
 { key: "name", header: "Name", render: (m) => <b>{m.name}</b> },
 { key: "pathInRepo", header: "Path in repo", render: (m) => m.pathInRepo || "—" },
 { key: "sbomPattern", header: "SBOM pattern", render: (m) => <code className={styles.sha}>{m.sbomPattern || "—"}</code> },
 { key: "updatedAt", header: "Updated", width: 180, render: (m) => (m.updatedAt ? new Date(m.updatedAt).toLocaleString() : "—") },
 {
 key: "actions", header: "", width: 280, align: "right",
 render: (m) => (
 <div style={{ display: "inline-flex", gap: 6 }} onClick={(e) => e.stopPropagation()}>
 <Button
 size="sm"
 variant="primary"
 onClick={() => handleScanModuleFs(m)}
 disabled={scanFsModuleId === m.id}
 title="Clone the repo and run trivy fs on this module's subdir — produces a module-specific SBOM"
 >
 {scanFsModuleId === m.id ? "Cloning…" : "Scan fs"}
 </Button>
 <Button size="sm" variant="ghost" onClick={() => setModal({ kind: "module", mode: "edit", initial: m })}>Edit</Button>
 <Button size="sm" variant="danger" onClick={() => onDeleteModule(m)}>Delete</Button>
 </div>
 ),
 },
 ];

 const repoColumns = null; // RepoConfig table removed in favour of RecentCommits.

 const fileColumns = [
 { key: "fileName", header: "File", render: (f) => <b>{f.fileName}</b> },
 { key: "sha256", header: "SHA-256", render: (f) => <code className={styles.sha}>{f.sha256 ? f.sha256.slice(0, 12) + "…" : "—"}</code> },
 { key: "sizeBytes", header: "Size", width: 110, align: "right", render: (f) => (f.sizeBytes ? `${Math.round(f.sizeBytes / 1024)} KB` : "—") },
 { key: "scanStatus", header: "Status", width: 140, render: (f) => <StatusBadge status={f.scanStatus} /> },
 { key: "uploadedAt", header: "Uploaded", width: 180, render: (f) => (f.uploadedAt ? new Date(f.uploadedAt).toLocaleString() : "—") },
 {
 key: "actions", header: "", width: 110, align: "right",
 render: (f) => <Button size="sm" variant="danger" onClick={() => onDeleteFile(f)}>Delete</Button>,
 },
 ];

 return (
 <div>
 <ErrorBanner error={error} />

 <div className={styles.section}>
 <div className={styles.sectionHeader}>
 <h3 className={styles.sectionTitle}>Detected modules from GitHub</h3>
 <div style={{ display: "inline-flex", gap: 8 }}>
 {detect && safeArray(detect.modules).length > 0 && (
 <Button size="sm" variant="primary" onClick={addAllDetectedAsModules} disabled={addingDetected}>
 {addingDetected ? "Adding…" : "Add all"}
 </Button>
 )}
 <Button size="sm" variant="secondary" onClick={loadDetected} disabled={detecting}>
 {detecting ? "Scanning GitHub…" : detect ? "Re-scan" : "Auto-detect"}
 </Button>
 </div>
 </div>
 {detectError && <ErrorBanner error={detectError} />}
 {detect && (
 <div style={{ fontSize: "var(--text-sm)", color: "var(--text-secondary)", marginBottom: "var(--space-2)" }}>
 {detect.error ? (
 <em>{detect.error}</em>
 ) : (
 <>
 <b>Repo:</b> <code className={styles.sha}>{detect.owner}/{detect.repo}</code>{" "}
 <b>Branch:</b> <code className={styles.sha}>{detect.defaultBranch}</code>{" "}
 <b>Build system:</b> <code className={styles.sha}>{detect.buildSystem}</code>{" "}
 {detect.modules?.length > 0 && (
 <span>· {detect.modules.length} module(s) suggested below</span>
 )}
 </>
 )}
 </div>
 )}
 {detect && safeArray(detect.modules).length > 0 && (
 <DataTable
 columns={[
 { key: "name", header: "Suggested name", render: (m) => <b>{m.name}</b> },
 { key: "pathInRepo", header: "Path in repo", render: (m) => m.pathInRepo || "—" },
 { key: "buildFile", header: "Build file", width: 130, render: (m) => <code className={styles.sha}>{m.buildFile}</code> },
 { key: "source", header: "Source", width: 130, render: (m) => m.declaredInParent ? "parent pom" : "tree scan" },
 {
 key: "actions", header: "", width: 120, align: "right",
 render: (m) => {
 const alreadyAdded = modules.some((existing) => existing.name === m.name && existing.pathInRepo === m.pathInRepo);
 if (alreadyAdded) return <span style={{ fontSize: "var(--text-xs)", color: "var(--text-muted)" }}>already added</span>;
 return (
 <Button size="sm" variant="primary" onClick={() => addDetectedAsModule(m)} disabled={addingDetected}>
 Add
 </Button>
 );
 },
 },
 ]}
 rows={safeArray(detect.modules)}
 emptyTitle="No modules detected"
 emptyHint="The repo may not have a standard build manifest at the root."
 />
 )}
 </div>

 <div className={styles.section}>
 <div className={styles.sectionHeader}>
 <h3 className={styles.sectionTitle}>Modules</h3>
 </div>
 <p className={styles.sectionSubtitle} style={{ margin: "0 0 var(--space-2) 0" }}>
 Populated by the Auto-detect step above. Use <b>Scan fs</b> on each row to clone the repo and run trivy fs on that module's subdir — produces a module-specific SBOM with only the packages declared by this module.
 </p>
 {scanModuleError && (
 <div style={{ marginBottom: "var(--space-3)" }}>
 <ErrorBanner error={scanModuleError} onDismiss={() => setScanModuleError(null)} />
 </div>
 )}
 {lastScanResult && (
 <div
 style={{
 marginBottom: "var(--space-3)",
 padding: "var(--space-2) var(--space-3)",
 background: "var(--color-info-soft, #eff6ff)",
 color: "var(--color-primary)",
 borderRadius: "var(--radius-md)",
 fontSize: "var(--text-sm)",
 }}
 >
 Last scan: {lastScanResult.fileName} · {Math.round((lastScanResult.sizeBytes || 0) / 1024)} KB · {lastScanResult.packages ?? 0} packages.
 </div>
 )}
 <DataTable columns={moduleColumns} rows={modules} emptyTitle="No modules yet" emptyHint="Click 'Auto-detect' above to populate from the GitHub repo." />
 </div>

 <div className={styles.section}>
 <div className={styles.sectionHeader}><h3 className={styles.sectionTitle}>Recent upstream commits</h3></div>
 <p className={styles.sectionSubtitle} style={{ margin: "0 0 var(--space-2) 0" }}>
 The most recent commits on this project's upstream repo. A <b>New</b> badge marks
 commits that landed after the latest risk snapshot — click <b>Re-scan</b> to pull
 the latest dependency list. Commits already covered by the latest scan are tagged
 <b>Scanned</b> or <b>No impact</b> depending on whether the vuln diff changed.
 </p>
 <RecentCommits
 project={project}
 moduleId={moduleId}
 onRescanned={typeof onChanged === "function" ? onChanged : undefined}
 />
 </div>

 <div className={styles.section}>
 <div className={styles.sectionHeader}><h3 className={styles.sectionTitle}>SBOM Files</h3></div>
 <p className={styles.sectionSubtitle} style={{ margin: "0 0 var(--space-2) 0" }}>
 SBOM files are produced by the <b>Scan repo</b> and <b>Scan fs</b> buttons above.
 Each row below is one Trivy run — pick a different module to see its SBOMs.
 </p>
 <div style={{ display: "flex", alignItems: "center", gap: 8, marginBottom: "var(--space-2)" }}>
 <label style={{ fontSize: "var(--text-sm)", color: "var(--text-secondary)" }}>Module</label>
 <select
 className={styles.moduleSelect}
 value={moduleId ?? ""}
 onChange={(e) => setModuleId(Number(e.target.value))}
 disabled={modules.length === 0}
 >
 {modules.length === 0 && <option value="">(no modules)</option>}
 {modules.map((m) => <option key={m.id} value={m.id}>{m.name}</option>)}
 </select>
 </div>
 <DataTable columns={fileColumns} rows={files} emptyTitle="No SBOM files yet" emptyHint="Run 'Scan repo' or 'Scan fs' above to populate this list." />
 </div>

 {modal?.kind === "module" && <ModuleFormModal initial={modal.initial} onClose={() => setModal(null)} onSave={onSaveModule} />}
 {confirmNode}
 </div>
 );
}

function ModuleFormModal({ initial, onClose, onSave }) {
 const isEdit = Boolean(initial);
 const [name, setName] = useState(initial?.name ?? "");
 const [pathInRepo, setPathInRepo] = useState(initial?.pathInRepo ?? "");
 const [sbomPattern, setSbomPattern] = useState(initial?.sbomPattern ?? "**/sbom.json");
 const [saving, setSaving] = useState(false);
 const [error, setError] = useState(null);

 const submit = async (e) => {
 e?.preventDefault();
 if (!name.trim()) { setError("Name is required"); return; }
 setSaving(true);
 setError(null);
 try {
 await onSave({ name: name.trim(), pathInRepo: pathInRepo.trim() || null, sbomPattern: sbomPattern.trim() || null });
 } catch (err) {
 setError(err?.response?.data?.message || err?.message || "Save failed");
 } finally { setSaving(false); }
 };

 return (
 <Modal
 title={isEdit ? "Edit module" : "New module"}
 onClose={onClose}
 size="md"
 footer={
 <>
 <Button variant="secondary" onClick={onClose} disabled={saving}>Cancel</Button>
 <Button variant="primary" onClick={submit} disabled={saving || !name.trim()}>
 {saving ? "Saving…" : isEdit ? "Save" : "Create"}
 </Button>
 </>
 }
 >
 <form onSubmit={submit} noValidate>
 <ErrorBanner error={error} />
 <Field label="Name" required><Input value={name} onChange={(e) => setName(e.target.value)} maxLength={200} autoFocus /></Field>
 <Field label="Path in repo" hint="Optional. e.g. src/main/java/com/example/core">
 <Input value={pathInRepo} onChange={(e) => setPathInRepo(e.target.value)} maxLength={500} />
 </Field>
 <Field label="SBOM file pattern" hint="Glob pattern matched inside the repo.">
 <Input value={sbomPattern} onChange={(e) => setSbomPattern(e.target.value)} maxLength={500} />
 </Field>
 </form>
 </Modal>
 );
}
