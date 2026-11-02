import { useEffect, useState } from "react";
import { useLocation, useNavigate } from "react-router-dom";
import PageHeader from "../../components/shared/PageHeader";
import ErrorBanner from "../../components/shared/ErrorBanner";
import Spinner from "../../components/shared/Spinner";
import EmptyState from "../../components/shared/EmptyState";
import { Field } from "../../components/shared/Form";
import Button from "../../components/shared/Button";
import projectApi from "../../api/projectApi";
import legacyApi from "../../api/legacyApi";
import { fetchSbomValidationByProject } from "../../api/sbomApi";
import TrustScore from "../../components/trust-score/TrustScore";
import { safeArray } from "../../utils/safe";

/**
 * Trust Score page.
 *
 * Single project dropdown at the top, plus a "Scan + score"
 * button next to it. The button runs Trivy against the
 * project's recorded repoUrl (read from the project history
 * snapshot) and recomputes the trust score in-page. If the
 * project has no URL on file, the button is disabled with a
 * tooltip pointing the user at the Scan page.
 *
 * No Git-URL input lives on this page — the user only ever
 * picks a project. The page never navigates away.
 */
export default function TrustScorePage() {
    const location = useLocation();
    const navigate = useNavigate();

    const [projects, setProjects] = useState([]);
    const [projectsLoading, setProjectsLoading] = useState(true);
    const [selectedProjectId, setSelectedProjectId] = useState(
        () => location.state?.projectId || ""
    );
    const [resolvedRepoUrl, setResolvedRepoUrl] = useState(null);
    const [resolvingUrl, setResolvingUrl] = useState(false);
    const [error, setError] = useState(null);
    const [scanning, setScanning] = useState(false);
    const [refreshing, setRefreshing] = useState(false);
    const [scanMessage, setScanMessage] = useState(null);
    // Bumped after every successful scan (or project switch) so
    // the TrustScore component re-runs its validate fetch even
    // when projectId/repoName/repoUrl haven't changed.
    const [refreshKey, setRefreshKey] = useState(0);
    // Validation result owned by the page so we can run the
    // fetch right after a Trivy scan completes (rather than
    // relying on the child's useEffect to re-fire).
    const [validationData, setValidationData] = useState(null);
    const [validating, setValidating] = useState(false);

    // Load project list once on mount.
    useEffect(() => {
        let cancelled = false;
        (async () => {
            setProjectsLoading(true);
            try {
                const list = safeArray(await projectApi.list());
                if (cancelled) return;
                setProjects(list);
                if (!selectedProjectId && list.length > 0) {
                    setSelectedProjectId(list[0].id);
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

    // Resolve the picked project's repoUrl. The history
    // snapshot is the primary source; if it's missing (e.g.
    // the legacy "Default Project" seed), fall back to the URL
    // embedded in the project description ("Auto-created from
    // Trivy scan of <url>"). The TrustScore component itself
    // is project-scoped, so this URL is only used when the
    // user explicitly hits "Re-scan + score" to trigger a
    // fresh Trivy scan.
    useEffect(() => {
        if (!selectedProjectId) {
            setResolvedRepoUrl(null);
            return;
        }
        let cancelled = false;
        setResolvingUrl(true);
        (async () => {
            let url = null;
            try {
                const history = await projectApi.history(selectedProjectId);
                const rows = safeArray(history);
                if (rows.length > 0) {
                    const latest = rows[rows.length - 1];
                    if (latest && latest.snapshotJson) {
                        try {
                            const parsed = JSON.parse(latest.snapshotJson);
                            if (parsed && typeof parsed.repoUrl === "string") {
                                url = parsed.repoUrl;
                            }
                        } catch {
                            // snapshotJson may be a plain string; ignore
                        }
                    }
                }
            } catch {
                // ignore history failures; we still try the description
            }
            if (!url) {
                try {
                    const proj = await projectApi.get(selectedProjectId);
                    const desc = proj?.description || "";
                    const m = desc.match(/(https?:\/\/\S+?)(?:\s|$)/);
                    if (m) {
                        url = m[1].replace(/[.,]$/, "");
                    }
                } catch {
                    // ignore
                }
            }
            if (!cancelled) setResolvedRepoUrl(url);
            if (!cancelled) setResolvingUrl(false);
        })();
        return () => { cancelled = true; };
    }, [selectedProjectId]);

    // Auto-fetch validation whenever the picked project changes
    // (or refreshKey bumps after a successful scan). This is the
    // authoritative source of truth for the trust score — the
    // <TrustScore> child just renders whatever we hand it, so
    // there is no chance of stale state from React batching.
    useEffect(() => {
        if (!selectedProjectId) {
            setValidationData(null);
            return;
        }
        let cancelled = false;
        setValidating(true);
        (async () => {
            try {
                const res = await fetchSbomValidationByProject(selectedProjectId);
                if (!cancelled) setValidationData(res);
            } catch (err) {
                if (!cancelled) {
                    setValidationData(null);
                    setError(err?.response?.data || err?.message || "Validation failed");
                }
            } finally {
                if (!cancelled) setValidating(false);
            }
        })();
        return () => { cancelled = true; };
    }, [selectedProjectId, refreshKey]);

    const selectedProject = projects.find((p) => p.id === selectedProjectId);

    // Re-run a Trivy scan for the picked project using its
    // recorded repoUrl. If the project has no URL on file
    // (e.g. the legacy "Default Project" seed), we still allow
    // the user to click and just refresh the trust score from
    // what's already in the database — matching the legacy
    // dashboard flow where the score could be recomputed
    // without re-running Trivy.
    const handleScanAndScore = async () => {
        if (!selectedProjectId) return;
        if (!resolvedRepoUrl) {
            // No URL on file → run a validate-only refresh against
            // whatever's already in the database.
            setError(null);
            setScanMessage("Refreshing trust score from existing data…");
            try {
                const res = await fetchSbomValidationByProject(selectedProjectId);
                setValidationData(res);
                setRefreshKey((k) => k + 1);
            } catch (err) {
                setError(err?.response?.data || err?.message || "Refresh failed");
            } finally {
                setScanMessage(null);
            }
            return;
        }
        setScanning(true);
        setValidating(false);
        setError(null);
        setScanMessage("Running Trivy scan…");
        try {
            // Step 1: Trivy scan + persist packages / vulns / graph.
            const result = await legacyApi.scanAndSave(resolvedRepoUrl);
            const list = safeArray(await projectApi.list().catch(() => projects));
            setProjects(list);
            setScanMessage(
                typeof result === "string"
                    ? `Scan complete — ${result.slice(0, 80)} — computing trust score…`
                    : "Scan complete — computing trust score…"
            );
            // Step 2: explicitly run validate so the trust score
            // reflects the freshly-scanned data, instead of relying on
            // the child's useEffect to fire.
            setValidating(true);
            const res = await fetchSbomValidationByProject(selectedProjectId);
            setValidationData(res);
            setRefreshKey((k) => k + 1);
            setScanMessage(
                typeof result === "string"
                    ? `Scan complete — ${result.slice(0, 80)} — trust score updated`
                    : "Scan complete — trust score updated"
            );
        } catch (err) {
            setError(err?.response?.data || err?.message || "Scan failed");
            setScanMessage(null);
        } finally {
            setScanning(false);
            setValidating(false);
        }
    };

    const handleRefreshOnly = async () => {
        if (!selectedProjectId) return;
        setRefreshing(true);
        setError(null);
        setScanMessage("Refreshing trust score from existing data…");
        try {
            const res = await fetchSbomValidationByProject(selectedProjectId);
            setValidationData(res);
            setRefreshKey((k) => k + 1);
            setScanMessage("Trust score refreshed");
        } catch (err) {
            setError(err?.response?.data || err?.message || "Refresh failed");
            setScanMessage(null);
        } finally {
            setRefreshing(false);
        }
    };

    const handleProjectChange = (id) => {
        setSelectedProjectId(id);
        setScanMessage(null);
        setError(null);
    };

    const hasTarget = Boolean(selectedProject);
    // Note: we no longer block on `resolvingUrl` here. The
    // TrustScore component is project-scoped (calls
    // /api/sbom/validate-by-project), so it can render the
    // trust score from the project's data even before the
    // optional repoUrl resolution finishes. `resolvedRepoUrl`
    // is only needed when the user hits "Re-scan + score" to
    // trigger a fresh Trivy scan.
    const canCompute = hasTarget;

    return (
        <div>
            <PageHeader
                title="Trust Score"
                description="Multi-source SBOM validation: cross-checks the dependency graph, build-system resolution, and runtime scanner output to grade the trustworthiness of the generated SBOM."
            />

            <div
                style={{
                    background: "var(--bg-surface)",
                    border: "1px solid var(--border-subtle)",
                    borderRadius: "var(--radius-lg)",
                    padding: "var(--space-5)",
                    boxShadow: "var(--shadow-xs)",
                    marginBottom: "var(--space-5)",
                    display: "grid",
                    gridTemplateColumns: "1fr",
                    gap: "var(--space-4)",
                }}
            >
                <Field label="Project" hint="Pick a previously scanned project to validate.">
                    <div style={{ display: "flex", gap: "var(--space-2)", alignItems: "center" }}>
                        <select
                            value={selectedProjectId}
                            onChange={(e) => handleProjectChange(e.target.value)}
                            disabled={projectsLoading}
                            style={{
                                flex: 1, height: 40, padding: "0 12px", border: "1px solid var(--border-default)",
                                borderRadius: "var(--radius-md)", fontSize: "var(--text-sm)",
                                background: "var(--bg-surface)",
                            }}
                        >
                            <option value="">— Select a project —</option>
                            {projects.map((p) => (
                                <option key={p.id} value={p.id}>
                                    {p.name}
                                    {p.packageCount != null ? ` (${p.packageCount} packages)` : ""}
                                </option>
                            ))}
                        </select>
                        <Button
                            type="button"
                            variant="ghost"
                            onClick={handleRefreshOnly}
                            disabled={!selectedProjectId || refreshing || scanning}
                            title={
                                !selectedProjectId
                                    ? "Pick a project first"
                                    : "Recompute the trust score from data already in the database — no Trivy scan, instant."
                            }
                        >
                            {refreshing ? "Refreshing…" : "Refresh score"}
                        </Button>
                        <Button
                            type="button"
                            variant="primary"
                            onClick={handleScanAndScore}
                            disabled={!selectedProjectId || scanning || refreshing}
                            title={
                                !selectedProjectId
                                    ? "Pick a project first"
                                    : !resolvedRepoUrl
                                        ? "This project has no scanner URL — use the Scan page to add one first."
                                        : "Re-run a Trivy scan against the recorded URL, then recompute the trust score. Creates a new Trivy cache dir."
                            }
                        >
                            {scanning ? "Scanning…" : "Re-scan + score"}
                        </Button>
                    </div>
                </Field>

                {selectedProject && (
                    <div style={{ fontSize: "var(--text-xs)", color: "var(--text-muted)" }}>
                        {resolvingUrl
                            ? "Resolving scanner source…"
                            : resolvedRepoUrl
                                ? `Scanner source: ${resolvedRepoUrl}`
                                : "No scanner source on file for this project. Use the Scan page to add a URL."}
                    </div>
                )}

                {scanMessage && (
                    <div
                        style={{
                            fontSize: "var(--text-sm)",
                            color: scanning ? "var(--text-secondary)" : "var(--color-primary)",
                            background: scanning ? "var(--bg-subtle)" : "var(--color-info-soft, #eff6ff)",
                            padding: "var(--space-2) var(--space-3)",
                            borderRadius: "var(--radius-md)",
                            display: "flex",
                            alignItems: "center",
                            gap: "var(--space-2)",
                        }}
                    >
                        {scanning && <Spinner size="sm" />}
                        {scanMessage}
                    </div>
                )}

                {selectedProject && (
                    <div style={{ display: "flex", gap: "var(--space-2)" }}>
                        <Button
                            type="button"
                            variant="ghost"
                            onClick={() => navigate(`/projects/${selectedProject.id}`)}
                        >
                            Open project detail
                        </Button>
                        {!resolvedRepoUrl && (
                            <Button
                                type="button"
                                variant="ghost"
                                onClick={() => navigate("/scan")}
                            >
                                Go to Scan page
                            </Button>
                        )}
                    </div>
                )}
            </div>

            <ErrorBanner error={error} />

            {projectsLoading ? (
                <Spinner center size="md" label="Loading projects…" />
            ) : !selectedProjectId ? (
                <EmptyState
                    title="No project selected"
                    hint="Pick a scanned project above to compute its trust score."
                />
            ) : (
                <TrustScore
                    key={selectedProjectId}
                    projectId={selectedProjectId}
                    repoName={selectedProject?.name || ""}
                    repoUrl={resolvedRepoUrl}
                    refreshKey={refreshKey}
                    controlledData={validationData}
                    controlledLoading={validating && !validationData}
                    controlledError={error}
                />
            )}
        </div>
    );
}
