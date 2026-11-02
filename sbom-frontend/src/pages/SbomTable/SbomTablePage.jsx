import { useEffect, useState } from "react";
import PageHeader from "../../components/shared/PageHeader";
import DataTable from "../../components/shared/DataTable";
import StatusBadge from "../../components/shared/StatusBadge";
import Button from "../../components/shared/Button";
import ErrorBanner from "../../components/shared/ErrorBanner";
import Spinner from "../../components/shared/Spinner";
import EmptyState from "../../components/shared/EmptyState";
import legacyApi from "../../api/legacyApi";
import projectApi from "../../api/projectApi";
import { safeArray } from "../../utils/safe";

/**
 * Flat SBOM table: one row per (package, vulnerability) pair.
 * Filter by project (dropdown of all scanned repos) and export
 * the current view as CSV or JSON.
 *
 * The dropdown replaces the old free-text input so users pick
 * from existing scans rather than typing repo names that may
 * not match anything in the DB.
 */
export default function SbomTablePage() {
    const [projects, setProjects] = useState([]);
    const [projectsLoading, setProjectsLoading] = useState(true);
    const [projectId, setProjectId] = useState("");
    const [rows, setRows] = useState([]);
    const [loading, setLoading] = useState(true);
    const [error, setError] = useState(null);
    const [exporting, setExporting] = useState(false);

    // Load the project list once. Auto-pick the project with the
    // most packages (usually the most useful default for a flat
    // SBOM view).
    useEffect(() => {
        let cancelled = false;
        (async () => {
            setProjectsLoading(true);
            try {
                const list = safeArray(await projectApi.list());
                if (cancelled) return;
                setProjects(list);
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

    // Reload the table whenever the project changes.
    useEffect(() => {
        let cancelled = false;
        (async () => {
            setLoading(true);
            setError(null);
            try {
                const data = await legacyApi.sbomTable(selectedProject?.name || null);
                if (!cancelled) setRows(safeArray(data));
            } catch (e) {
                if (!cancelled) setError(e?.response?.data || e?.message || "Failed to load");
            } finally {
                if (!cancelled) setLoading(false);
            }
        })();
        return () => { cancelled = true; };
    }, [projectId, selectedProject?.name]);

    const columns = [
        { key: "repo_name", header: "Repo", render: (r) => r.repo_name || "—" },
        { key: "package_name", header: "Package", render: (r) => <b>{r.package_name}</b> },
        { key: "version", header: "Version", render: (r) => r.version || "—" },
        { key: "type", header: "Type", render: (r) => r.type || "—" },
        {
            key: "rank_score",
            header: "Rank",
            width: 90,
            align: "right",
            render: (r) => (r.rank_score != null ? r.rank_score.toFixed(2) : "—"),
        },
        {
            key: "vulnerabilities",
            header: "Vuln",
            render: (r) => r.vulnerabilities ? <code style={{ fontSize: "var(--text-xs)" }}>{r.vulnerabilities}</code> : <em style={{ color: "var(--text-muted)" }}>secure</em>,
        },
        {
            key: "severity",
            header: "Severity",
            width: 110,
            render: (r) => r.severity ? <StatusBadge status={r.severity} /> : "—",
        },
        {
            key: "cvss",
            header: "CVSS",
            width: 80,
            align: "right",
            render: (r) => (r.cvss != null ? Number(r.cvss).toFixed(1) : "—"),
        },
    ];

    const exportFile = async (kind) => {
        setExporting(true);
        try {
            const blob = kind === "csv"
                ? await legacyApi.exportCsv(selectedProject?.name || null)
                : await legacyApi.exportJson(selectedProject?.name || null);
            const url = URL.createObjectURL(blob);
            const a = document.createElement("a");
            a.href = url;
            a.download = `sbom-table${selectedProject ? `-${selectedProject.name}` : ""}.${kind}`;
            document.body.appendChild(a);
            a.click();
            a.remove();
            URL.revokeObjectURL(url);
        } catch (e) {
            setError(e?.response?.data || e?.message || "Export failed");
        } finally {
            setExporting(false);
        }
    };

    return (
        <div>
            <PageHeader
                title="SBOM Table"
                description="Flat view: one row per package × vulnerability. Filter by project and export to CSV/JSON."
                actions={
                    <div style={{ display: "flex", gap: "var(--space-2)" }}>
                        <Button variant="secondary" size="sm" disabled={exporting} onClick={() => exportFile("csv")}>Export CSV</Button>
                        <Button variant="secondary" size="sm" disabled={exporting} onClick={() => exportFile("json")}>Export JSON</Button>
                    </div>
                }
            />

            <div
                style={{
                    display: "flex",
                    alignItems: "center",
                    gap: "var(--space-3)",
                    marginBottom: "var(--space-4)",
                    justifyContent: "flex-end",
                }}
            >
                <label style={{ fontSize: "var(--text-sm)", color: "var(--text-secondary)" }}>Project</label>
                <select
                    value={projectId}
                    onChange={(e) => setProjectId(e.target.value ? Number(e.target.value) : "")}
                    disabled={projectsLoading || projects.length === 0}
                    style={{
                        height: 36, padding: "0 12px", border: "1px solid var(--border-default)",
                        borderRadius: "var(--radius-md)", fontSize: "var(--text-sm)", background: "var(--bg-surface)", minWidth: 220,
                    }}
                >
                    <option value="">(all repos)</option>
                    {projects.map((p) => (
                        <option key={p.id} value={p.id}>
                            {p.name}{p.packageCount != null ? ` (${p.packageCount} packages)` : ""}
                        </option>
                    ))}
                </select>
            </div>

            <ErrorBanner error={error} />

            {loading ? (
                <Spinner center size="md" label="Loading SBOM table…" />
            ) : rows.length === 0 ? (
                <EmptyState
                    title={selectedProject ? `No SBOM rows for ${selectedProject.name}` : "No SBOM rows"}
                    hint={selectedProject
                        ? "Run a scan against this project to populate the table."
                        : "Pick a project above, or trigger a scan from the Scan page."}
                />
            ) : (
                <DataTable
                    columns={columns}
                    rows={rows}
                    emptyTitle="No SBOM rows match the filter"
                />
            )}
        </div>
    );
}
