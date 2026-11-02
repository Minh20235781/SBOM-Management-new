import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import PageHeader from "../../components/shared/PageHeader";
import DataTable from "../../components/shared/DataTable";
import Button from "../../components/shared/Button";
import StatusBadge from "../../components/shared/StatusBadge";
import ErrorBanner from "../../components/shared/ErrorBanner";
import Spinner from "../../components/shared/Spinner";
import EmptyState from "../../components/shared/EmptyState";
import { Field, Input } from "../../components/shared/Form";
import legacyApi from "../../api/legacyApi";
import projectApi from "../../api/projectApi";
import { safeArray } from "../../utils/safe";

/**
 * Scan trigger page. The user pastes a repo URL, hits "Trigger
 * Scan", and waits for the backend to run Trivy (this can take
 * anywhere from 30s to a few minutes for large repos).
 *
 * The "Recent scans" list is sourced from the project list — every
 * scan creates a project row, so the table mirrors the scan history.
 */
export default function ScanPage() {
    const navigate = useNavigate();
    const [repoUrl, setRepoUrl] = useState("");
    const [scanning, setScanning] = useState(false);
    const [result, setResult] = useState(null);
    const [error, setError] = useState(null);
    const [history, setHistory] = useState([]);
    const [historyLoading, setHistoryLoading] = useState(true);

    useEffect(() => {
        let cancelled = false;
        (async () => {
            setHistoryLoading(true);
            try {
                setHistory(safeArray(await projectApi.list()));
            } catch (e) {
                if (!cancelled) setError(e?.message || "Failed to load history");
            } finally {
                if (!cancelled) setHistoryLoading(false);
            }
        })();
        return () => { cancelled = true; };
    }, []);

    const submit = async (e) => {
        e?.preventDefault();
        if (!repoUrl.trim()) return;
        setScanning(true);
        setError(null);
        setResult(null);
        try {
            const msg = await legacyApi.scanAndSave(repoUrl.trim());
            setResult({ ok: true, message: typeof msg === "string" ? msg : "Scan completed." });
            try {
                setHistory(safeArray(await projectApi.list()));
            } catch { /* non-fatal */ }
        } catch (err) {
            setError(err?.response?.data || err?.message || "Scan failed");
        } finally {
            setScanning(false);
        }
    };

    const historyColumns = [
        {
            key: "name",
            header: "Name",
            render: (p) => (
                <div>
                    <div style={{ fontWeight: "var(--weight-semibold)", color: "var(--text-primary)" }}>{p.name}</div>
                    {p.description && (
                        <div style={{ fontSize: "var(--text-xs)", color: "var(--text-muted)", marginTop: 2 }}>
                            {p.description}
                        </div>
                    )}
                </div>
            ),
        },
        { key: "status", header: "Status", width: 120, render: (p) => <StatusBadge status={p.status} /> },
        { key: "packageCount", header: "Packages", width: 110, align: "right", render: (p) => p.packageCount ?? "—" },
        {
            key: "createdAt",
            header: "Created",
            width: 200,
            render: (p) => (p.createdAt ? new Date(p.createdAt).toLocaleString() : "—"),
        },
        {
            key: "actions",
            header: "",
            width: 110,
            align: "right",
            render: (p) => (
                <Button size="sm" variant="secondary" onClick={(e) => { e.stopPropagation(); navigate(`/projects/${p.id}`); }}>
                    Open
                </Button>
            ),
        },
    ];

    return (
        <div>
            <PageHeader
                title="Scan"
                description="Trigger a Trivy scan on a Git repository. Results are stored in the Default Project."
            />

            <div
                style={{
                    background: "var(--bg-surface)",
                    border: "1px solid var(--border-subtle)",
                    borderRadius: "var(--radius-lg)",
                    padding: "var(--space-5)",
                    boxShadow: "var(--shadow-xs)",
                    marginBottom: "var(--space-5)",
                }}
            >
                <form onSubmit={submit} noValidate>
                    <Field
                        label="Repository URL"
                        hint="A public GitHub URL works out of the box. Private repos require GITHUB_TOKEN on the backend."
                        required
                    >
                        <Input
                            value={repoUrl}
                            onChange={(e) => setRepoUrl(e.target.value)}
                            placeholder="https://github.com/lodash/lodash"
                            disabled={scanning}
                            autoFocus
                        />
                    </Field>

                    <div style={{ display: "flex", gap: "var(--space-2)", alignItems: "center" }}>
                        <Button
                            type="submit"
                            variant="primary"
                            disabled={scanning || !repoUrl.trim()}
                            data-testid="trigger-scan-btn"
                        >
                            {scanning ? "Scanning…" : "Trigger Scan"}
                        </Button>
                        {scanning && (
                            <span style={{ color: "var(--text-secondary)", fontSize: "var(--text-sm)" }}>
                                <Spinner size="sm" /> Trivy is scanning the repo. This may take a while…
                            </span>
                        )}
                    </div>
                </form>

                <ErrorBanner error={error} />

                {result && (
                    <div
                        style={{
                            marginTop: "var(--space-4)",
                            padding: "var(--space-3) var(--space-4)",
                            background: "var(--color-success-soft)",
                            color: "var(--color-success)",
                            borderRadius: "var(--radius-md)",
                            fontSize: "var(--text-sm)",
                        }}
                    >
                        ✓ {result.message}
                    </div>
                )}
            </div>

            <h2 style={{ fontSize: "var(--text-md)", fontWeight: "var(--weight-semibold)", margin: "0 0 var(--space-3) 0" }}>
                Recent scans
            </h2>

            <DataTable
                columns={historyColumns}
                rows={history}
                loading={historyLoading}
                onRowClick={(p) => navigate(`/projects/${p.id}`)}
                emptyTitle="No scans yet"
                emptyHint="Trigger your first scan above. The result will appear here as a project row."
            />
        </div>
    );
}
