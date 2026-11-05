import { useEffect, useState, useRef } from "react";
import { useNavigate } from "react-router-dom";
import PageHeader from "../../components/shared/PageHeader";
import DataTable from "../../components/shared/DataTable";
import Button from "../../components/shared/Button";
import StatusBadge from "../../components/shared/StatusBadge";
import ErrorBanner from "../../components/shared/ErrorBanner";
import Spinner from "../../components/shared/Spinner";
import EmptyState from "../../components/shared/EmptyState";
import ProgressBar from "../../components/shared/ProgressBar";
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

    const [progress, setProgress] = useState(0);
    const [statusText, setStatusText] = useState("");
    const [stepIndex, setStepIndex] = useState(0);
    const progressTimerRef = useRef(null);

    const scanSteps = [
        "Khởi tạo & Clone Git",
        "Chạy Trivy quét Manifest",
        "Trích xuất CycloneDX & CVE",
        "Lưu trữ & Đánh giá rủi ro",
    ];

    useEffect(() => {
        return () => {
            if (progressTimerRef.current) clearInterval(progressTimerRef.current);
        };
    }, []);

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
        setProgress(5);
        setStepIndex(0);
        setStatusText("Khởi tạo môi trường quét và chuẩn bị kết nối kho Git...");

        if (progressTimerRef.current) clearInterval(progressTimerRef.current);

        // Giả lập tiến trình mượt mà qua các giai đoạn quét thực tế của Trivy
        progressTimerRef.current = setInterval(() => {
            setProgress((prev) => {
                if (prev < 25) {
                    setStepIndex(0);
                    setStatusText("Đang kết nối và sao chép mã nguồn từ repository Git...");
                    return prev + 2;
                } else if (prev < 55) {
                    setStepIndex(1);
                    setStatusText("Trivy đang phân tích các file cấu hình manifest và cây phụ thuộc...");
                    return prev + 1.5;
                } else if (prev < 80) {
                    setStepIndex(2);
                    setStatusText("Trích xuất thông tin linh kiện CycloneDX và đối soát cơ sở dữ liệu lỗ hổng CVE...");
                    return prev + 1;
                } else if (prev < 92) {
                    setStepIndex(3);
                    setStatusText("Đang tổng hợp thông tin, chuẩn hóa dữ liệu và lưu vào cơ sở dữ liệu...");
                    return prev + 0.6;
                }
                return prev;
            });
        }, 350);

        try {
            const msg = await legacyApi.scanAndSave(repoUrl.trim());
            clearInterval(progressTimerRef.current);
            setProgress(100);
            setStepIndex(3);
            setStatusText("Quét mã nguồn và trích xuất SBOM thành công!");
            setResult({ ok: true, message: typeof msg === "string" ? msg : "Scan completed." });
            try {
                setHistory(safeArray(await projectApi.list()));
            } catch { /* non-fatal */ }
        } catch (err) {
            clearInterval(progressTimerRef.current);
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

                {(scanning || progress > 0) && !error && (
                    <ProgressBar
                        progress={progress}
                        statusText={statusText}
                        stepText={`Bước ${Math.min(stepIndex + 1, scanSteps.length)}/${scanSteps.length}`}
                        steps={scanSteps}
                        currentStepIndex={stepIndex}
                        color="#2563eb"
                    />
                )}

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
