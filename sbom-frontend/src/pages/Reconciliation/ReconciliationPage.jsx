import { useEffect, useState, useMemo } from "react";
import { Link, useSearchParams } from "react-router-dom";
import PageHeader from "../../components/shared/PageHeader";
import Spinner from "../../components/shared/Spinner";
import ErrorBanner from "../../components/shared/ErrorBanner";
import { Field, Input, Select } from "../../components/shared/Form";
import { exportPocCsv, generateRuntimeSbom } from "../../api/reconciliationApi";
import F12NetworkInspector from "../../components/reconciliation/F12NetworkInspector";
import toast from "react-hot-toast";
import { getOriginalSbom, saveNormalizedSbom, listNormalizedSboms, listSbomComparisons, saveSbomComparison } from "../../utils/sbomSnapshots";
import DependencyComparison from "./DependencyComparison";
import { compareDependencyGraphs, readDependencyGraph } from "./compareDependencyGraphs";
import { readBrowserLog, attachBackend } from "./runtimeEvidence";
import RuntimeTerminal from "./RuntimeTerminal";
import styles from "./ReconciliationPage.module.css";

const sourceSelectStyle = {
  minWidth: 0,
  maxWidth: "100%",
  paddingInlineStart: "min(var(--space-3), 10%)",
  paddingInlineEnd: "min(var(--space-8), 40%)",
  textOverflow: "ellipsis",
};

function downloadJson(payload, filename) {
  downloadBlob(new Blob([JSON.stringify(payload, null, 2)], { type: "application/json;charset=utf-8" }), filename);
}

function downloadBlob(blob, filename) {
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  link.click();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

export default function ReconciliationPage() {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const [searchParams, setSearchParams] = useSearchParams();
  const [catalog, setCatalog] = useState([]);
  const [savedComparisons, setSavedComparisons] = useState([]);
  const sourceId = searchParams.get("sbom") || "";
  const source = catalog.find(({ id }) => id === sourceId);
  const source1Content = source?.content || "";

  // Nguồn 2: Dữ liệu quan sát Runtime duy nhất từ link web qua nút Run
  const [targetWebUrl, setTargetWebUrl] = useState("");
  const [isRunningScan, setIsRunningScan] = useState(false);
  const [runtime, setRuntime] = useState(null);
  const [showF12Inspector, setShowF12Inspector] = useState(false);
  const runtimeSbomReady = !!runtime;
  const targetWebRequests = runtime?.auditLog?.capturedNetworkRequests || [];
  const runtimePackageCount = runtime?.componentCount ?? 0;
  const runtimeResourceCount = targetWebRequests.length;

  // Kết quả đối sánh sau khi có đủ cả 2 nguồn
  const [matchReport, setMatchReport] = useState(null);
  const [selection, setSelection] = useState(null);
  const [statusFilter, setStatusFilter] = useState("ALL");
  const [searchTerm, setSearchTerm] = useState("");
  const staticGraph = useMemo(() => source1Content ? readDependencyGraph(JSON.parse(source1Content)) : null, [source1Content]);
  const runtimeGraph = useMemo(() => runtime ? readDependencyGraph(JSON.parse(runtime.content)) : null, [runtime]);

  useEffect(() => {
    let active = true;
    listNormalizedSboms().then((records) => {
      if (active) setCatalog(records);
    }).catch((err) => { if (active) setError(`Không đọc được danh sách SBOM: ${err.message}`); });
    return () => { active = false; };
  }, []);

  useEffect(() => {
    if (!sourceId) return;
    let active = true;
    listSbomComparisons(sourceId).then((records) => {
      if (active) setSavedComparisons(records);
    }).catch((err) => { if (active) setError(`Không đọc được lịch sử đối sánh: ${err.message}`); });
    return () => { active = false; };
  }, [sourceId]);

  const resetComparison = () => {
    setMatchReport(null);
    setSelection(null);
    setStatusFilter("ALL");
    setSearchTerm("");
  };

  const handleSourceChange = (id) => {
    setSearchParams(id ? { sbom: id } : {}, { replace: true });
    setSavedComparisons([]);
    setRuntime(null);
    setShowF12Inspector(false);
    setError(null);
    resetComparison();
  };

  async function uploadStatic(event) {
    const file = event.target.files[0];
    event.target.value = "";
    if (!file) return;
    setLoading(true);
    handleSourceChange("");
    try {
      const content = await file.text();
      const document = JSON.parse(content);
      if (document.bomFormat !== "CycloneDX" || !Array.isArray(document.components)) {
        throw new Error("Chọn tệp SBOM CycloneDX JSON có danh sách components.");
      }
      readDependencyGraph(document);
      const record = await saveNormalizedSbom(content, file.name);
      setCatalog(records => [record, ...records.filter(r => r.id !== record.id)]);
      handleSourceChange(record.id);
    } catch (err) { setError(err.message); }
    finally { setLoading(false); }
  }

  const handleRunRuntimeScan = async () => {
    let url;
    try {
      url = new URL(targetWebUrl.trim());
      if (!["http:", "https:"].includes(url.protocol) || url.username || url.password) throw new Error();
    } catch {
      setError("Nhập URL HTTP hoặc HTTPS của dự án, ví dụ http://localhost:3000.");
      return;
    }

    setIsRunningScan(true);
    setRuntime(null);
    setShowF12Inspector(false);
    resetComparison();
    setError(null);
    try {
      const res = await generateRuntimeSbom({ targetUrl: url.href, observedOnly: true });
      if (!res?.success || !res.sbomJson || !res.sessionId) {
        throw new Error(res?.message || "Bộ thu thập chưa trả về phiên SBOM runtime hợp lệ.");
      }
      setRuntime(readBrowserLog(res));
      setShowF12Inspector(true);
      toast.success("Đã thu thập SBOM runtime từ URL dự án");
    } catch (err) {
      setError(err.message || "Lỗi khi thu thập SBOM runtime");
    } finally {
      setIsRunningScan(false);
    }
  };

  const importEvidence = async (event, backend) => {
    const files = Array.from(event.target.files);
    event.target.value = "";
    if (!files.length) return;
    setError(null);
    setLoading(true);
    const staticDocument = JSON.parse(source1Content);
    const hash = staticDocument.metadata?.properties?.find(p => p.name === "devops.provenance.file_sha256")?.value || sourceId;
    try {
      let next = runtime;
      for (const file of files) {
        const data = JSON.parse(await file.text());
        if (backend) next = attachBackend(next, data, hash);
        else {
          next = readBrowserLog(data);
          for (const inventory of Object.values(data.backendEvidence || {})) next = attachBackend(next, inventory, hash);
        }
      }
      setRuntime(next);
      setShowF12Inspector(true);
      setTargetWebUrl(next.targetUrl);
      resetComparison();
    } catch (err) { setError(err.message); }
    finally { setLoading(false); }
  };

  const handleExportRuntimeLog = () => {
    if (!runtime) return;
    downloadJson({
      sessionId: runtime.sessionId,
      targetUrl: runtime.targetUrl,
      scannedAt: runtime.scannedAt,
      componentCount: runtime.componentCount,
      backendEvidence: runtime.backendEvidence,
      engineV8Packages: runtime.auditLog?.identifiedPackages,
      f12NetworkAuditLog: runtime.auditLog,
      cycloneDxRuntimeSbom: JSON.parse(runtime.content),
    }, `runtime-sbom-log-${runtime.sessionId}.json`);
  };

  const handleExecuteMatch = async () => {
    if (!staticGraph || !runtimeGraph) return;
    setLoading(true);
    setError(null);
    resetComparison();
    try {
      const report = compareDependencyGraphs(staticGraph, runtimeGraph);
      try {
        const saved = await saveSbomComparison(sourceId, { ...runtime, report });
        setRuntime(saved);
        setSavedComparisons((records) => [saved, ...records.filter(({ id }) => id !== saved.id)]);
      } catch (storageError) {
        setError(`Có kết quả đối sánh nhưng chưa lưu được phiên: ${storageError.message}`);
      }
      setMatchReport(report);
      toast.success("Đối sánh hoàn tất");
    } catch (err) {
      setError(err.message || "Lỗi khi thực hiện đối sánh");
    } finally {
      setLoading(false);
    }
  };

  const handleRestoreComparison = (id) => {
    const saved = savedComparisons.find((record) => record.id === id && record.staticId === sourceId);
    if (!saved) return;
    resetComparison();
    setTargetWebUrl(saved.targetUrl);
    setRuntime(saved);
    setShowF12Inspector(false);
    setError(null);
    setMatchReport(saved.report);
  };

  const handleExportCsv = async () => {
    if (!matchReport) {
      toast.error("Chưa có kết quả đối sánh để xuất");
      return;
    }
    try {
      const { summary, results } = matchReport;
      const blob = await exportPocCsv({ summary, results: results.map(({ status, component, staticVersion, runtimeResource, runtimeVersion, versionStatus, evidence }) => (
        { status, component, staticVersion, runtimeResource, runtimeVersion, versionStatus, evidence }
      )) });
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = "matching-results.csv";
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);
      toast.success("Đã xuất báo cáo CSV");
    } catch (err) {
      toast.error("Không thể xuất CSV: " + err.message);
    }
  };

  const handleExportJson = () => {
    if (!matchReport) {
      toast.error("Chưa có kết quả đối sánh để xuất");
      return;
    }
    try {
      downloadJson({
        ...matchReport,
        inputs: {
          static: { id: sourceId, name: source.name, sha256: sourceId, originalSha256: source.originalHash || JSON.parse(source.content).metadata?.properties?.find(p => p.name === "devops.provenance.file_sha256")?.value },
          runtime: { sessionId: runtime.sessionId, url: runtime.targetUrl, scannedAt: runtime.scannedAt, sha256: runtime.runtimeSha256 },
        },
        observation: runtime.auditLog?.observation,
        backendEvidence: runtime.backendEvidence || {},
        graphs: { static: [...staticGraph.nodes.values()], runtime: [...runtimeGraph.nodes.values()] },
      }, "matching-results.json");
      toast.success("Đã xuất báo cáo JSON");
    } catch (err) {
      toast.error("Không thể xuất JSON: " + err.message);
    }
  };

  const filteredResults = useMemo(() => {
    if (!matchReport || !matchReport.results) return [];
    return matchReport.results.filter((item) => {
      if (statusFilter !== "ALL" && item.status !== statusFilter) {
        return false;
      }
      if (searchTerm.trim()) {
        const q = searchTerm.toLowerCase();
        const matchComp = item.component?.toLowerCase().includes(q);
        const matchRes = item.runtimeResource?.toLowerCase().includes(q);
        const matchEv = item.evidence?.toLowerCase().includes(q);
        return matchComp || matchRes || matchEv;
      }
      return true;
    });
  }, [matchReport, statusFilter, searchTerm]);

  const summary = matchReport?.summary || {
    staticComponentCount: 0,
    runtimeResourceCount: 0,
    resultCount: 0,
    statusCounts: {
      MATCHED: 0,
      STATIC_ONLY: 0,
      RUNTIME_ONLY: 0,
      UNRESOLVED: 0,
    },
  };

  const getStatusBadgeStyle = (status) => {
    switch (status) {
      case "MATCHED":
        return {
          background: "rgba(16, 185, 129, 0.15)",
          color: "#10b981",
          border: "1px solid #10b981",
        };
      case "STATIC_ONLY":
        return {
          background: "rgba(59, 130, 246, 0.15)",
          color: "#3b82f6",
          border: "1px solid #3b82f6",
        };
      case "RUNTIME_ONLY":
        return {
          background: "rgba(239, 68, 68, 0.15)",
          color: "#ef4444",
          border: "1px solid #ef4444",
        };
      case "UNRESOLVED":
      default:
        return {
          background: "rgba(156, 163, 175, 0.15)",
          color: "#9ca3af",
          border: "1px solid #6b7280",
        };
    }
  };

  const getVersionStatusBadgeStyle = (status) => {
    switch (status) {
      case "VERSION_MATCH":
        return { color: "#10b981", fontWeight: 700 };
      case "VERSION_MISMATCH":
        return { color: "#ef4444", fontWeight: 700 };
      default:
        return { color: "#9ca3af", fontStyle: "italic" };
    }
  };

  return (
    <div className={styles.page}>
      {/* Header */}
      <PageHeader
        title="Đối Sánh SBOM Tĩnh Với Dữ Liệu Runtime"
        description="Tải SBOM tĩnh và đối sánh với log runtime đã thu hoặc thu phiên mới từ URL."
      />

      {error && <ErrorBanner message={error} onDismiss={() => setError(null)} />}

      {/* HAI NGUỒN ĐẦU VÀO */}
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(auto-fit, minmax(min(100%, 22rem), 1fr))",
          gap: 20,
          marginTop: 20,
          marginBottom: 20,
        }}
      >
        {/* SBOM tĩnh đã lưu từ Provenance */}
        <div
          className={styles.inputCard}
          style={{
            background: "var(--bg-surface)",
            border: "1px solid var(--border-default)",
            borderRadius: "var(--radius-lg)",
            display: "flex",
            flexDirection: "column",
            justifyContent: "space-between",
          }}
        >
          <div>
            <div style={{ display: "flex", flexWrap: "wrap", gap: 4, justifyContent: "space-between", alignItems: "center", marginBottom: 12 }}>
              <div style={{ fontWeight: 800, fontSize: "var(--font-md)", color: "var(--text-primary)" }}>
                Nguồn 1: SBOM Cơ Sở
              </div>
              <span
                style={{
                  fontSize: "var(--font-xs)",
                  padding: "2px 8px",
                  borderRadius: "var(--radius-sm)",
                  background: "rgba(59, 130, 246, 0.15)",
                  color: "#3b82f6",
                  fontWeight: 700,
                }}
              >
                File Tĩnh
              </span>
            </div>

            <div style={{ fontSize: "var(--font-sm)", color: "var(--text-secondary)", marginBottom: 14 }}>
              <label>Tải SBOM tĩnh đã chuẩn hóa
                <input type="file" accept=".json,application/json" disabled={loading || isRunningScan} onChange={uploadStatic} />
              </label>
              <Link to="/provenance">Chuẩn hóa SBOM</Link>
            </div>
            {source?.originalHash && <button onClick={async () => {
              try {
                const blob = await getOriginalSbom(source.originalHash);
                downloadBlob(blob, blob.name || "sbom-original.json");
              } catch (err) { setError(err.message); }
            }}>Tải lại SBOM gốc</button>}
            {source && savedComparisons.some((record) => record.staticId === sourceId) && (
              <Field label="Mở phiên đối sánh đã lưu" htmlFor="reconciliation-saved-session">
                <Select id="reconciliation-saved-session" value={runtime?.id || ""} title={runtime?.id ? runtime.targetUrl : undefined}
                  disabled={loading || isRunningScan} onChange={(event) => handleRestoreComparison(event.target.value)} style={sourceSelectStyle}>
                  <option value="" disabled>Chọn phiên</option>
                  {savedComparisons.filter((record) => record.staticId === sourceId).map((record) => (
                    <option key={record.id} value={record.id}>{new Date(record.scannedAt).toLocaleString("vi-VN")} · {record.targetUrl} · {record.sessionId}</option>
                  ))}
                </Select>
              </Field>
            )}
          </div>

          <div
            style={{
              padding: "10px 12px",
              background: "var(--bg-secondary)",
              borderRadius: "var(--radius-md)",
              border: "1px solid var(--border-default)",
              fontSize: "var(--font-xs)",
            }}
          >
            <div style={{ color: "var(--text-primary)", fontWeight: 700 }}>
              SBOM đã chọn <span style={{ color: "#60a5fa", overflowWrap: "anywhere" }}>{source?.name || "Chưa chọn"}</span>
            </div>
            <div style={{ color: "var(--text-secondary)", marginTop: 4 }}>
              Số thành phần <b style={{ color: "#10b981" }}>{source?.count ?? 0}</b>
            </div>
          </div>
        </div>

        {/* Nguồn 2: Dữ liệu quan sát Runtime duy nhất từ link web qua nút Run */}
        <div
          className={styles.inputCard}
          style={{
            background: "var(--bg-surface)",
            border: "1px solid var(--border-default)",
            borderRadius: "var(--radius-lg)",
            display: "flex",
            flexDirection: "column",
            justifyContent: "space-between",
          }}
        >
          <div>
            <div style={{ display: "flex", flexWrap: "wrap", gap: 4, justifyContent: "space-between", alignItems: "center", marginBottom: 12 }}>
              <div style={{ fontWeight: 800, fontSize: "var(--font-md)", color: "var(--text-primary)" }}>
                Nguồn 2: Dữ Liệu Quan Sát Runtime
              </div>
              <span
                style={{
                  fontSize: "var(--font-xs)",
                  padding: "2px 8px",
                  borderRadius: "var(--radius-sm)",
                  background: "rgba(16, 185, 129, 0.15)",
                  color: "#10b981",
                  fontWeight: 700,
                }}
              >
                Chromium CDP
              </span>
            </div>

            <div style={{ fontSize: "var(--font-sm)", color: "var(--text-secondary)", marginBottom: 14 }}>
              Nhập URL để thu phía trình duyệt. Để quan sát backend, chạy ứng dụng với agent hoặc tải log đã ghép từ phiên trước.
            </div>

            {/* Ô NHẬP LINK WEB VÀ NÚT RUN CẠNH NHAU */}
            <div style={{ display: "flex", flexWrap: "wrap", gap: 8, alignItems: "center", marginBottom: 12 }}>
              <Input
                type="url"
                aria-label="URL của dự án"
                value={targetWebUrl}
                disabled={isRunningScan || loading}
                onChange={(e) => {
                  setTargetWebUrl(e.target.value);
                  setRuntime(null);
                  setShowF12Inspector(false);
                  setError(null);
                  resetComparison();
                }}
                placeholder="http://localhost:3000"
                style={{ flex: "1 1 min(100%, 10rem)", minWidth: 0, paddingInline: "min(var(--space-3), 10%)" }}
              />

              {/* NÚT RUN KÈM NÉT TAM GIÁC CHẠY BẰNG CSS BORDER */}
              <button
                onClick={handleRunRuntimeScan}
                disabled={isRunningScan || loading || !source || !targetWebUrl.trim()}
                style={{
                  padding: "8px 20px",
                  borderRadius: "var(--radius-md)",
                  border: "none",
                  background: "#16a34a",
                  color: "#ffffff",
                  fontWeight: 800,
                  fontSize: "var(--font-sm)",
                  cursor: isRunningScan ? "not-allowed" : "pointer",
                  display: "flex",
                  alignItems: "center",
                  boxShadow: "0 2px 6px rgba(22, 163, 74, 0.4)",
                  opacity: isRunningScan ? 0.7 : 1,
                }}
              >
                {/* NÉT TAM GIÁC CHẠY VẼ BẰNG CSS BORDER */}
                <span
                  style={{
                    width: 0,
                    height: 0,
                    borderTop: "5px solid transparent",
                    borderBottom: "5px solid transparent",
                    borderLeft: "8px solid #ffffff",
                    display: "inline-block",
                    marginRight: 6,
                  }}
                />
                {isRunningScan ? "Đang Chạy..." : "Run"}
              </button>
            </div>

            <label>Hoặc tải log runtime đã xuất (.json) <input type="file" accept=".json" disabled={!source || loading || isRunningScan} onChange={e => importEvidence(e, false)} /></label>
            <label>Ghép log backend cùng phiên <input type="file" multiple accept=".json" disabled={!runtime || loading || isRunningScan} onChange={e => importEvidence(e, true)} /></label>
            {runtime && <p>Tiến trình backend đã đối chiếu request: {Object.keys(runtime.backendEvidence || {}).length}</p>}
            {runtime?.auditLog?.observation && <p>
              {runtime.auditLog.observation.scenario || "Log chưa ghi thao tác"} · Build trình duyệt: {runtime.auditLog.observation.buildId || "chưa ghi nhận"}
            </p>}
            {runtime?.omittedServerCount > 0 && <p>Log cũ có dữ liệu server thiếu liên kết request. Chỉ dùng phần trình duyệt.</p>}
            {/* Thanh tiến trình chạy link web Nguồn 2 */}
            {isRunningScan && (
              <p role="status">Đang thu thập dữ liệu từ ứng dụng bằng Chromium CDP…</p>
            )}
          </div>

          {/* TRẠNG THÁI RUNTIME SBOM SAU KHI QUÉT */}
          <div
            style={{
              padding: "10px 12px",
              background: "var(--bg-secondary)",
              borderRadius: "var(--radius-md)",
              border: "1px solid var(--border-default)",
              fontSize: "var(--font-xs)",
            }}
          >
            {runtimeSbomReady ? (
              <div>
                <div style={{ color: "#10b981", fontWeight: 700, marginBottom: 4 }}>
                  SBOM runtime đã sẵn sàng
                </div>
                <div style={{ color: "var(--text-secondary)", display: "flex", gap: 16, flexWrap: "wrap", marginBottom: 8 }}>
                  <span>Số tài nguyên F12: <b style={{ color: "var(--text-primary)" }}>{runtimeResourceCount}</b></span>
                  <span>Gói nhận diện được: <b style={{ color: "var(--text-primary)" }}>{runtimePackageCount}</b></span>
                </div>
                <p style={{ overflowWrap: "anywhere" }}>{runtime.targetUrl} · {runtime.sessionId} · {new Date(runtime.scannedAt).toLocaleString("vi-VN")}</p>
                <div style={{ display: "flex", gap: 10, alignItems: "center", flexWrap: "wrap" }}>
                  <button
                    onClick={handleExportRuntimeLog}
                    style={{
                      padding: "4px 10px",
                      borderRadius: "var(--radius-sm)",
                      border: "1px solid #10b981",
                      background: "rgba(16, 185, 129, 0.1)",
                      color: "#10b981",
                      fontSize: "var(--font-xs)",
                      fontWeight: 700,
                      cursor: "pointer",
                    }}
                  >
                    Xuất File Log Runtime JSON
                  </button>

                  <button
                    onClick={() => setShowF12Inspector(!showF12Inspector)}
                    style={{
                      padding: "4px 10px",
                      borderRadius: "var(--radius-sm)",
                      border: "1px solid #3b82f6",
                      background: "rgba(59, 130, 246, 0.1)",
                      color: "#60a5fa",
                      fontSize: "var(--font-xs)",
                      fontWeight: 600,
                      cursor: "pointer",
                    }}
                  >
                    {showF12Inspector ? "Ẩn Bảng F12 Inspector" : "Xem Bảng F12 Inspector"}
                  </button>
                </div>
              </div>
            ) : (
              <div style={{ color: "var(--text-muted)" }}>
                Chưa có phiên runtime cho URL đã nhập.
              </div>
            )}
          </div>
        </div>
      </div>

      {/* NÚT THỰC HIỆN ĐỐI SÁNH SBOM */}
      <div style={{ textAlign: "center", marginBottom: 24 }}>
        <button
          onClick={handleExecuteMatch}
          disabled={loading || isRunningScan || !runtimeSbomReady || !source1Content}
          style={{
            padding: "12px 36px",
            borderRadius: "var(--radius-lg)",
            border: "none",
            background: runtimeSbomReady && source1Content ? "var(--color-primary)" : "#374151",
            color: runtimeSbomReady && source1Content ? "#ffffff" : "#9ca3af",
            fontWeight: 800,
            fontSize: "var(--font-md)",
            cursor: loading || !runtimeSbomReady || !source1Content ? "not-allowed" : "pointer",
            boxShadow: runtimeSbomReady && source1Content ? "0 4px 14px rgba(37, 99, 235, 0.4)" : "none",
          }}
        >
          {loading ? "Đang Đối Sánh Dữ Liệu..." : "Thực Hiện Đối Sánh SBOM"}
        </button>

        {!runtimeSbomReady && (
          <div style={{ fontSize: "var(--font-xs)", color: "var(--text-muted)", marginTop: 8 }}>
            Nhập URL và bấm Run hoặc tải file log runtime để đối sánh.
          </div>
        )}
      </div>

      <div className={styles.inspectors}>
      {showF12Inspector && runtime && (
        <div style={{ marginBottom: 24 }}>
          <F12NetworkInspector
            targetUrl={runtime.targetUrl}
            capturedLogs={targetWebRequests}
            snapshotOnly
            onClose={() => setShowF12Inspector(false)}
          />
        </div>
      )}

      {source && <RuntimeTerminal key={sourceId} inventories={runtime?.backendEvidence} onAttach={runtime && !loading && !isRunningScan ? data => {
        try {
          const hash = JSON.parse(source.content).metadata?.properties?.find(p => p.name === "devops.provenance.file_sha256")?.value || source.id;
          setRuntime(attachBackend(runtime, data, hash));
          resetComparison();
          setError(null);
        } catch (err) { setError(err.message); }
      } : null} />}
      </div>

      {matchReport && staticGraph && runtimeGraph && (
        <DependencyComparison key={`${sourceId}/${runtime.sessionId}`} staticGraph={staticGraph} runtimeGraph={runtimeGraph}
          report={matchReport} selection={selection} onSelect={setSelection} />
      )}

      {/* THẺ TỔNG HỢP KẾT QUẢ THEO CHUẨN POC */}
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "repeat(7, 1fr)",
          gap: 6,
          marginBottom: 16,
        }}
      >
        <div
          style={{
            background: "var(--bg-surface)",
            border: "1px solid var(--border-default)",
            borderRadius: "var(--radius-md)",
            padding: "8px 6px",
            minWidth: 0,
            textAlign: "center",
          }}
        >
          <div style={{ fontSize: "11px", color: "var(--text-secondary)", fontWeight: 700, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }} title="Số Component Tĩnh">
            Component Tĩnh
          </div>
          <div style={{ fontSize: 18, fontWeight: 900, color: "var(--text-primary)", marginTop: 2 }}>
            {summary.staticComponentCount}
          </div>
        </div>

        <div
          style={{
            background: "var(--bg-surface)",
            border: "1px solid var(--border-default)",
            borderRadius: "var(--radius-md)",
            padding: "8px 6px",
            minWidth: 0,
            textAlign: "center",
          }}
        >
          <div style={{ fontSize: "11px", color: "var(--text-secondary)", fontWeight: 700, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }} title="Số gói nhận diện trong SBOM runtime">
            Gói runtime
          </div>
          <div style={{ fontSize: 18, fontWeight: 900, color: "var(--text-primary)", marginTop: 2 }}>
            {summary.runtimeResourceCount}
          </div>
        </div>

        <div
          style={{
            background: "var(--bg-surface)",
            border: "1px solid var(--border-default)",
            borderRadius: "var(--radius-md)",
            padding: "8px 6px",
            minWidth: 0,
            textAlign: "center",
          }}
        >
          <div style={{ fontSize: "11px", color: "var(--text-secondary)", fontWeight: 700, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }} title="Tổng Dòng Kết Quả">
            Tổng Bản Ghi
          </div>
          <div style={{ fontSize: 18, fontWeight: 900, color: "var(--text-primary)", marginTop: 2 }}>
            {summary.resultCount}
          </div>
        </div>

        <div
          style={{
            background: "rgba(16, 185, 129, 0.08)",
            border: "1px solid rgba(16, 185, 129, 0.3)",
            borderRadius: "var(--radius-md)",
            padding: "8px 6px",
            minWidth: 0,
            textAlign: "center",
          }}
        >
          <div style={{ fontSize: "11px", color: "#10b981", fontWeight: 700, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>
            MATCHED
          </div>
          <div style={{ fontSize: 18, fontWeight: 900, color: "#10b981", marginTop: 2 }}>
            {summary.statusCounts?.MATCHED || 0}
          </div>
        </div>

        <div
          style={{
            background: "rgba(59, 130, 246, 0.08)",
            border: "1px solid rgba(59, 130, 246, 0.3)",
            borderRadius: "var(--radius-md)",
            padding: "8px 6px",
            minWidth: 0,
            textAlign: "center",
          }}
        >
          <div style={{ fontSize: "11px", color: "#3b82f6", fontWeight: 700, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>
            STATIC ONLY
          </div>
          <div style={{ fontSize: 18, fontWeight: 900, color: "#3b82f6", marginTop: 2 }}>
            {summary.statusCounts?.STATIC_ONLY || 0}
          </div>
        </div>

        <div
          style={{
            background: "rgba(239, 68, 68, 0.08)",
            border: "1px solid rgba(239, 68, 68, 0.3)",
            borderRadius: "var(--radius-md)",
            padding: "8px 6px",
            minWidth: 0,
            textAlign: "center",
          }}
        >
          <div style={{ fontSize: "11px", color: "#ef4444", fontWeight: 700, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>
            RUNTIME ONLY
          </div>
          <div style={{ fontSize: 18, fontWeight: 900, color: "#ef4444", marginTop: 2 }}>
            {summary.statusCounts?.RUNTIME_ONLY || 0}
          </div>
        </div>

        <div
          style={{
            background: "rgba(156, 163, 175, 0.08)",
            border: "1px solid rgba(156, 163, 175, 0.3)",
            borderRadius: "var(--radius-md)",
            padding: "8px 6px",
            minWidth: 0,
            textAlign: "center",
          }}
        >
          <div style={{ fontSize: "11px", color: "#9ca3af", fontWeight: 700, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }}>
            UNRESOLVED
          </div>
          <div style={{ fontSize: 18, fontWeight: 900, color: "#9ca3af", marginTop: 2 }}>
            {summary.statusCounts?.UNRESOLVED || 0}
          </div>
        </div>
      </div>

      {/* FILTER VÀ EXPORT BAR */}
      <div
        style={{
          background: "var(--bg-surface)",
          border: "1px solid var(--border-default)",
          borderRadius: "var(--radius-lg)",
          padding: "12px 18px",
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          flexWrap: "wrap",
          gap: 12,
          marginBottom: 16,
        }}
      >
        <div style={{ display: "flex", gap: 6, flexWrap: "wrap", alignItems: "center" }}>
          {[
            { key: "ALL", label: "Tất Cả" },
            { key: "MATCHED", label: "MATCHED" },
            { key: "STATIC_ONLY", label: "STATIC ONLY" },
            { key: "RUNTIME_ONLY", label: "RUNTIME ONLY" },
            { key: "UNRESOLVED", label: "UNRESOLVED" },
          ].map((item) => (
            <button
              key={item.key}
              onClick={() => setStatusFilter(item.key)}
              style={{
                padding: "6px 14px",
                borderRadius: "var(--radius-md)",
                border: "1px solid " + (statusFilter === item.key ? "var(--color-primary)" : "var(--border-default)"),
                background: statusFilter === item.key ? "var(--color-primary)" : "transparent",
                color: statusFilter === item.key ? "#ffffff" : "var(--text-secondary)",
                fontWeight: 700,
                fontSize: "var(--font-xs)",
                cursor: "pointer",
              }}
            >
              {item.label}
            </button>
          ))}
        </div>

        <div style={{ display: "flex", gap: 10, alignItems: "center", flexWrap: "wrap" }}>
          <input
            type="text"
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            placeholder="Lọc tên component hoặc URL"
            style={{
              padding: "6px 12px",
              borderRadius: "var(--radius-md)",
              border: "1px solid var(--border-default)",
              background: "var(--bg-secondary)",
              color: "var(--text-primary)",
              fontSize: "var(--font-sm)",
              width: 240,
              outline: "none",
            }}
          />

          <button
            onClick={handleExportCsv}
            style={{
              padding: "6px 14px",
              borderRadius: "var(--radius-md)",
              border: "1px solid #10b981",
              background: "rgba(16, 185, 129, 0.15)",
              color: "#10b981",
              fontWeight: 700,
              fontSize: "var(--font-xs)",
              cursor: "pointer",
            }}
          >
            Xuất Báo Cáo CSV
          </button>

          <button
            onClick={handleExportJson}
            style={{
              padding: "6px 14px",
              borderRadius: "var(--radius-md)",
              border: "1px solid #3b82f6",
              background: "rgba(59, 130, 246, 0.15)",
              color: "#60a5fa",
              fontWeight: 700,
              fontSize: "var(--font-xs)",
              cursor: "pointer",
            }}
          >
            Xuất Báo Cáo JSON
          </button>
        </div>
      </div>

      {/* BẢNG KẾT QUẢ ĐỐI SÁNH CHI TIẾT */}
      <div
        style={{
          background: "var(--bg-surface)",
          border: "1px solid var(--border-default)",
          borderRadius: "var(--radius-lg)",
          overflow: "hidden",
        }}
      >
        <div style={{ overflowX: "auto" }}>
          <table
            style={{
              width: "100%",
              tableLayout: "fixed",
              borderCollapse: "collapse",
              textAlign: "left",
              fontSize: "12px",
            }}
          >
            <thead>
              <tr
                style={{
                  background: "var(--bg-secondary)",
                  borderBottom: "1px solid var(--border-default)",
                  color: "var(--text-secondary)",
                  fontWeight: 700,
                }}
              >
                <th style={{ padding: "8px 6px", width: "10%" }}>Trạng Thái</th>
                <th style={{ padding: "8px 6px", width: "14%" }}>Thành Phần</th>
                <th style={{ padding: "8px 6px", width: "9%" }}>Phiên Bản Tĩnh</th>
                <th style={{ padding: "8px 6px", width: "25%" }}>Tài Nguyên Runtime</th>
                <th style={{ padding: "8px 6px", width: "10%" }}>Phiên Bản Runtime</th>
                <th style={{ padding: "8px 6px", width: "12%" }}>Tình Trạng Phiên Bản</th>
                <th style={{ padding: "8px 6px", width: "20%" }}>Bằng Chứng Đối Sánh</th>
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr>
                  <td colSpan={7} style={{ textAlign: "center", padding: 40 }}>
                    <Spinner size="md" />
                    <div style={{ marginTop: 10, color: "var(--text-secondary)" }}>
                      Đang xử lý đối sánh hai nguồn SBOM...
                    </div>
                  </td>
                </tr>
              ) : filteredResults.length === 0 ? (
                <tr>
                  <td
                    colSpan={7}
                    style={{ textAlign: "center", padding: 40, color: "var(--text-secondary)" }}
                  >
                    Không có kết quả đối sánh nào phù hợp với bộ lọc
                  </td>
                </tr>
              ) : (
                filteredResults.map((item, idx) => {
                  const badgeStyle = getStatusBadgeStyle(item.status);
                  const verStyle = getVersionStatusBadgeStyle(item.versionStatus);

                  return (
                    <tr
                      key={idx}
                      style={{
                        borderBottom: "1px solid var(--border-default)",
                        transition: "background 0.15s ease",
                      }}
                      onMouseEnter={(e) => (e.currentTarget.style.background = "var(--bg-hover)")}
                      onMouseLeave={(e) => (e.currentTarget.style.background = "transparent")}
                    >
                      <td style={{ padding: "8px 6px", verticalAlign: "top" }}>
                        <span
                          style={{
                            display: "inline-block",
                            padding: "3px 6px",
                            borderRadius: "var(--radius-sm)",
                            fontWeight: 800,
                            fontSize: "11px",
                            ...badgeStyle,
                          }}
                        >
                          {item.status}
                        </span>
                      </td>

                      <td
                        style={{
                          padding: "8px 6px",
                          verticalAlign: "top",
                          fontWeight: 700,
                          color: "var(--text-primary)",
                          wordBreak: "break-all",
                          whiteSpace: "normal",
                        }}
                      >
                        <button type="button" onClick={() => setSelection(item)}
                          style={{ color: "var(--color-primary)", background: "none", border: 0, padding: 0, textAlign: "start", textDecoration: "underline", overflowWrap: "anywhere", cursor: "pointer" }}>
                          {item.component}
                        </button>
                      </td>

                      <td
                        style={{
                          padding: "8px 6px",
                          verticalAlign: "top",
                          fontFamily: "var(--font-mono)",
                          wordBreak: "break-all",
                          whiteSpace: "normal",
                        }}
                      >
                        {item.staticVersion || "—"}
                      </td>

                      <td
                        style={{
                          padding: "8px 6px",
                          verticalAlign: "top",
                          wordBreak: "break-all",
                          whiteSpace: "normal",
                          lineHeight: 1.4,
                        }}
                      >
                        {item.runtimeResource ? (
                          <span
                            style={{
                              fontFamily: "var(--font-mono)",
                              fontSize: "11px",
                              color: "#60a5fa",
                              wordBreak: "break-all",
                              whiteSpace: "normal",
                              overflowWrap: "anywhere",
                              display: "block",
                            }}
                          >
                            {item.runtimeResource}
                          </span>
                        ) : (
                          <span style={{ color: "var(--text-muted)" }}>Không có</span>
                        )}
                      </td>

                      <td
                        style={{
                          padding: "8px 6px",
                          verticalAlign: "top",
                          fontFamily: "var(--font-mono)",
                          wordBreak: "break-all",
                          whiteSpace: "normal",
                        }}
                      >
                        {item.runtimeVersion || "—"}
                      </td>

                      <td
                        style={{
                          padding: "8px 6px",
                          verticalAlign: "top",
                          fontSize: "11px",
                          wordBreak: "break-word",
                          whiteSpace: "normal",
                          ...verStyle,
                        }}
                      >
                        {item.versionStatus || "VERSION_UNKNOWN"}
                      </td>

                      <td
                        style={{
                          padding: "8px 6px",
                          verticalAlign: "top",
                          fontSize: "11px",
                          color: "var(--text-secondary)",
                          wordBreak: "break-word",
                          whiteSpace: "normal",
                          lineHeight: 1.4,
                        }}
                      >
                        {item.evidence || "—"}
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  );
}
