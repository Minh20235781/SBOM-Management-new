import { useEffect, useState, useRef, useMemo } from "react";
import PageHeader from "../../components/shared/PageHeader";
import Spinner from "../../components/shared/Spinner";
import ErrorBanner from "../../components/shared/ErrorBanner";
import ProgressBar from "../../components/shared/ProgressBar";
import { matchPoc, exportPocCsv, generateRuntimeSbom } from "../../api/reconciliationApi";
import F12NetworkInspector, {
  captureRealBrowserNetworkEntries,
  detectPackageFromResourceUrl
} from "../../components/reconciliation/F12NetworkInspector";
import toast from "react-hot-toast";

const SAMPLE_CYCLONEDX_SBOM = JSON.stringify(
  {
    bomFormat: "CycloneDX",
    specVersion: "1.5",
    components: [
      { type: "library", name: "react", version: "18.3.1", purl: "pkg:npm/react@18.3.1" },
      { type: "library", name: "react-dom", version: "18.3.1", purl: "pkg:npm/react-dom@18.3.1" },
      { type: "library", name: "axios", version: "1.7.2", purl: "pkg:npm/axios@1.7.2" },
      { type: "library", name: "lodash", version: "4.17.21", purl: "pkg:npm/lodash@4.17.21" },
      { type: "library", name: "@supabase/supabase-js", version: "2.45.4", purl: "pkg:npm/%40supabase/supabase-js@2.45.4" },
      { type: "library", name: "lucide-react", version: "0.453.0", purl: "pkg:npm/lucide-react@0.453.0" },
      { type: "library", name: "jsonwebtoken", version: "9.0.2", purl: "pkg:npm/jsonwebtoken@9.0.2" }
    ]
  },
  null,
  2
);

export default function ReconciliationPage() {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  // Nguồn 1: SBOM Cơ sở duy nhất từ file
  const [source1Content, setSource1Content] = useState("");
  const [source1FileName, setSource1FileName] = useState("");
  const [source1ComponentCount, setSource1ComponentCount] = useState(0);

  // Nguồn 2: Dữ liệu quan sát Runtime duy nhất từ link web qua nút Run
  const [targetWebUrl, setTargetWebUrl] = useState("");
  const [isRunningScan, setIsRunningScan] = useState(false);
  const [runtimeSbomReady, setRuntimeSbomReady] = useState(false);
  const [runtimeSbomJson, setRuntimeSbomJson] = useState("");
  const [runtimeLogData, setRuntimeLogData] = useState(null);
  const [runtimePackageCount, setRuntimePackageCount] = useState(0);
  const [runtimeResourceCount, setRuntimeResourceCount] = useState(0);
  const [targetWebRequests, setTargetWebRequests] = useState([]);
  const [showF12Inspector, setShowF12Inspector] = useState(false);

  // Kết quả đối sánh sau khi có đủ cả 2 nguồn
  const [matchReport, setMatchReport] = useState(null);
  const [statusFilter, setStatusFilter] = useState("ALL");
  const [searchTerm, setSearchTerm] = useState("");

  const fileInputRef1 = useRef(null);

  // Tiến trình chạy link web (Nguồn 2)
  const [runtimeProgress, setRuntimeProgress] = useState(0);
  const [runtimeStatusText, setRuntimeStatusText] = useState("");
  const [runtimeStepIndex, setRuntimeStepIndex] = useState(0);
  const runtimeTimerRef = useRef(null);

  const runtimeSteps = [
    "Khởi chạy Chromium CDP",
    "Lắng nghe lưu lượng F12",
    "Bóc tách bundle & RAM V8",
    "Đóng gói CycloneDX Runtime",
  ];

  // Tiến trình thực hiện đối sánh (Nguồn 1 vs Nguồn 2)
  const [matchProgress, setMatchProgress] = useState(0);
  const [matchStatusText, setMatchStatusText] = useState("");
  const [matchStepIndex, setMatchStepIndex] = useState(0);
  const matchTimerRef = useRef(null);

  const matchSteps = [
    "Nạp SBOM Tĩnh",
    "Đọc Runtime HAR",
    "Khử trùng lặp & So khớp",
    "Tổng hợp Báo cáo 4 trạng thái",
  ];

  useEffect(() => {
    return () => {
      if (runtimeTimerRef.current) clearInterval(runtimeTimerRef.current);
      if (matchTimerRef.current) clearInterval(matchTimerRef.current);
    };
  }, []);

  const handleSource1FileChange = (e) => {
    const file = e.target.files?.[0];
    if (!file) return;

    const reader = new FileReader();
    reader.onload = (event) => {
      const text = event.target?.result;
      if (typeof text === "string") {
        try {
          const parsed = JSON.parse(text);

          // Cơ chế kiểm soát: Chỉ chấp nhận file SBOM tĩnh ĐÃ CHUẨN HÓA VÀ XÁC THỰC NGUỒN GỐC
          const isNormalizedProperty = parsed.metadata?.properties?.some(
            (p) => p.name === "devops.provenance.normalized" && p.value === "true"
          );
          const components = parsed.components || parsed.packages || [];
          const withPedigree = components.filter((c) => c.pedigree && Object.keys(c.pedigree).length > 0).length;
          const hasHighPedigreeRatio = components.length > 0 && withPedigree / components.length >= 0.5;

          if (!isNormalizedProperty && !hasHighPedigreeRatio) {
            toast.error(
              "Tệp từ chối: Nguồn 1 chỉ tiếp nhận file SBOM tĩnh đã chuẩn hóa và xác thực nguồn gốc (vui lòng qua trang SBOM Provenance để chuẩn hóa trước)"
            );
            setSource1FileName("");
            setSource1Content("");
            setSource1ComponentCount(0);
            return;
          }

          setSource1FileName(file.name);
          setSource1Content(text);
          setSource1ComponentCount(components.length);
          toast.success(`Đã tiếp nhận SBOM tĩnh đã chuẩn hóa: ${file.name}`);
        } catch (err) {
          toast.error("Tệp không phải là định dạng JSON SBOM hợp lệ");
          setSource1ComponentCount(0);
        }
      }
    };
    reader.readAsText(file);
  };

  // Nút Run ở Nguồn 2: Bắt F12 Network trên browser và quét bộ nhớ memory Engine v8
  const handleRunRuntimeScan = async () => {
    if (!targetWebUrl.trim()) {
      toast.error("Vui lòng nhập địa chỉ web của dự án");
      return;
    }

    try {
      setIsRunningScan(true);
      setError(null);
      setRuntimeProgress(10);
      setRuntimeStepIndex(0);
      setRuntimeStatusText("Khởi chạy Chromium headless và thiết lập Chrome DevTools Protocol...");

      if (runtimeTimerRef.current) clearInterval(runtimeTimerRef.current);
      runtimeTimerRef.current = setInterval(() => {
        setRuntimeProgress((prev) => {
          if (prev < 25) {
            setRuntimeStepIndex(0);
            setRuntimeStatusText("Khởi chạy Chromium CDP và thiết lập môi trường thu thập...");
            return prev + 3;
          } else if (prev < 55) {
            setRuntimeStepIndex(1);
            setRuntimeStatusText("Truy cập trang web mục tiêu & bắt lưu lượng mạng F12...");
            return prev + 2.2;
          } else if (prev < 82) {
            setRuntimeStepIndex(2);
            setRuntimeStatusText("Giải mã bundle JavaScript & bóc tách các package trong RAM V8...");
            return prev + 1.6;
          } else if (prev < 93) {
            setRuntimeStepIndex(3);
            setRuntimeStatusText("Đóng gói dữ liệu bằng chứng và chuẩn bị xuất Runtime SBOM...");
            return prev + 0.8;
          }
          return prev;
        });
      }, 250);

      // Thu thập các network request thực tế từ browser
      let browserEntries = [];
      try {
        browserEntries = captureRealBrowserNetworkEntries();
      } catch (err) {
        console.warn("Không thể đọc window.performance:", err);
      }

      // Gọi API chạy phân tích trang web và quét bộ nhớ Engine v8
      const res = await generateRuntimeSbom({
        targetUrl: targetWebUrl.trim(),
        presetKey: "BASELINE",
        source1Content: source1Content || null,
        browserRequests: browserEntries,
      });

      if (!res || !res.success) {
        throw new Error("Không nhận được phản hồi từ trình quét runtime");
      }

      const generatedSbomJson = res.sbomJson || "{}";
      const detectedPackages = res.packages || [];
      const auditLog = res.auditLog || {};
      const rawNet = auditLog.capturedNetworkRequests || [];

      // Định dạng các request mạng F12 thực tế bóc tách từ trang web
      const formattedNet = rawNet.map((r, idx) => {
        const u = r.url || "";
        const fName = u.split("/").pop()?.split("?")[0] || u;
        return {
          id: `target-${idx}-${Date.now()}`,
          url: u,
          fileName: fName,
          type: r.type || "script",
          status: r.status || 200,
          statusText: "OK",
          sizeBytes: r.sizeBytes || 18500,
          durationMs: r.latencyMs || 25,
          startTimeMs: idx * 15,
          initiator: r.initiator || "script",
          detectedPackage: detectPackageFromResourceUrl(u),
          isLiveBrowser: true,
          timestamp: new Date().toLocaleTimeString(),
        };
      });

      clearInterval(runtimeTimerRef.current);
      setRuntimeProgress(100);
      setRuntimeStepIndex(3);
      setRuntimeStatusText("Thu thập và đóng gói Runtime SBOM CycloneDX thành công!");

      setTargetWebRequests(formattedNet);
      setRuntimeSbomJson(generatedSbomJson);
      setRuntimePackageCount(detectedPackages.length);
      setRuntimeResourceCount(formattedNet.length);
      setShowF12Inspector(true);

      // Cấu trúc file log hoàn chỉnh
      const logPayload = {
        sessionId: res.sessionId,
        targetUrl: res.targetUrl,
        scannedAt: res.scannedAt,
        componentCount: res.componentCount,
        engineV8Packages: detectedPackages,
        f12NetworkAuditLog: auditLog,
        cycloneDxRuntimeSbom: JSON.parse(generatedSbomJson),
      };
      setRuntimeLogData(logPayload);
      setRuntimeSbomReady(true);

      toast.success("Đã hoàn thành thu thập SBOM runtime từ F12 và Engine v8");
    } catch (err) {
      if (runtimeTimerRef.current) clearInterval(runtimeTimerRef.current);
      setError(err.message || "Lỗi khi quét runtime web");
      toast.error("Lỗi khi quét runtime web: " + err.message);
    } finally {
      setIsRunningScan(false);
    }
  };

  // Xuất file log JSON cho người dùng nếu muốn
  const handleExportRuntimeLog = () => {
    if (!runtimeLogData) {
      toast.error("Chưa có dữ liệu log runtime để xuất");
      return;
    }
    try {
      const jsonStr = JSON.stringify(runtimeLogData, null, 2);
      const blob = new Blob([jsonStr], { type: "application/json;charset=utf-8" });
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `runtime-sbom-log-${Date.now()}.json`;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);
      toast.success("Đã tải xuống file log JSON");
    } catch (err) {
      toast.error("Không thể xuất file log JSON: " + err.message);
    }
  };

  // Thực hiện đối sánh khi đã có đủ 2 nguồn
  const handleExecuteMatch = async () => {
    if (!source1Content) {
      toast.error("Vui lòng nạp file SBOM tĩnh ở Nguồn 1");
      return;
    }
    if (!runtimeSbomReady || !runtimeSbomJson) {
      toast.error("Vui lòng nhấn Run ở Nguồn 2 để thu thập SBOM runtime trước");
      return;
    }

    try {
      setLoading(true);
      setError(null);
      setMatchProgress(12);
      setMatchStepIndex(0);
      setMatchStatusText("Đang nạp và kiểm tra dữ liệu SBOM Tĩnh (Nguồn 1)...");

      if (matchTimerRef.current) clearInterval(matchTimerRef.current);
      matchTimerRef.current = setInterval(() => {
        setMatchProgress((prev) => {
          if (prev < 30) {
            setMatchStepIndex(0);
            setMatchStatusText("Phân tích Package URL và danh mục linh kiện trong SBOM tĩnh...");
            return prev + 3.5;
          } else if (prev < 60) {
            setMatchStepIndex(1);
            setMatchStatusText("Đọc dữ liệu Runtime HAR và giải mã các URL tài nguyên...");
            return prev + 2.8;
          } else if (prev < 85) {
            setMatchStepIndex(2);
            setMatchStatusText("Thực hiện đối soát chéo, khử trùng lặp và phân loại 4 trạng thái...");
            return prev + 2;
          } else if (prev < 94) {
            setMatchStepIndex(3);
            setMatchStatusText("Tổng hợp ma trận đối soát và tính toán số liệu thống kê...");
            return prev + 0.8;
          }
          return prev;
        });
      }, 200);

      const res = await matchPoc({
        sbomContent: source1Content,
        harContent: runtimeSbomJson,
      });

      clearInterval(matchTimerRef.current);
      setMatchProgress(100);
      setMatchStepIndex(3);
      setMatchStatusText("Đối sánh SBOM tĩnh và Runtime hoàn tất thành công!");

      setMatchReport(res);
      toast.success("Đối sánh hoàn tất");
    } catch (err) {
      if (matchTimerRef.current) clearInterval(matchTimerRef.current);
      setError(err.message || "Lỗi khi thực hiện đối sánh");
      toast.error("Đối sánh thất bại: " + err.message);
    } finally {
      setLoading(false);
    }
  };

  const handleExportCsv = async () => {
    if (!matchReport) {
      toast.error("Chưa có kết quả đối sánh để xuất");
      return;
    }
    try {
      const blob = await exportPocCsv(matchReport);
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
      const jsonStr = JSON.stringify(matchReport, null, 2);
      const blob = new Blob([jsonStr], { type: "application/json;charset=utf-8" });
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = "matching-results.json";
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);
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
    <div style={{ maxWidth: 1400, margin: "0 auto", padding: "20px 24px" }}>
      {/* Header */}
      <PageHeader
        title="Đối Sánh SBOM Tĩnh Với Dữ Liệu Runtime"
        description="Đối sánh danh sách component từ file SBOM tĩnh với SBOM runtime thu thập từ F12 Browser và bộ nhớ Engine v8"
      />

      {error && <ErrorBanner message={error} onDismiss={() => setError(null)} />}

      {/* HAI NGUỒN ĐẦU VÀO */}
      <div
        style={{
          display: "grid",
          gridTemplateColumns: "1fr 1fr",
          gap: 20,
          marginTop: 20,
          marginBottom: 20,
        }}
      >
        {/* Nguồn 1: SBOM Cơ sở duy nhất từ file */}
        <div
          style={{
            background: "var(--bg-surface)",
            border: "1px solid var(--border-default)",
            borderRadius: "var(--radius-lg)",
            padding: 18,
            display: "flex",
            flexDirection: "column",
            justifyContent: "space-between",
          }}
        >
          <div>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 12 }}>
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
              Yêu cầu tệp SBOM tĩnh <b>đã được chuẩn hóa và xác thực nguồn gốc</b> (có trường pedigree và mã băm toàn vẹn)
            </div>

            <input
              ref={fileInputRef1}
              type="file"
              accept=".json"
              style={{ display: "none" }}
              onChange={handleSource1FileChange}
            />

            <div style={{ display: "flex", gap: 10, alignItems: "center", flexWrap: "wrap", marginBottom: 12 }}>
              <button
                onClick={() => fileInputRef1.current?.click()}
                style={{
                  padding: "8px 16px",
                  borderRadius: "var(--radius-md)",
                  border: "1px solid var(--border-default)",
                  background: "var(--bg-secondary)",
                  color: "var(--text-primary)",
                  fontWeight: 600,
                  fontSize: "var(--font-sm)",
                  cursor: "pointer",
                }}
              >
                Chọn Tệp SBOM Đã Chuẩn Hóa
              </button>
            </div>
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
              Tệp đã chọn: <span style={{ color: "#60a5fa" }}>{source1FileName || "Chưa chọn tệp"}</span>
            </div>
            <div style={{ color: "var(--text-secondary)", marginTop: 4 }}>
              Số component tĩnh đã đọc: <b style={{ color: "#10b981" }}>{source1ComponentCount}</b>
            </div>
          </div>
        </div>

        {/* Nguồn 2: Dữ liệu quan sát Runtime duy nhất từ link web qua nút Run */}
        <div
          style={{
            background: "var(--bg-surface)",
            border: "1px solid var(--border-default)",
            borderRadius: "var(--radius-lg)",
            padding: 18,
            display: "flex",
            flexDirection: "column",
            justifyContent: "space-between",
          }}
        >
          <div>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 12 }}>
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
                F12 Browser và Engine v8
              </span>
            </div>

            <div style={{ fontSize: "var(--font-sm)", color: "var(--text-secondary)", marginBottom: 14 }}>
              Nhập link web của dự án và bấm Run để tự động bắt F12 và quét bộ nhớ memory Engine v8
            </div>

            {/* Ô NHẬP LINK WEB VÀ NÚT RUN CẠNH NHAU */}
            <div style={{ display: "flex", gap: 8, alignItems: "center", marginBottom: 12 }}>
              <input
                type="text"
                value={targetWebUrl}
                onChange={(e) => setTargetWebUrl(e.target.value)}
                placeholder="Nhập link web, ví dụ..."
                style={{
                  flex: 1,
                  padding: "8px 12px",
                  borderRadius: "var(--radius-md)",
                  border: "1px solid var(--border-default)",
                  background: "var(--bg-secondary)",
                  color: "var(--text-primary)",
                  fontSize: "var(--font-sm)",
                  outline: "none",
                }}
              />

              {/* NÚT RUN KÈM NÉT TAM GIÁC CHẠY BẰNG CSS BORDER */}
              <button
                onClick={handleRunRuntimeScan}
                disabled={isRunningScan}
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

            {/* Thanh tiến trình chạy link web Nguồn 2 */}
            {(isRunningScan || (runtimeProgress > 0 && runtimeProgress < 100)) && (
              <ProgressBar
                progress={runtimeProgress}
                statusText={runtimeStatusText}
                stepText={`Bước ${Math.min(runtimeStepIndex + 1, runtimeSteps.length)}/${runtimeSteps.length}`}
                steps={runtimeSteps}
                currentStepIndex={runtimeStepIndex}
                color="#16a34a"
                style={{ padding: "12px 16px", margin: "0 0 12px 0" }}
              />
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
                  Đã hoàn thành thu thập SBOM runtime từ F12 Browser và bộ nhớ Engine v8
                </div>
                <div style={{ color: "var(--text-secondary)", display: "flex", gap: 16, flexWrap: "wrap", marginBottom: 8 }}>
                  <span>Số tài nguyên F12: <b style={{ color: "var(--text-primary)" }}>{runtimeResourceCount}</b></span>
                  <span>Số thư viện nạp trong Engine v8: <b style={{ color: "var(--text-primary)" }}>{runtimePackageCount}</b></span>
                </div>
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
                Chưa có dữ liệu runtime. Vui lòng bấm nút Run để khởi chạy và quét dự án trên browser và RAM
              </div>
            )}
          </div>
        </div>
      </div>

      {/* NÚT THỰC HIỆN ĐỐI SÁNH SBOM */}
      <div style={{ textAlign: "center", marginBottom: 24 }}>
        <button
          onClick={handleExecuteMatch}
          disabled={loading || !runtimeSbomReady || !source1Content}
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
            Cần bấm nút Run ở Nguồn 2 để có SBOM runtime trước khi thực hiện đối sánh
          </div>
        )}
      </div>

      {/* Thanh tiến trình đối sánh 2 nguồn SBOM */}
      {(loading || (matchProgress > 0 && matchProgress < 100)) && (
        <div style={{ maxWidth: 860, margin: "0 auto 24px auto" }}>
          <ProgressBar
            progress={matchProgress}
            statusText={matchStatusText}
            stepText={`Bước ${Math.min(matchStepIndex + 1, matchSteps.length)}/${matchSteps.length}`}
            steps={matchSteps}
            currentStepIndex={matchStepIndex}
            color="#2563eb"
          />
        </div>
      )}

      {/* F12 NETWORK INSPECTOR BẬT TẮT ĐỘNG */}
      {showF12Inspector && (
        <div style={{ marginBottom: 24 }}>
          <F12NetworkInspector
            targetUrl={targetWebUrl}
            capturedLogs={targetWebRequests}
            onClose={() => setShowF12Inspector(false)}
            onSyncUpdate={({ synced, count, url }) => {
              setRuntimeResourceCount(count);
              if (synced && synced.length > 0) {
                const detectedPackages = synced
                  .filter((r) => r.detectedPackage && r.detectedPackage.name)
                  .map((r) => r.detectedPackage);
                setRuntimePackageCount(detectedPackages.length);
                if (!targetWebUrl && url) setTargetWebUrl(url);

                // Tạo CycloneDX SBOM từ luồng live stream nếu chưa có
                const components = detectedPackages.map((p) => ({
                  type: "library",
                  name: p.name,
                  version: p.version || "1.0.0",
                  purl: "pkg:npm/" + p.name + "@" + (p.version || "1.0.0"),
                }));
                const dynamicSbom = {
                  bomFormat: "CycloneDX",
                  specVersion: "1.4",
                  components: components,
                };
                setRuntimeSbomJson(JSON.stringify(dynamicSbom, null, 2));
                setRuntimeSbomReady(true);
              }
            }}
          />
        </div>
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
          <div style={{ fontSize: "11px", color: "var(--text-secondary)", fontWeight: 700, whiteSpace: "nowrap", overflow: "hidden", textOverflow: "ellipsis" }} title="Số Tài Nguyên Runtime">
            Tài Nguyên Runtime
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
                        {item.component || "—"}
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
