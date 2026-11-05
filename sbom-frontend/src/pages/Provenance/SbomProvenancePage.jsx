import { useState, useMemo } from "react";
import {
  validateAndNormalizeSbomFile,
  validateAndNormalizeSbomJson,
  downloadEnrichedSbom,
} from "../../api/provenanceApi";
import { toast } from "../../components/shared/Toaster";

export default function SbomProvenancePage() {
  const [selectedFile, setSelectedFile] = useState(null);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState(null);
  const [filterStatus, setFilterStatus] = useState("ALL");
  const [searchQuery, setSearchQuery] = useState("");
  const [selectedComponent, setSelectedComponent] = useState(null);
  const [rawJsonMode, setRawJsonMode] = useState(false);
  const [jsonInput, setJsonInput] = useState("");

  const handleFileChange = (e) => {
    const file = e.target.files?.[0];
    if (file) {
      setSelectedFile(file);
      setResult(null);
      setSelectedComponent(null);
    }
  };

  const handleRunValidation = async () => {
    if (!rawJsonMode && !selectedFile) {
      toast.error("Vui lòng chọn tệp SBOM cần chuẩn hóa");
      return;
    }
    if (rawJsonMode && !jsonInput.trim()) {
      toast.error("Vui lòng dán nội dung JSON SBOM");
      return;
    }

    setLoading(true);
    try {
      let data;
      if (rawJsonMode) {
        data = await validateAndNormalizeSbomJson(jsonInput);
      } else {
        data = await validateAndNormalizeSbomFile(selectedFile);
      }

      setResult(data);

      if (data.alreadyNormalized) {
        toast.warning(data.message);
      } else {
        toast.success(data.message);
      }
    } catch (err) {
      toast.error(err.message || "Xảy ra lỗi trong quá trình xử lý SBOM");
    } finally {
      setLoading(false);
    }
  };

  const handleDownload = async () => {
    if (!result?.enrichedSbomJson) return;
    try {
      const origName = selectedFile ? selectedFile.name.replace(/\.[^/.]+$/, "") : "sbom";
      await downloadEnrichedSbom(result.enrichedSbomJson, `${origName}-normalized-pedigree.json`);
      toast.success("Đã tải xuống file SBOM chuẩn hóa thành công");
    } catch (err) {
      toast.error("Không thể tải file: " + err.message);
    }
  };

  const filteredComponents = useMemo(() => {
    if (!result?.components) return [];
    return result.components.filter((c) => {
      const matchStatus = filterStatus === "ALL" || c.status === filterStatus;
      const matchSearch =
        !searchQuery ||
        c.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
        (c.normalizedPurl && c.normalizedPurl.toLowerCase().includes(searchQuery.toLowerCase())) ||
        (c.publisherOrAuthor && c.publisherOrAuthor.toLowerCase().includes(searchQuery.toLowerCase()));
      return matchStatus && matchSearch;
    });
  }, [result, filterStatus, searchQuery]);

  return (
    <div style={{ padding: "20px 28px", maxWidth: 1400, margin: "0 auto", color: "var(--text-primary)" }}>
      {/* Header */}
      <div style={{ marginBottom: 20 }}>
        <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", flexWrap: "wrap", gap: 12 }}>
          <div>
            <h1 style={{ fontSize: 22, fontWeight: 800, margin: 0, color: "var(--text-primary)" }}>
              Xác Thực Nguồn Gốc và Chuẩn Hóa SBOM Tĩnh
            </h1>
            <p style={{ margin: "4px 0 0 0", fontSize: 13, color: "var(--text-muted)" }}>
              Chuẩn hóa định danh PURL, đối chiếu kho lưu trữ chính thức npm Registry / Maven Central, truy xuất mã nguồn GitHub và làm giàu trường pedigree theo CycloneDX
            </p>
          </div>

          {result?.enrichedSbomJson && (
            <button
              onClick={handleDownload}
              style={{
                background: "#059669",
                color: "#ffffff",
                border: "none",
                borderRadius: "var(--radius-md)",
                padding: "8px 18px",
                fontWeight: 700,
                fontSize: 13,
                cursor: "pointer",
                boxShadow: "0 2px 4px rgba(5, 150, 105, 0.2)",
              }}
            >
              Tải SBOM Đã Chuẩn Hóa
            </button>
          )}
        </div>
      </div>

      {/* Input panel */}
      <div
        style={{
          background: "var(--bg-surface)",
          border: "1px solid var(--border-default)",
          borderRadius: "var(--radius-lg)",
          padding: 20,
          marginBottom: 20,
          boxShadow: "0 1px 3px rgba(0,0,0,0.05)",
        }}
      >
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 14, flexWrap: "wrap", gap: 10 }}>
          <div style={{ fontWeight: 700, fontSize: 14 }}>
            Đầu Vào: File SBOM Tĩnh Ban Đầu Chưa Chuẩn Hóa (Syft, Trivy)
          </div>
          <div style={{ display: "flex", gap: 8 }}>
            <button
              onClick={() => setRawJsonMode(false)}
              style={{
                padding: "4px 12px",
                borderRadius: "var(--radius-sm)",
                border: !rawJsonMode ? "1px solid #2563eb" : "1px solid var(--border-default)",
                background: !rawJsonMode ? "#eff6ff" : "transparent",
                color: !rawJsonMode ? "#2563eb" : "var(--text-muted)",
                fontSize: 12,
                fontWeight: 600,
                cursor: "pointer",
              }}
            >
              Tải Tệp Lên
            </button>
            <button
              onClick={() => setRawJsonMode(true)}
              style={{
                padding: "4px 12px",
                borderRadius: "var(--radius-sm)",
                border: rawJsonMode ? "1px solid #2563eb" : "1px solid var(--border-default)",
                background: rawJsonMode ? "#eff6ff" : "transparent",
                color: rawJsonMode ? "#2563eb" : "var(--text-muted)",
                fontSize: 12,
                fontWeight: 600,
                cursor: "pointer",
              }}
            >
              Dán JSON Trực Tiếp
            </button>
          </div>
        </div>

        {!rawJsonMode ? (
          <div style={{ display: "flex", alignItems: "center", gap: 14, flexWrap: "wrap" }}>
            <input
              type="file"
              accept=".json,.xml"
              onChange={handleFileChange}
              style={{
                fontSize: 13,
                border: "1px solid var(--border-default)",
                padding: "8px 12px",
                borderRadius: "var(--radius-md)",
                background: "var(--bg-secondary)",
                flex: 1,
                minWidth: 260,
              }}
            />
            <button
              onClick={handleRunValidation}
              disabled={loading || !selectedFile}
              style={{
                padding: "9px 24px",
                background: loading || !selectedFile ? "#94a3b8" : "#2563eb",
                color: "#ffffff",
                border: "none",
                borderRadius: "var(--radius-md)",
                fontWeight: 700,
                fontSize: 13,
                cursor: loading || !selectedFile ? "not-allowed" : "pointer",
              }}
            >
              {loading ? "Đang Xác Thực và Chuẩn Hóa..." : "Bắt Đầu Xác Thực Nguồn Gốc"}
            </button>
          </div>
        ) : (
          <div>
            <textarea
              rows={6}
              value={jsonInput}
              onChange={(e) => setJsonInput(e.target.value)}
              placeholder="Dán toàn bộ nội dung file SBOM CycloneDX hoặc SPDX JSON tại đây..."
              style={{
                width: "100%",
                padding: 12,
                fontSize: 12,
                fontFamily: "Consolas, monospace",
                border: "1px solid var(--border-default)",
                borderRadius: "var(--radius-md)",
                background: "var(--bg-secondary)",
                color: "var(--text-primary)",
                resize: "vertical",
                boxSizing: "border-box",
              }}
            />
            <div style={{ marginTop: 10, display: "flex", justifyContent: "flex-end" }}>
              <button
                onClick={handleRunValidation}
                disabled={loading || !jsonInput.trim()}
                style={{
                  padding: "9px 24px",
                  background: loading || !jsonInput.trim() ? "#94a3b8" : "#2563eb",
                  color: "#ffffff",
                  border: "none",
                  borderRadius: "var(--radius-md)",
                  fontWeight: 700,
                  fontSize: 13,
                  cursor: loading || !jsonInput.trim() ? "not-allowed" : "pointer",
                }}
              >
                {loading ? "Đang Xác Thực và Chuẩn Hóa..." : "Bắt Đầu Xác Thực Nguồn Gốc"}
              </button>
            </div>
          </div>
        )}

        <div style={{ marginTop: 12, fontSize: 12, color: "var(--text-muted)", display: "flex", alignItems: "center", gap: 16 }}>
          <span>Cơ chế kiểm soát: Tự động chặn các file SBOM đã được xác thực nguồn gốc hoặc đã có trường pedigree</span>
          <span>Định dạng hỗ trợ: CycloneDX 1.4-1.6 JSON, SPDX 2.3 JSON</span>
        </div>
      </div>

      {/* Cảnh báo nếu file đã chuẩn hóa */}
      {result?.alreadyNormalized && (
        <div
          style={{
            background: "#fffbeb",
            border: "1px solid #fde68a",
            borderRadius: "var(--radius-lg)",
            padding: 18,
            marginBottom: 20,
            color: "#b45309",
          }}
        >
          <div style={{ fontWeight: 800, fontSize: 15, marginBottom: 4 }}>
            Thông Báo Cơ Chế Kiểm Soát: SBOM Đã Được Chuẩn Hóa Trước Đó
          </div>
          <div style={{ fontSize: 13, lineHeight: 1.5 }}>
            {result.message}
          </div>
          <div style={{ marginTop: 8, fontSize: 12, color: "#92400e" }}>
            Số lượng linh kiện đã có sẵn thông tin nguồn gốc: <b>{result.totalComponents}</b> thành phần. Hệ thống bảo toàn tính toàn vẹn và không chạy lại pipeline xác thực.
          </div>
        </div>
      )}

      {/* Báo cáo thống kê kết quả nếu chưa chuẩn hóa và vừa chạy xong */}
      {result && !result.alreadyNormalized && (
        <>
          {/* Card xác thực mã băm SHA-256 toàn vẹn */}
          <div
            style={{
              background: "#ffffff",
              border: "1px solid #93c5fd",
              borderRadius: "var(--radius-lg)",
              padding: "16px 20px",
              marginBottom: 20,
              boxShadow: "0 2px 4px rgba(37, 99, 235, 0.06)",
            }}
          >
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: 10, marginBottom: 8 }}>
              <div style={{ fontWeight: 800, fontSize: 13.5, color: "#1d4ed8" }}>
                Xác Thực Tính Toàn Vẹn Mã Băm SHA-256 Hệ Thống
              </div>
              <span
                style={{
                  fontSize: 11,
                  padding: "3px 10px",
                  borderRadius: 12,
                  background: "rgba(37, 99, 235, 0.1)",
                  color: "#2563eb",
                  fontWeight: 700,
                  border: "1px solid rgba(37, 99, 235, 0.25)",
                }}
              >
                Mã băm FIPS-180-4
              </span>
            </div>

            <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(320px, 1fr))", gap: 14 }}>
              <div style={{ background: "#f8fafc", padding: 10, borderRadius: 6, border: "1px solid #e2e8f0" }}>
                <div style={{ fontSize: 11, color: "var(--text-muted)", fontWeight: 700 }}>Mã băm SHA-256 tệp SBOM đầu vào:</div>
                <div style={{ fontFamily: "var(--font-mono)", fontSize: 11.5, color: "#0f172a", wordBreak: "break-all", marginTop: 2 }}>
                  {result.fileSha256 || "—"}
                </div>
              </div>

              <div style={{ background: "#f8fafc", padding: 10, borderRadius: 6, border: "1px solid #e2e8f0" }}>
                <div style={{ fontSize: 11, color: "var(--text-muted)", fontWeight: 700 }}>Mã băm phả hệ Pedigree Digest SHA-256:</div>
                <div style={{ fontFamily: "var(--font-mono)", fontSize: 11.5, color: "#059669", wordBreak: "break-all", marginTop: 2 }}>
                  {result.pedigreeDigestSha256 || "—"}
                </div>
              </div>
            </div>
          </div>

          {/* Thống kê 4 số liệu */}
          <div
            style={{
              display: "grid",
              gridTemplateColumns: "repeat(auto-fit, minmax(200px, 1fr))",
              gap: 14,
              marginBottom: 20,
            }}
          >
            <div style={{ background: "#ffffff", border: "1px solid var(--border-default)", borderRadius: "var(--radius-lg)", padding: "14px 18px" }}>
              <div style={{ fontSize: 12, color: "var(--text-muted)", fontWeight: 600 }}>Tổng thành phần</div>
              <div style={{ fontSize: 24, fontWeight: 800, color: "var(--text-primary)", marginTop: 4 }}>
                {result.totalComponents}
              </div>
            </div>

            <div style={{ background: "#ffffff", border: "1px solid #bbf7d0", borderRadius: "var(--radius-lg)", padding: "14px 18px" }}>
              <div style={{ fontSize: 12, color: "#16a34a", fontWeight: 700 }}>Đã xác thực chính thức</div>
              <div style={{ fontSize: 24, fontWeight: 800, color: "#16a34a", marginTop: 4 }}>
                {result.verifiedComponents}
              </div>
            </div>

            <div style={{ background: "#ffffff", border: "1px solid #fecaca", borderRadius: "var(--radius-lg)", padding: "14px 18px" }}>
              <div style={{ fontSize: 12, color: "#dc2626", fontWeight: 700 }}>Không tìm thấy</div>
              <div style={{ fontSize: 24, fontWeight: 800, color: "#dc2626", marginTop: 4 }}>
                {result.suspiciousComponents}
              </div>
            </div>

            <div style={{ background: "#ffffff", border: "1px solid var(--border-default)", borderRadius: "var(--radius-lg)", padding: "14px 18px" }}>
              <div style={{ fontSize: 12, color: "var(--text-muted)", fontWeight: 600 }}>Khác</div>
              <div style={{ fontSize: 24, fontWeight: 800, color: "var(--text-muted)", marginTop: 4 }}>
                {result.unverifiedComponents}
              </div>
            </div>
          </div>

          {/* Bộ lọc và tìm kiếm */}
          <div
            style={{
              background: "var(--bg-surface)",
              border: "1px solid var(--border-default)",
              borderRadius: "var(--radius-lg)",
              overflow: "hidden",
              boxShadow: "0 1px 3px rgba(0,0,0,0.05)",
            }}
          >
            <div
              style={{
                padding: "12px 18px",
                borderBottom: "1px solid var(--border-default)",
                background: "var(--bg-secondary)",
                display: "flex",
                alignItems: "center",
                justifyContent: "space-between",
                flexWrap: "wrap",
                gap: 12,
              }}
            >
              <div style={{ display: "flex", gap: 8, alignItems: "center", flexWrap: "wrap" }}>
                {[
                  { key: "ALL", label: `Tất cả (${result.components.length})` },
                  { key: "VERIFIED", label: `Đã Xác Thực (${result.verifiedComponents})` },
                  { key: "SUSPICIOUS_VERSION", label: "Lệch Version" },
                  { key: "NOT_FOUND", label: "Không Tìm Thấy Kho" },
                ].map((t) => (
                  <button
                    key={t.key}
                    onClick={() => setFilterStatus(t.key)}
                    style={{
                      padding: "4px 12px",
                      borderRadius: "var(--radius-sm)",
                      border: filterStatus === t.key ? "1px solid #2563eb" : "1px solid var(--border-default)",
                      background: filterStatus === t.key ? "#2563eb" : "#ffffff",
                      color: filterStatus === t.key ? "#ffffff" : "var(--text-primary)",
                      fontSize: 11.5,
                      fontWeight: filterStatus === t.key ? 700 : 500,
                      cursor: "pointer",
                    }}
                  >
                    {t.label}
                  </button>
                ))}
              </div>

              <div style={{ minWidth: 280 }}>
                <input
                  type="text"
                  placeholder="Lọc tên gói, purl, tác giả..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  style={{
                    width: "100%",
                    padding: "6px 12px",
                    borderRadius: "var(--radius-sm)",
                    border: "1px solid var(--border-default)",
                    fontSize: 12,
                    boxSizing: "border-box",
                  }}
                />
              </div>
            </div>

            {/* Bảng chi tiết */}
            <div style={{ display: "grid", gridTemplateColumns: selectedComponent ? "1fr 400px" : "1fr", maxHeight: 520, overflow: "hidden" }}>
              <div style={{ overflowY: "auto", maxHeight: 520 }}>
                <table style={{ width: "100%", tableLayout: "fixed", borderCollapse: "separate", borderSpacing: 0, fontSize: 12, textAlign: "left" }}>
                  <thead>
                    <tr style={{ color: "#475569", fontWeight: 700 }}>
                      <th style={{ position: "sticky", top: 0, background: "#f8fafc", zIndex: 10, padding: "10px 14px", width: "22%", borderBottom: "1px solid #e2e8f0" }}>
                        Thành Phần (Package)
                      </th>
                      <th style={{ position: "sticky", top: 0, background: "#f8fafc", zIndex: 10, padding: "10px 8px", width: "7%", borderBottom: "1px solid #e2e8f0" }}>
                        Phiên Bản
                      </th>
                      <th style={{ position: "sticky", top: 0, background: "#f8fafc", zIndex: 10, padding: "10px 8px", width: "10%", borderBottom: "1px solid #e2e8f0" }}>
                        Trạng Thái
                      </th>
                      <th style={{ position: "sticky", top: 0, background: "#f8fafc", zIndex: 10, padding: "10px 12px", width: "31%", borderBottom: "1px solid #e2e8f0" }}>
                        PURL Chuẩn Hóa
                      </th>
                      <th style={{ position: "sticky", top: 0, background: "#f8fafc", zIndex: 10, padding: "10px 12px", width: "20%", borderBottom: "1px solid #e2e8f0" }}>
                        Mã Băm Toàn Vẹn Chính Thức
                      </th>
                      <th style={{ position: "sticky", top: 0, background: "#f8fafc", zIndex: 10, padding: "10px 10px", width: "10%", borderBottom: "1px solid #e2e8f0" }}>
                        Kho Lưu Trữ
                      </th>
                    </tr>
                  </thead>
                  <tbody>
                    {filteredComponents.length === 0 ? (
                      <tr>
                        <td colSpan={6} style={{ textAlign: "center", padding: 30, color: "var(--text-muted)", background: "#ffffff" }}>
                          Không có thành phần nào phù hợp với bộ lọc
                        </td>
                      </tr>
                    ) : (
                      filteredComponents.map((c, idx) => {
                        const isSelected = selectedComponent?.name === c.name;
                        return (
                          <tr
                            key={idx}
                            onClick={() => setSelectedComponent((prev) => (prev?.name === c.name ? null : c))}
                            style={{
                              background: isSelected ? "#eff6ff" : "#ffffff",
                              cursor: "pointer",
                              transition: "background 0.15s ease",
                            }}
                          >
                            <td style={{ padding: "10px 14px", borderBottom: "1px solid #e2e8f0", overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                              <div style={{ fontWeight: 700, color: "var(--text-primary)", overflow: "hidden", textOverflow: "ellipsis" }} title={c.name}>
                                {c.name}
                              </div>
                              {c.publisherOrAuthor && (
                                <div style={{ fontSize: 11, color: "var(--text-muted)", overflow: "hidden", textOverflow: "ellipsis" }} title={c.publisherOrAuthor}>
                                  {c.publisherOrAuthor}
                                </div>
                              )}
                            </td>
                            <td style={{ padding: "10px 8px", borderBottom: "1px solid #e2e8f0", fontFamily: "var(--font-mono)", fontWeight: 600, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }} title={c.version || "N/A"}>
                              {c.version || "N/A"}
                            </td>
                            <td style={{ padding: "10px 8px", borderBottom: "1px solid #e2e8f0", whiteSpace: "nowrap" }}>
                              <span
                                style={{
                                  padding: "2px 8px",
                                  borderRadius: 4,
                                  fontSize: 10.5,
                                  fontWeight: 700,
                                  background:
                                    c.status === "VERIFIED"
                                      ? "rgba(16, 185, 129, 0.12)"
                                      : c.status === "SUSPICIOUS_VERSION"
                                        ? "rgba(239, 68, 68, 0.12)"
                                        : "rgba(245, 158, 11, 0.12)",
                                  color:
                                    c.status === "VERIFIED"
                                      ? "#059669"
                                      : c.status === "SUSPICIOUS_VERSION"
                                        ? "#dc2626"
                                        : "#d97706",
                                  border:
                                    c.status === "VERIFIED"
                                      ? "1px solid rgba(16, 185, 129, 0.3)"
                                      : c.status === "SUSPICIOUS_VERSION"
                                        ? "1px solid rgba(239, 68, 68, 0.3)"
                                        : "1px solid rgba(245, 158, 11, 0.3)",
                                }}
                              >
                                {c.status}
                              </span>
                            </td>
                            <td style={{ padding: "10px 12px", borderBottom: "1px solid #e2e8f0", fontFamily: "var(--font-mono)", fontSize: 11, color: "#2563eb", wordBreak: "break-all" }}>
                              {c.normalizedPurl}
                            </td>
                            <td style={{ padding: "10px 12px", borderBottom: "1px solid #e2e8f0", fontFamily: "var(--font-mono)", fontSize: 10.5, color: "#334155", wordBreak: "break-all" }}>
                              {c.officialHash ? (
                                <span title={c.officialHash}>
                                  {c.officialHash}
                                </span>
                              ) : (
                                "—"
                              )}
                            </td>
                            <td style={{ padding: "10px 10px", borderBottom: "1px solid #e2e8f0", fontSize: 11, color: "var(--text-muted)", whiteSpace: "nowrap" }}>
                              {c.ecosystem?.toUpperCase()}
                            </td>
                          </tr>
                        );
                      })
                    )}
                  </tbody>
                </table>
              </div>

              {/* Ngăn thông tin chi tiết */}
              {selectedComponent && (
                <div
                  style={{
                    background: "var(--bg-secondary)",
                    borderLeft: "1px solid var(--border-default)",
                    padding: 16,
                    overflowY: "auto",
                    maxHeight: 520,
                    fontSize: 12,
                  }}
                >
                  <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: 12, borderBottom: "1px solid var(--border-default)", paddingBottom: 8 }}>
                    <div style={{ fontWeight: 800, fontSize: 13, color: "var(--text-primary)" }}>
                      Chi Tiết Nguồn Gốc và Pedigree
                    </div>
                    <button
                      onClick={() => setSelectedComponent(null)}
                      style={{ background: "transparent", border: "none", color: "var(--text-muted)", cursor: "pointer", fontWeight: 700 }}
                    >
                      Đóng
                    </button>
                  </div>

                  <div style={{ marginBottom: 14 }}>
                    <div style={{ fontWeight: 700, fontSize: 13, color: "#2563eb" }}>{selectedComponent.name}</div>
                    <div style={{ marginTop: 4 }}><b>Phiên bản:</b> {selectedComponent.version}</div>
                    <div style={{ marginTop: 2, wordBreak: "break-all" }}><b>PURL:</b> <code>{selectedComponent.normalizedPurl}</code></div>
                    <div style={{ marginTop: 2 }}><b>Kho chính thức:</b> {selectedComponent.officialRegistry || "N/A"}</div>
                    {selectedComponent.repositoryUrl && (
                      <div style={{ marginTop: 2, wordBreak: "break-all" }}>
                        <b>Mã nguồn:</b> <a href={selectedComponent.repositoryUrl} target="_blank" rel="noreferrer" style={{ color: "#2563eb" }}>{selectedComponent.repositoryUrl}</a>
                      </div>
                    )}
                    {selectedComponent.commitSha && (
                      <div style={{ marginTop: 2, fontFamily: "var(--font-mono)", fontSize: 11 }}>
                        <b>Commit SHA:</b> {selectedComponent.commitSha}
                      </div>
                    )}
                    {selectedComponent.officialHash && (
                      <div style={{ marginTop: 4, background: "#ffffff", padding: 8, borderRadius: 4, border: "1px solid var(--border-default)", wordBreak: "break-all" }}>
                        <div style={{ fontWeight: 700, color: "#059669", fontSize: 11 }}>Mã băm toàn vẹn:</div>
                        <div style={{ fontFamily: "var(--font-mono)", fontSize: 10.5 }}>{selectedComponent.officialHash}</div>
                      </div>
                    )}
                  </div>

                  {/* Cảnh báo vi phạm nếu có */}
                  {selectedComponent.issues?.length > 0 && (
                    <div style={{ background: "#fef2f2", border: "1px solid #fecaca", padding: 10, borderRadius: 6, marginBottom: 14, color: "#dc2626" }}>
                      <div style={{ fontWeight: 700, marginBottom: 4 }}>Phát Hiện Bất Thường:</div>
                      {selectedComponent.issues.map((iss, i) => (
                        <div key={i} style={{ fontSize: 11.5 }}>- {iss}</div>
                      ))}
                    </div>
                  )}

                  {/* Khối CycloneDX Pedigree JSON */}
                  <div style={{ background: "#ffffff", padding: 10, borderRadius: 6, border: "1px solid var(--border-default)" }}>
                    <div style={{ fontWeight: 700, color: "var(--text-primary)", marginBottom: 6, fontSize: 11 }}>
                      Cấu Trúc Pedigree CycloneDX Đã Tạo:
                    </div>
                    <pre style={{ margin: 0, fontSize: 10.5, fontFamily: "Consolas, monospace", color: "var(--text-secondary)", maxHeight: 180, overflowY: "auto", whiteSpace: "pre-wrap", wordBreak: "break-all" }}>
                      {JSON.stringify(selectedComponent.pedigree, null, 2)}
                    </pre>
                  </div>
                </div>
              )}
            </div>
          </div>
        </>
      )}
    </div>
  );
}

