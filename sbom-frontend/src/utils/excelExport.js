import * as XLSX from "xlsx";

/**
 * Xuất Báo Cáo Đối Sánh SBOM Đầy Đủ Ra File Excel (.xlsx)
 * Gồm 3 Sheet chuyên nghiệp phục vụ Developer và Quản trị viên:
 * 1. Tổng Quan Đối Sánh (Summary & Metrics)
 * 2. Chi Tiết Track Changes (Toàn bộ thư viện & Đánh giá kỹ thuật)
 * 3. Danh Mục Cần Xử Lý (Action Items cho Developer)
 */
export function exportReconciliationToExcel(reconcileResult) {
  if (!reconcileResult) {
    throw new Error("Không có dữ liệu đối sánh để xuất báo cáo");
  }

  const summary = reconcileResult.summary || {};
  const packages = reconcileResult.packages || [];
  const exportDate = new Date().toLocaleString("vi-VN");

  const wb = XLSX.utils.book_new();

  // =========================================================================
  // SHEET 1: TỔNG QUAN ĐỐI SÁNH (SUMMARY)
  // =========================================================================
  const summaryRows = [
    ["BÁO CÁO ĐỐI SÁNH KHÁC BIỆT SBOM (SBOM RECONCILIATION & TRACK CHANGES REPORT)"],
    ["Thời gian xuất:", exportDate],
    ["Nguồn 1 (SBOM Cơ Sở / Build-time):", summary.source1Label || "Build Manifest"],
    ["Nguồn 2 (SBOM Đối Chiếu / Runtime):", summary.source2Label || "Runtime JVM RAM"],
    [],
    ["CHỈ SỐ ĐỐI SÁNH THỰC TẾ", "GIÁ TRỊ", "Ý NGHĨA KỸ THUẬT / PHÂN TÍCH BẢO MẬT"],
    ["Tổng số thư viện Nguồn 1 (Base/Build)", summary.totalBuildPackages || 0, "Số lượng thành phần khai báo trong file cấu hình (pom.xml)"],
    ["Tổng số thư viện Nguồn 2 (Target/Runtime)", summary.totalRuntimePackages || 0, "Số lượng thành phần nạp thực tế vào bộ nhớ RAM máy chủ"],
    ["Trùng khớp hoàn toàn (Matched)", summary.matchedRunningCount || 0, "Thư viện hoạt động bình thường, phiên bản đồng nhất 100%"],
    ["Thư viện lạ tiêm nhiễm (Shadow Injected)", summary.shadowInjectedCount || 0, "CẢNH BÁO: Thư viện xuất hiện ở Runtime nhưng KHÔNG có trong SBOM"],
    ["Thư viện dư thừa (Dead / Unused Code)", summary.deadOrUnusedCount || 0, "Khai báo trong Build nhưng 0 class nạp vào RAM (Code chết)"],
    ["Lệch phiên bản (Version Drift)", summary.versionDriftCount || 0, "Xung đột phiên bản giữa lúc đóng gói và lúc chạy thực tế"],
    ["Thư viện Test/Build Only", summary.buildTestOnlyCount || 0, "Được Maven/Gradle loại trừ an toàn khỏi Production"],
    [],
    ["CHỈ SỐ LỖ HỔNG CVE THEO NGỮ CẢNH", "GIÁ TRỊ", "Ý NGHĨA THỰC TIỄN CHO DEVELOPER"],
    ["Tổng số lỗ hổng CVE ghi nhận", summary.totalVulnerabilities || 0, "Tổng số CVE từ toàn bộ các thành phần"],
    ["Lỗ hổng CVE đang chạy trong RAM (Active)", summary.activeRuntimeVulnerabilities || 0, "Bắt buộc vá khẩn cấp (Active Attack Surface đang mở)"],
    ["Lỗ hổng CVE được giảm trừ (Suppressed)", summary.suppressedVulnerabilities || 0, "Thuộc Test-only hoặc Dead Code, không khai thác được trên Production"],
    [],
    ["KẾT LUẬN TỰ ĐỘNG CỦA HỆ THỐNG:"],
  ];

  if (summary.insights && summary.insights.length > 0) {
    summary.insights.forEach((ins, idx) => {
      summaryRows.push([`• ${ins}`]);
    });
  }

  const wsSummary = XLSX.utils.aoa_to_sheet(summaryRows);

  // Set column widths for summary
  wsSummary["!cols"] = [
    { wch: 45 },
    { wch: 15 },
    { wch: 65 },
  ];

  XLSX.utils.book_append_sheet(wb, wsSummary, "Tong_Quan_Doi_Sanh");

  // =========================================================================
  // SHEET 2: CHI TIẾT TRACK CHANGES (DETAIL & TECHNICAL EVALUATION)
  // =========================================================================
  const detailHeaders = [
    "STT",
    "Tên Thư Viện (Package)",
    "Phân Loại Đối Sánh",
    "Ký Hiệu Track Changes",
    "Phiên Bản Build (Base)",
    "Phiên Bản Runtime (Target)",
    "Scope Khai Báo",
    "Số Class Trong RAM",
    "Cơ Chế Nạp",
    "Danh Sách CVEs",
    "Mức Rủi Ro",
    "Nguyên Nhân Kỹ Thuật",
    "Đánh Giá An Ninh & Chuỗi Cung Ứng",
    "Hướng Dẫn Khắc Phục (Actionable Remediation)",
  ];

  const detailRows = [detailHeaders];

  packages.forEach((pkg, idx) => {
    let catLabel = pkg.category;
    if (pkg.category === "MATCHED_RUNNING") catLabel = "Trùng khớp";
    else if (pkg.category === "SHADOW_INJECTED") catLabel = "Shadow Lib Lạ";
    else if (pkg.category === "DEAD_OR_UNUSED") catLabel = "Dead / Unused Code";
    else if (pkg.category === "BUILD_TEST_ONLY") catLabel = "Test/Build Only";
    else if (pkg.category === "VERSION_DRIFT") catLabel = "Lệch Phiên Bản (Drift)";

    let diffSymbol = "= Giữ nguyên";
    if (pkg.diffType === "ADDED") diffSymbol = "+ Thêm mới (Shadow)";
    else if (pkg.diffType === "REMOVED") diffSymbol = "- Loại bỏ (Dead/Test)";
    else if (pkg.diffType === "MODIFIED") diffSymbol = "~ Thay đổi (Drift)";

    const cveStr = pkg.vulnerabilities && pkg.vulnerabilities.length > 0
      ? pkg.vulnerabilities.map(v => `${v.name || v.vulnId} (CVSS: ${v.cvssScore || "N/A"})`).join("; ")
      : "Không có CVE";

    detailRows.push([
      idx + 1,
      pkg.packageName || "N/A",
      catLabel,
      diffSymbol,
      pkg.declaredVersion || "Không có",
      pkg.runtimeVersion || "Không nạp",
      pkg.buildScope || "compile",
      pkg.loadedClassesCount || 0,
      pkg.runtimeSource || "JVM",
      cveStr,
      pkg.aiRiskLevel || "INFO",
      pkg.aiTechnicalReason || "",
      pkg.aiSecurityRisk || "",
      pkg.aiRemediation || "",
    ]);
  });

  const wsDetail = XLSX.utils.aoa_to_sheet(detailRows);

  wsDetail["!cols"] = [
    { wch: 6 },
    { wch: 42 },
    { wch: 22 },
    { wch: 22 },
    { wch: 18 },
    { wch: 18 },
    { wch: 18 },
    { wch: 15 },
    { wch: 25 },
    { wch: 32 },
    { wch: 16 },
    { wch: 45 },
    { wch: 50 },
    { wch: 45 },
  ];

  XLSX.utils.book_append_sheet(wb, wsDetail, "Chi_Tiet_Track_Changes");

  // =========================================================================
  // SHEET 3: DANH MỤC CẦN XỬ LÝ (ACTION ITEMS CHO DEVELOPER)
  // =========================================================================
  const actionHeaders = [
    "STT",
    "Tên Thư Viện",
    "Loại Bất Thường",
    "Mức Độ Rủi Ro",
    "Classes Nạp",
    "Nguyên Nhân Phát Hiện",
    "Câu Lệnh / Hướng Xử Lý Khắc Phục Cụ Thể (Developer Action)",
  ];

  const actionRows = [actionHeaders];
  let actionIdx = 1;

  // Lọc chỉ lấy các mục có khác biệt hoặc có CVE cần xử lý
  packages.forEach((pkg) => {
    if (pkg.category !== "MATCHED_RUNNING" || (pkg.vulnerabilities && pkg.vulnerabilities.length > 0)) {
      let issueType = "Lỗ hổng CVE";
      if (pkg.category === "SHADOW_INJECTED") issueType = "Mã độc / Thư viện lạ nạp ngầm ngoài SBOM";
      else if (pkg.category === "DEAD_OR_UNUSED") issueType = "Thư viện rác thừa trong pom.xml (0 class nạp)";
      else if (pkg.category === "VERSION_DRIFT") issueType = "Xung đột / Lệch phiên bản giữa build và runtime";
      else if (pkg.category === "BUILD_TEST_ONLY") issueType = "Thư viện Test (Đã loại trừ khỏi Production)";

      actionRows.push([
        actionIdx++,
        pkg.packageName,
        issueType,
        pkg.aiRiskLevel || "MEDIUM",
        pkg.loadedClassesCount || 0,
        pkg.aiTechnicalReason || pkg.description || "Phát hiện sai lệch đối sánh",
        pkg.aiRemediation || "Kiểm tra cấu hình dependencies",
      ]);
    }
  });

  const wsAction = XLSX.utils.aoa_to_sheet(actionRows);

  wsAction["!cols"] = [
    { wch: 6 },
    { wch: 42 },
    { wch: 35 },
    { wch: 16 },
    { wch: 14 },
    { wch: 48 },
    { wch: 55 },
  ];

  XLSX.utils.book_append_sheet(wb, wsAction, "Danh_Muc_Can_Xu_Ly");

  // Tên file theo ngày giờ
  const fileName = `Bao_Cao_Doi_Sanh_SBOM_${new Date().toISOString().slice(0, 10)}_${Date.now().toString().slice(-4)}.xlsx`;
  XLSX.writeFile(wb, fileName);
}

