package com.example.sbom.dto.reconciliation;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.ArrayList;
import java.util.List;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class ReconciliationSummaryDTO {
    private String iterationTag;

    private int totalBuildPackages;
    private int totalRuntimePackages;

    // 3 Tình huống cốt lõi + Version Drift
    private int matchedRunningCount;     // Tình huống 1: Trùng nhau
    private int buildTestOnlyCount;      // Tình huống 2a: Test/devDependency
    private int deadOrUnusedCount;       // Tình huống 2b: SBOM có mà không dùng
    private int shadowInjectedCount;     // Tình huống 3: Runtime có mà SBOM không có
    private int versionDriftCount;       // Lệch phiên bản giữa 2 nguồn SBOM

    // Track Changes statistics
    private int addedCount;              // Shadow libs thêm vào runtime
    private int removedCount;            // Thư viện loại bỏ (dead / test)
    private int modifiedCount;           // Lệch version
    private int unchangedCount;          // Giữ nguyên trùng khớp

    // Thông tin 2 nguồn đầu vào SBOM
    private String source1Label;         // Tên nguồn 1 (Base / Build SBOM)
    private String source2Label;         // Tên nguồn 2 (Target / Runtime SBOM)

    private int totalVulnerabilities;
    private int activeRuntimeVulnerabilities;
    private int suppressedVulnerabilities;

    // Làm rõ 2 công thức:
    private double sbomTrustScore;       // Đo độ tin cậy của SBOM: phản ánh đúng bao nhiêu % runtime
    private double staticRiskScore;      // Điểm rủi ro tĩnh (chưa phân biệt runtime)
    private double contextualRiskScore;  // Điểm rủi ro mới sau đối chiếu (hạ điểm test, phạt shadow)
    private double scoreDifference;      // Chênh lệch điểm chứng minh hiệu quả giảm False Positive

    // Chuẩn hóa thang điểm 0 - 10 theo 9 tài liệu nghiên cứu:
    private Double trustScore10;          // TS: Điểm tin cậy tổng thể (0 đến 10)
    private Double staticRiskScore10;     // RS_static: Điểm rủi ro tĩnh (0 đến 10)
    private Double contextualRiskScore10; // RS_overall: Điểm rủi ro ngữ cảnh runtime (0 đến 10)
    private Double adjustedRiskScore10;   // RS_adjusted: Rủi ro hiệu chỉnh theo TS & R_penalty (0 đến 10)
    private Double peakRiskScore10;       // RS_max: Rủi ro đỉnh của thành phần nguy hiểm nhất (0 đến 10)

    @Builder.Default
    private List<String> insights = new ArrayList<>();
}
