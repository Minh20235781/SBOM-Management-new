package com.example.sbom.dto.reconciliation;

import com.example.sbom.dto.VulnerabilityDTO;
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
public class ReconciledPackageDTO {
    private String packageName;
    private String declaredVersion;
    private String runtimeVersion;

    /**
     * Categories based on advisor requirements:
     * MATCHED_RUNNING: Có trong SBOM tĩnh và đang nạp chạy thật ở runtime (Tình huống 1)
     * BUILD_TEST_ONLY: Khai báo scope test/devDependency, không nạp ở runtime (Tình huống 2a)
     * DEAD_OR_UNUSED: Có trong build manifest nhưng không hề được nạp/gọi tới (Tình huống 2b)
     * SHADOW_INJECTED: Không có trong SBOM tĩnh nhưng lại xuất hiện trong runtime (Tình huống 3)
     */
    private String category;

    private boolean inBuildSbom;
    private boolean inRuntime;
    private String buildScope; // compile, test, runtime, devDependency

    @Builder.Default
    private List<VulnerabilityDTO> vulnerabilities = new ArrayList<>();

    private Double originalCvssMax;
    private Double effectiveCvssMax; // Sau khi tái đánh giá theo ngữ cảnh runtime
    private Double vexModifier;      // Evex,i: Hệ số điều chỉnh khả năng khai thác VEX (0.0 đến 1.0)
    private Double componentRiskValue; // RVi: Giá trị rủi ro thành phần (thang 0 đến 10)

    /**
     * URGENT_FIX: Chạy thật và có lỗ hổng nguy hiểm
     * SUPPRESSED_BUILD_ONLY: Có lỗ hổng nhưng chỉ ở khâu test/dev, không chạy production
     * UNUSED_CLEANUP: Thư viện thừa, khuyến nghị gỡ bỏ khỏi build manifest
     * ANOMALY_INVESTIGATE: Thư viện lạ nạp ngầm, nguy cơ tấn công chuỗi cung ứng
     * SAFE_ACTIVE: Chạy bình thường, không có lỗ hổng
     */
    private String riskAction;

    private String description;

    /**
     * Thuộc tính hỗ trợ giao diện Track Changes (MS Word style):
     * ADDED: Thư viện tiêm nhiễm thêm vào runtime (Shadow Injected)
     * REMOVED: Thư viện trong SBOM gốc nhưng không có ở runtime (Dead code, Test-only)
     * MODIFIED: Lệch phiên bản giữa Build và Runtime (Version Drift)
     * UNCHANGED: Trùng khớp hoàn toàn (Matched Running)
     */
    private String diffType;

    private Integer loadedClassesCount;
    private String runtimeSource;

    /**
     * Đánh giá AI động cho từng khác biệt riêng biệt (Không dùng text tĩnh):
     */
    private String aiTechnicalReason;
    private String aiSecurityRisk;
    private String aiRemediation;
    private String aiRiskLevel; // CRITICAL, HIGH, MEDIUM, LOW, INFO
}
