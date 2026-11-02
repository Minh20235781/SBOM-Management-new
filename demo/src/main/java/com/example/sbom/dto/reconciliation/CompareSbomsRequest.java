package com.example.sbom.dto.reconciliation;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.List;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class CompareSbomsRequest {
    /**
     * Nguồn 1 (Cơ sở / Base / Build-time SBOM):
     * "PROJECT" | "FILE_CONTENT" | "PRESET"
     */
    private String source1Type;
    private Long source1ProjectId;
    private String source1Content;
    private String source1Label;

    /**
     * Nguồn 2 (Đối chiếu / Target / Runtime SBOM):
     * "PROJECT" | "FILE_CONTENT" | "LIVE_JVM" | "LIVE_WEB" | "PRESET"
     */
    private String source2Type;
    private Long source2ProjectId;
    private String source2Content;
    private String source2Label;
    private String targetUrl; // URL web của dự án để quét F12 Network & RAM (vd: http://localhost:3000, vercel.app)

    /**
     * Mẫu demo cài sẵn (nếu chọn)
     */
    private String presetKey; // "BASELINE", "DEAD_TEST", "SHADOW_DRIFT", "LIVE_JVM"

    /**
     * Tùy chọn truyền trực tiếp danh sách package đã parse
     */
    private List<RuntimePackageItem> customSource1Packages;
    private List<RuntimePackageItem> customSource2Packages;
}

