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
public class NodeAgentReportRequest {
    private String appName;
    private String pid;
    private String nodeVersion;
    private String platform;
    private String timestamp;
    @Builder.Default
    private List<RuntimePackageItem> packages = new ArrayList<>();
    private Object memorySnapshot;
}

