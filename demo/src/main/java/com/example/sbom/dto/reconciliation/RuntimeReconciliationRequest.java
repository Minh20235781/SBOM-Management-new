package com.example.sbom.dto.reconciliation;

import lombok.Data;
import java.util.List;

@Data
public class RuntimeReconciliationRequest {
    private Long projectId;
    private String repoName;
    private String iterationTag; // e.g. "Vòng 1 - Baseline", "Vòng 2 - Test/Dead Code", "Vòng 3 - Shadow Lib"
    private List<RuntimePackageItem> runtimePackages;
}
