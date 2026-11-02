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
public class RuntimeReconciliationResponse {
    private ReconciliationSummaryDTO summary;
    @Builder.Default
    private List<ReconciledPackageDTO> packages = new ArrayList<>();
    private Object runtimeAuditLog; // Toàn bộ log chi tiết Network F12 và Snapshot RAM để xuất file .json
}
