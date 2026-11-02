package com.example.sbom.dto;

import lombok.Data;

import java.util.Map;

@Data
public class ValidationSummaryDTO {
    private int highConfidence;
    private int mediumConfidence;
    private int lowConfidence;
    private int declaredDependencyCount;
    private int resolvedRuntimeDependencyCount;
    private int scannerComponentCount;
    private int graphNodeCount;
    private Map<String, Integer> runtimeSupplyChainVisibility;
}
