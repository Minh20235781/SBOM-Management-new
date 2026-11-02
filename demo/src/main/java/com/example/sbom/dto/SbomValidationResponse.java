package com.example.sbom.dto;

import lombok.Data;

import java.util.List;
import java.util.Map;

@Data
public class SbomValidationResponse {
    private Double structuralTrustScore;
    private String structuralTrustQuality;
    private Double buildDependencyCoverage;
    private Double dependencyGraphConsistency;
    private Double externalScannerAlignment;
    private Double securityMetadataAvailability;
    private Map<String, Integer> runtimeSupplyChainVisibility;
    private boolean buildValidationAvailable;
    private boolean declaredDependenciesAvailable;
    private boolean resolvedRuntimeAvailable;
    private boolean mavenDetected;
    private boolean ecosystemDetected;
    private String validationInterpretation;
    private boolean buildFallbackUsed;
    private String buildFallbackReason;
    private ValidationSummaryDTO summary;
    private List<DependencyConfidenceDTO> dependencies;
    private List<ValidationIssueDTO> issues;
}
