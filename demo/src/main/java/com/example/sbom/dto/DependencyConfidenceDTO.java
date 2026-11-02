package com.example.sbom.dto;

import lombok.Data;

import java.util.List;

@Data
public class DependencyConfidenceDTO {
    private String packageName;
    private String version;
    private List<String> sources;
    private String ecosystem;
    private boolean ecosystemDetected;
    private boolean directDependency;
    private boolean transitiveDependency;
    private boolean detectedByScanner;
    private boolean resolvedByBuild;
    private boolean graphPresent;
    private List<String> provenanceCategories;
    private boolean inGraph;
    private boolean inScanner;
    private boolean inDeclared;
    private boolean inResolved;
    private String confidence;
    private double weightedScore;
}
