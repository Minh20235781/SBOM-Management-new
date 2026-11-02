package com.example.sbom.ai.dto;

import lombok.Data;

@Data
public class RecommendationDTO {
    private Integer priority; // 1-5
    private String packageName;
    private String currentVersion;
    private String issue;
    private String suggestion;
    private String estimatedEffort; // LOW, MEDIUM, HIGH
    private String targetVersion; // optional
    private String impactIfNotFixed;
    private String reason;
}