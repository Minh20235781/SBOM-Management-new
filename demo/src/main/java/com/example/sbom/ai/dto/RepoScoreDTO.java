package com.example.sbom.ai.dto;

import lombok.Data;

import java.util.Map;

@Data
public class RepoScoreDTO {
    private Integer repoScore; // 0-100
    private String grade; // A,B,C,D,F
    private String gradeColor; // CSS color cho FE
    
    // Metrics hiển thị
    private Integer totalPackages;
    private Integer securePackages;
    private Integer vulnerablePackages;
    private Integer criticalCount;
    private Integer highCount;
    private Integer mediumCount;
    private Integer lowCount;
    
    // Additional metrics
    private Double averageRankScore;
    private String mostRiskyPackage;
    private Double vulnAnomaly;

    private Map<String, Object> scoreBreakdown;
}