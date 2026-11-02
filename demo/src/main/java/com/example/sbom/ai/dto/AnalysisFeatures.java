package com.example.sbom.ai.dto;

import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.AllArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class AnalysisFeatures {
    private String repoName;
    private Integer totalPackages;
    private Integer securePackages;
    private Integer vulnerablePackages;
    private Integer criticalCount;
    private Integer highCount;
    private Integer mediumCount;
    private Integer lowCount;
    private Double averageRankScore;
    private Double maxRankScore;
    private String packageWithMaxRank;
    private Double vulnAnomaly;
    private Double hubAnomaly;
}