package com.example.sbom.ai.dto;

import lombok.Data;
import java.time.LocalDateTime;
import java.util.List;

@Data
public class AiAnalysisResponse {
    private boolean success;
    private RepoScoreDTO scoreData;
    private List<RecommendationDTO> recommendations;
    private LocalDateTime analyzedAt;
    private String aiRawResponse; // Thêm field này

    // Constructor để set default values
    public AiAnalysisResponse() {
        this.analyzedAt = LocalDateTime.now();
        this.success = true;
    }
}