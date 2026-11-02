package com.example.sbom.ai.service.builder;

import com.example.sbom.ai.dto.AiAnalysisResponse;
import com.example.sbom.ai.dto.AnalysisFeatures;
import com.example.sbom.ai.dto.RecommendationDTO;
import com.example.sbom.ai.dto.RepoScoreDTO;
import org.springframework.stereotype.Component;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;

@Component
public class ResponseBuilder {

    public AiAnalysisResponse buildSuccessResponse(AnalysisFeatures features,
                                                   List<RecommendationDTO> recommendations,
                                                   Integer score,
                                                   Map<String, Object> breakdown,
                                                   String grade,
                                                   String gradeColor,
                                                   String aiRawResponse) {
        AiAnalysisResponse response = new AiAnalysisResponse();
        response.setSuccess(true);
        response.setScoreData(buildRepoScoreDTO(features, score, grade, gradeColor, breakdown));
        response.setRecommendations(recommendations);
        response.setAiRawResponse(aiRawResponse);
        response.setAnalyzedAt(LocalDateTime.now());
        return response;
    }

    public AiAnalysisResponse buildErrorResponse(String errorMessage) {
        AiAnalysisResponse response = new AiAnalysisResponse();
        response.setSuccess(false);
        response.setAiRawResponse("ERROR: " + errorMessage);
        return response;
    }

    public RepoScoreDTO buildRepoScoreDTO(AnalysisFeatures features, Integer score,
                                          String grade, String gradeColor,
                                          Map<String, Object> breakdown) {
        RepoScoreDTO scoreData = new RepoScoreDTO();

        scoreData.setRepoScore(score);
        scoreData.setGrade(grade);
        scoreData.setGradeColor(gradeColor);

        // Set features metrics
        scoreData.setTotalPackages(features.getTotalPackages());
        scoreData.setSecurePackages(features.getSecurePackages());
        scoreData.setVulnerablePackages(features.getVulnerablePackages());
        scoreData.setCriticalCount(features.getCriticalCount());
        scoreData.setHighCount(features.getHighCount());
        scoreData.setMediumCount(features.getMediumCount());
        scoreData.setLowCount(features.getLowCount());
        scoreData.setAverageRankScore(features.getAverageRankScore());
        scoreData.setMostRiskyPackage(features.getPackageWithMaxRank());
        scoreData.setVulnAnomaly(features.getVulnAnomaly());

        // Set breakdown
        scoreData.setScoreBreakdown(breakdown);

        return scoreData;
    }
}