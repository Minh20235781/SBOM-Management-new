package com.example.sbom.ai.service;

import com.example.sbom.ai.dto.AiAnalysisResponse;
import com.example.sbom.ai.dto.AnalysisFeatures;
import com.example.sbom.ai.dto.RecommendationDTO;
import com.example.sbom.ai.service.builder.ResponseBuilder;
import com.example.sbom.ai.service.parser.PackageParser;
import com.example.sbom.ai.service.parser.RecommendationParser;
import com.example.sbom.dto.PackageDTO;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.util.List;
import java.util.Map;

@Service
public class AiAnalysisService {

    private static final Logger log = LoggerFactory.getLogger(AiAnalysisService.class);

    private final FileUploadService fileUploadService;
    private final RepoScoringService repoScoringService;
    private final GeminiAiService geminiAiService;
    private final ResponseBuilder responseBuilder;
    private final PackageParser packageParser;
    private final RecommendationParser recommendationParser;

    public AiAnalysisService(FileUploadService fileUploadService,
                             RepoScoringService repoScoringService,
                             GeminiAiService geminiAiService,
                             ResponseBuilder responseBuilder,
                             PackageParser packageParser,
                             RecommendationParser recommendationParser) {
        this.fileUploadService = fileUploadService;
        this.repoScoringService = repoScoringService;
        this.geminiAiService = geminiAiService;
        this.responseBuilder = responseBuilder;
        this.packageParser = packageParser;
        this.recommendationParser = recommendationParser;
    }

    public AiAnalysisResponse analyzeUploadedJson(MultipartFile file) {
        try {
            // 1. Process file to get features
            AnalysisFeatures features = fileUploadService.processUploadedFile(file);

            // 2. Re-parse packages for AI context
            List<PackageDTO> packages = packageParser.parsePackagesFromFile(file);

            // 3. Calculate score and get breakdown
            Integer score = repoScoringService.calculateScore(features);
            Map<String, Object> breakdown = repoScoringService.getScoreBreakdown(features);
            String grade = repoScoringService.getGrade(score);
            String gradeColor = repoScoringService.getGradeColor(grade);

            // 4. Get AI analysis từ Gemini
            String aiText = geminiAiService.analyzeRepository(features, packages);
            List<RecommendationDTO> recommendations = recommendationParser.parseRecommendations(aiText);

            // 5. Build and return response
            return responseBuilder.buildSuccessResponse(
                    features, recommendations, score, breakdown, grade, gradeColor, aiText
            );

        } catch (Exception e) {
            log.error("Error during AI analysis: {}", e.getMessage(), e);
            return responseBuilder.buildErrorResponse(e.getMessage());
        }
    }

    public String test() {
        return "AiAnalysisService is working with Gemini";
    }
}