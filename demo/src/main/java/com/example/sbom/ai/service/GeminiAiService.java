package com.example.sbom.ai.service;

import com.example.sbom.ai.dto.AnalysisFeatures;
import com.example.sbom.ai.service.gemini.builder.PromptBuilder;
import com.example.sbom.ai.service.gemini.client.GeminiApiClient;
import com.example.sbom.ai.service.gemini.fixer.JsonFixer;
import com.example.sbom.ai.service.gemini.mock.MockResponseGenerator;
import com.example.sbom.ai.service.gemini.parser.GeminiResponseParser;
import com.example.sbom.dto.PackageDTO;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class GeminiAiService {

    private static final Logger log = LoggerFactory.getLogger(GeminiAiService.class);

    private final GeminiApiClient apiClient;
    private final PromptBuilder promptBuilder;
    private final GeminiResponseParser responseParser;
    private final JsonFixer jsonFixer;
    private final MockResponseGenerator mockGenerator;

    public GeminiAiService(GeminiApiClient apiClient,
                           PromptBuilder promptBuilder,
                           GeminiResponseParser responseParser,
                           JsonFixer jsonFixer,
                           MockResponseGenerator mockGenerator) {
        this.apiClient = apiClient;
        this.promptBuilder = promptBuilder;
        this.responseParser = responseParser;
        this.jsonFixer = jsonFixer;
        this.mockGenerator = mockGenerator;
    }

    public String analyzeRepository(AnalysisFeatures features, List<PackageDTO> packages) {
        if (!apiClient.isApiKeyConfigured()) {
            log.error("Gemini API key not configured");
            return mockGenerator.createMockRecommendations(features);
        }

        String top5 = promptBuilder.getTop5RiskyPackages(packages);
        String prompt = promptBuilder.buildSecurityAnalysisPrompt(features, top5);

        try {
            log.info("Calling Gemini API with model: {}", apiClient.getModel());
            String response = apiClient.callGeminiApi(prompt);
            log.info("Gemini response received (length: {})", response.length());

            // Clean và validate response
            String cleanedResponse = responseParser.cleanAndValidateJsonResponse(response);

            // Kiểm tra và sửa nếu bị cắt
            if (responseParser.isResponseTruncated(cleanedResponse)) {
                log.warn("Gemini response appears to be truncated");
                cleanedResponse = jsonFixer.fixTruncatedJson(cleanedResponse);
            }

            return cleanedResponse;

        } catch (Exception e) {
            log.error("Gemini API call failed: {}", e.getMessage(), e);
            return mockGenerator.createMockRecommendations(features);
        }
    }

    public boolean isAvailable() {
        return apiClient.isApiKeyConfigured();
    }
}