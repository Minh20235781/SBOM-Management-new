package com.example.sbom.ai.service.gemini.mock;

import com.example.sbom.ai.dto.AnalysisFeatures;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Component
public class MockResponseGenerator {

    private final ObjectMapper objectMapper;

    public MockResponseGenerator(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    public String createMockRecommendations(AnalysisFeatures features) {
        List<Map<String, Object>> recommendations = new ArrayList<>();

        // Recommendation 1: Critical vulnerabilities
        if (features.getCriticalCount() > 0) {
            recommendations.add(createCriticalRecommendation(features));
        }

        // Recommendation 2: High vulnerabilities
        if (features.getHighCount() > 0) {
            recommendations.add(createHighRecommendation(features));
        }

        // Recommendation 3: General security
        recommendations.add(createGeneralRecommendation());

        try {
            return objectMapper.writeValueAsString(recommendations);
        } catch (Exception e) {
            return "[]";
        }
    }

    public String createErrorResponse(String error) {
        Map<String, Object> errorRec = new HashMap<>();
        errorRec.put("priority", 1);
        errorRec.put("packageName", "AI Service Error");
        errorRec.put("issue", error);
        errorRec.put("suggestion", "Check AI service configuration");
        errorRec.put("estimatedEffort", "LOW");

        try {
            return objectMapper.writeValueAsString(List.of(errorRec));
        } catch (Exception e) {
            return "[{\"priority\":1,\"packageName\":\"System Error\",\"issue\":\"Failed to generate recommendations\"}]";
        }
    }

    private Map<String, Object> createCriticalRecommendation(AnalysisFeatures features) {
        Map<String, Object> rec = new HashMap<>();
        rec.put("priority", 1);
        rec.put("packageName", "Spring Framework components");
        rec.put("currentVersion", "6.2.11");
        rec.put("targetVersion", "6.3.0");
        rec.put("issue", features.getCriticalCount() + " CRITICAL vulnerabilities detected");
        rec.put("suggestion", "Upgrade Spring Framework immediately");
        rec.put("estimatedEffort", "MEDIUM");
        rec.put("impactIfNotFixed", "Remote code execution risk");
        rec.put("reason", "Critical vulnerabilities require immediate attention");
        return rec;
    }

    private Map<String, Object> createHighRecommendation(AnalysisFeatures features) {
        Map<String, Object> rec = new HashMap<>();
        rec.put("priority", 2);
        rec.put("packageName", "Multiple high-risk packages");
        rec.put("currentVersion", "Various");
        rec.put("targetVersion", "Latest secure versions");
        rec.put("issue", features.getHighCount() + " HIGH vulnerabilities detected");
        rec.put("suggestion", "Review and update vulnerable dependencies");
        rec.put("estimatedEffort", "HIGH");
        rec.put("impactIfNotFixed", "Data breach and system compromise");
        rec.put("reason", "High severity vulnerabilities need prompt remediation");
        return rec;
    }

    private Map<String, Object> createGeneralRecommendation() {
        Map<String, Object> rec = new HashMap<>();
        rec.put("priority", 3);
        rec.put("packageName", "SBOM completeness");
        rec.put("currentVersion", "N/A");
        rec.put("targetVersion", "N/A");
        rec.put("issue", "Incomplete dependency tracking");
        rec.put("suggestion", "Improve SBOM generation process");
        rec.put("estimatedEffort", "LOW");
        rec.put("impactIfNotFixed", "Hidden vulnerabilities");
        rec.put("reason", "Complete SBOM is essential for security");
        return rec;
    }
}