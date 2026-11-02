package com.example.sbom.ai.service.parser;

import com.example.sbom.ai.dto.RecommendationDTO;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.List;

@Component
public class RecommendationParser {

    private static final Logger log = LoggerFactory.getLogger(RecommendationParser.class);
    private final ObjectMapper mapper = new ObjectMapper();

    public List<RecommendationDTO> parseRecommendations(String aiText) {
        if (aiText == null || aiText.isBlank()) {
            log.warn("AI response is empty");
            return createFallbackRecommendation("AI response is empty");
        }

        // Clean the response
        String jsonText = cleanJsonText(aiText);

        log.info("Cleaned AI response (first 500 chars): {}",
                jsonText.substring(0, Math.min(500, jsonText.length())));

        try {
            // Parse JSON array
            JsonNode root = mapper.readTree(jsonText);

            if (root.isArray()) {
                return parseRecommendationArray(root);
            } else if (root.isObject()) {
                return parseSingleRecommendation(root);
            }

            log.warn("Failed to parse AI response as JSON array or object");
            return createFallbackRecommendation(jsonText);

        } catch (Exception e) {
            log.error("Exception parsing AI response: {}", e.getMessage(), e);

            // Try to extract any JSON-like structure
            String extractedJson = extractJsonFromText(jsonText);
            if (!extractedJson.equals(jsonText)) {
                log.info("Trying to parse extracted JSON");
                return parseRecommendations(extractedJson); // Recursive call
            }

            return createFallbackRecommendation("Parse error: " + e.getMessage() + " | Raw: " +
                    jsonText.substring(0, Math.min(300, jsonText.length())));
        }
    }

    private List<RecommendationDTO> parseRecommendationArray(JsonNode root) {
        List<RecommendationDTO> recommendations = new ArrayList<>();

        for (JsonNode node : root) {
            try {
                RecommendationDTO rec = parseSingleRecommendationNode(node);
                if (rec != null) {
                    recommendations.add(rec);
                }
            } catch (Exception e) {
                log.warn("Failed to convert recommendation node: {}", e.getMessage());
            }
        }

        if (!recommendations.isEmpty()) {
            log.info("Successfully parsed {} recommendations from AI", recommendations.size());
            return recommendations;
        }

        return createFallbackRecommendation("No valid recommendations found in array");
    }

    private List<RecommendationDTO> parseSingleRecommendation(JsonNode root) {
        try {
            RecommendationDTO rec = parseSingleRecommendationNode(root);
            List<RecommendationDTO> singleList = new ArrayList<>();
            singleList.add(rec);
            log.info("Parsed single recommendation from AI");
            return singleList;
        } catch (Exception e) {
            log.warn("Failed to parse single recommendation: {}", e.getMessage());
            return createFallbackRecommendation("Failed to parse single recommendation");
        }
    }

    private RecommendationDTO parseSingleRecommendationNode(JsonNode node) {
        RecommendationDTO rec = mapper.convertValue(node, RecommendationDTO.class);

        // Validate and set defaults
        if (rec.getPriority() <= 0) {
            rec.setPriority(1);
        }
        if (rec.getPackageName() == null || rec.getPackageName().isBlank()) {
            rec.setPackageName("Unknown Package");
        }
        if (rec.getIssue() == null || rec.getIssue().isBlank()) {
            rec.setIssue("Issue description not provided by AI");
        }
        if (rec.getSuggestion() == null || rec.getSuggestion().isBlank()) {
            rec.setSuggestion("Check for updates or alternative packages");
        }
        if (rec.getEstimatedEffort() == null || rec.getEstimatedEffort().isBlank()) {
            rec.setEstimatedEffort("MEDIUM");
        }

        return rec;
    }

    private String cleanJsonText(String text) {
        if (text == null) return "[]";

        text = text.trim();

        // Remove markdown code blocks
        if (text.startsWith("```json")) {
            text = text.substring(7).trim();
        }
        if (text.startsWith("```")) {
            text = text.substring(3).trim();
        }
        if (text.endsWith("```")) {
            text = text.substring(0, text.length() - 3).trim();
        }

        return text;
    }

    private String extractJsonFromText(String text) {
        // Try to find JSON array in the text
        int start = text.indexOf('[');
        int end = text.lastIndexOf(']');

        if (start >= 0 && end > start) {
            String extracted = text.substring(start, end + 1);
            log.info("Extracted JSON from text: {}...", extracted.substring(0, Math.min(100, extracted.length())));
            return extracted;
        }

        // Try to find JSON object
        start = text.indexOf('{');
        end = text.lastIndexOf('}');

        if (start >= 0 && end > start) {
            String extracted = text.substring(start, end + 1);
            log.info("Extracted JSON object from text");
            return "[" + extracted + "]"; // Wrap in array
        }

        return text; // Return original if no JSON found
    }

    private List<RecommendationDTO> createFallbackRecommendation(String reason) {
        RecommendationDTO fallbackRec = new RecommendationDTO();
        fallbackRec.setPriority(1);
        fallbackRec.setPackageName("Analysis System");
        fallbackRec.setIssue("Không thể parse kết quả phân tích AI");
        fallbackRec.setSuggestion("Kiểm tra kết nối AI service hoặc định dạng response");
        fallbackRec.setEstimatedEffort("LOW");
        fallbackRec.setReason(reason.length() > 500 ? reason.substring(0, 500) + "..." : reason);

        List<RecommendationDTO> fallbackList = new ArrayList<>();
        fallbackList.add(fallbackRec);
        return fallbackList;
    }
}