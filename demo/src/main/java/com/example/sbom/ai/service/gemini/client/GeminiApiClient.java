package com.example.sbom.ai.service.gemini.client;

import com.example.sbom.ai.dto.AnalysisFeatures;
import com.example.sbom.dto.PackageDTO;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.*;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

@Component
public class GeminiApiClient {

    private static final Logger log = LoggerFactory.getLogger(GeminiApiClient.class);

    @Value("${ai.gemini.api-key:}")
    private String apiKey;

    @Value("${ai.gemini.model:gemini-1.5-flash}")
    private String model;

    @Value("${ai.gemini.temperature:0.3}")
    private Double temperature;

    @Value("${ai.gemini.max-tokens:8192}")
    private Integer maxTokens;

    private final RestTemplate restTemplate;
    private final ObjectMapper objectMapper;

    public GeminiApiClient(RestTemplate restTemplate, ObjectMapper objectMapper) {
        this.restTemplate = restTemplate;
        this.objectMapper = objectMapper;
    }

    public String callGeminiApi(String prompt) throws Exception {
        String url = String.format("https://generativelanguage.googleapis.com/v1beta/models/%s:generateContent?key=%s",
                model, apiKey);

        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);

        Map<String, Object> requestBody = buildRequestBody(prompt);

        log.debug("Gemini request to model: {}, prompt length: {}", model, prompt.length());

        HttpEntity<Map<String, Object>> request = new HttpEntity<>(requestBody, headers);

        ResponseEntity<Map> response = restTemplate.exchange(
                url,
                HttpMethod.POST,
                request,
                Map.class
        );

        if (response.getStatusCode().is2xxSuccessful()) {
            return extractTextFromResponse(response.getBody());
        } else {
            log.error("Gemini API error: {} - {}", response.getStatusCode(), response.getBody());
            throw new RuntimeException("Gemini API error: " + response.getStatusCode());
        }
    }

    private Map<String, Object> buildRequestBody(String prompt) {
        Map<String, Object> requestBody = new HashMap<>();

        // Contents
        List<Map<String, Object>> contents = new ArrayList<>();
        Map<String, Object> content = new HashMap<>();
        List<Map<String, String>> parts = new ArrayList<>();
        Map<String, String> part = new HashMap<>();
        part.put("text", prompt);
        parts.add(part);
        content.put("parts", parts);
        contents.add(content);
        requestBody.put("contents", contents);

        // Generation config
        Map<String, Object> generationConfig = new HashMap<>();
        generationConfig.put("temperature", temperature);
        generationConfig.put("maxOutputTokens", maxTokens);
        generationConfig.put("responseMimeType", "application/json");
        requestBody.put("generationConfig", generationConfig);

        return requestBody;
    }

    private String extractTextFromResponse(Map<String, Object> responseBody) throws Exception {
        JsonNode root = objectMapper.valueToTree(responseBody);

        if (root.has("error")) {
            throw new RuntimeException("Gemini API error: " + root.get("error").toString());
        }

        JsonNode candidates = root.path("candidates");
        if (!candidates.isArray() || candidates.isEmpty()) {
            throw new RuntimeException("No candidates in Gemini response");
        }

        JsonNode firstCandidate = candidates.get(0);

        if (firstCandidate.has("finishReason") &&
                "SAFETY".equals(firstCandidate.get("finishReason").asText())) {
            throw new RuntimeException("Gemini blocked the response for safety reasons");
        }

        JsonNode content = firstCandidate.path("content");
        JsonNode parts = content.path("parts");

        if (!parts.isArray() || parts.isEmpty()) {
            throw new RuntimeException("No parts in Gemini response");
        }

        return parts.get(0).path("text").asText();
    }

    public boolean isApiKeyConfigured() {
        return apiKey != null && !apiKey.isBlank();
    }

    public String getModel() {
        return model;
    }
}