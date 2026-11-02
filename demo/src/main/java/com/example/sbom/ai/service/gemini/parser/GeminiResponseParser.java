package com.example.sbom.ai.service.gemini.parser;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

@Component
public class GeminiResponseParser {

    private static final Logger log = LoggerFactory.getLogger(GeminiResponseParser.class);
    private final ObjectMapper objectMapper;

    public GeminiResponseParser(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    public String cleanAndValidateJsonResponse(String text) {
        if (text == null || text.trim().isEmpty()) {
            return "[]";
        }

        text = cleanMarkdown(text);

        try {
            JsonNode node = objectMapper.readTree(text);

            if (node.isObject()) {
                ArrayNode array = objectMapper.createArrayNode();
                array.add(node);
                text = array.toString();
            }

            return text;
        } catch (Exception e) {
            log.warn("Raw response is not valid JSON: {}", e.getMessage());
            return "[]";
        }
    }

    private String cleanMarkdown(String text) {
        text = text.trim();

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

    public boolean isResponseTruncated(String response) {
        if (response == null) return false;

        response = response.trim();

        int openBrackets = countOccurrences(response, '[');
        int closeBrackets = countOccurrences(response, ']');

        if (openBrackets != closeBrackets) {
            return true;
        }

        return !response.endsWith("]");
    }

    private int countOccurrences(String str, char ch) {
        int count = 0;
        for (int i = 0; i < str.length(); i++) {
            if (str.charAt(i) == ch) {
                count++;
            }
        }
        return count;
    }
}