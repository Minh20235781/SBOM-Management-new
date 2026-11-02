package com.example.sbom.ai.service.gemini.fixer;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

@Component
public class JsonFixer {

    private static final Logger log = LoggerFactory.getLogger(JsonFixer.class);
    private final ObjectMapper objectMapper;

    public JsonFixer(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    public String fixInvalidJson(String text) {
        text = text.trim();

        // Tìm JSON array
        int arrayStart = text.indexOf('[');
        int arrayEnd = text.lastIndexOf(']');

        if (arrayStart >= 0 && arrayEnd > arrayStart) {
            String jsonArray = text.substring(arrayStart, arrayEnd + 1);

            try {
                JsonNode node = objectMapper.readTree(jsonArray);
                return node.toString();
            } catch (Exception e) {
                return fixTruncatedJsonArray(jsonArray);
            }
        }

        // Tìm JSON object
        int objectStart = text.indexOf('{');
        int objectEnd = text.lastIndexOf('}');

        if (objectStart >= 0 && objectEnd > objectStart) {
            String jsonObject = text.substring(objectStart, objectEnd + 1);

            try {
                JsonNode node = objectMapper.readTree(jsonObject);
                ArrayNode array = objectMapper.createArrayNode();
                array.add(node);
                return array.toString();
            } catch (Exception e) {
                return "[]";
            }
        }

        return "[]";
    }

    public String fixTruncatedJson(String response) {
        log.warn("Attempting to fix truncated JSON response");

        response = response.trim();

        if (!response.endsWith("]")) {
            response += "]";
        }

        int openBraces = countOccurrences(response, '{');
        int closeBraces = countOccurrences(response, '}');

        if (openBraces > closeBraces) {
            for (int i = 0; i < (openBraces - closeBraces); i++) {
                response += "}";
            }
        }

        try {
            JsonNode node = objectMapper.readTree(response);
            return node.toString();
        } catch (Exception e) {
            log.error("Failed to fix truncated JSON: {}", e.getMessage());
            return "[]";
        }
    }

    private String fixTruncatedJsonArray(String json) {
        int openBraces = countOccurrences(json, '{');
        int closeBraces = countOccurrences(json, '}');

        if (openBraces > closeBraces) {
            for (int i = 0; i < (openBraces - closeBraces); i++) {
                json += "}";
            }
        }

        if (!json.endsWith("]")) {
            json += "]";
        }

        json = fixUnclosedStrings(json);

        return json;
    }

    private String fixUnclosedStrings(String json) {
        int quoteCount = countOccurrences(json, '"');

        if (quoteCount % 2 != 0) {
            json += "\"";
        }

        return json;
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