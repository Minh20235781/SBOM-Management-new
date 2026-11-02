package com.example.sbom.ai.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.client.RestTemplate;

@Configuration
public class AiConfig {

    private static final Logger log = LoggerFactory.getLogger(AiConfig.class);

    @Value("${ai.provider:gemini}")
    private String aiProvider;

    @Value("${ai.gemini.api-key:}")
    private String geminiApiKey;

    @Value("${ai.openai.api-key:}")
    private String openaiApiKey;

    @Bean
    public RestTemplate restTemplate() {
        return new RestTemplate();
    }

    @Bean
    public boolean isGeminiConfigured() {
        if (aiProvider.equalsIgnoreCase("gemini")) {
            if (geminiApiKey == null || geminiApiKey.isBlank()) {
                log.error("Gemini API key is not configured. Please set GEMINI_API_KEY environment variable or ai.gemini.api-key property.");
                log.error("Get free API key from: https://makersuite.google.com/app/apikey");
                return false;
            }
            log.info("Gemini AI provider configured with model");
            return true;
        }
        return false;
    }

    @Bean
    public boolean isOpenAiConfigured() {
        if (aiProvider.equalsIgnoreCase("openai")) {
            if (openaiApiKey == null || openaiApiKey.isBlank()) {
                log.error("OpenAI API key is not configured. Please set OPENAI_API_KEY environment variable.");
                return false;
            }
            log.info("OpenAI provider configured");
            return true;
        }
        return false;
    }
}