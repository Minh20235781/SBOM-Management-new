package com.example.sbom.threatintel.client;

import com.example.sbom.threatintel.dto.EpssResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import java.util.Locale;

/**
 * Experimental threat-intel client for EPSS scoring. This is isolated from
 * the existing SBOM analysis pipeline to enable future research.
 */
@Component
public class EpssApiClient {

    private static final Logger log = LoggerFactory.getLogger(EpssApiClient.class);
    private static final double DEFAULT_SCORE = 0.0;

    private final RestTemplate restTemplate;

    @Value("${threatintel.epss.base-url:https://api.first.org/data/v1/epss}")
    private String epssBaseUrl;

    public EpssApiClient(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }

    public double fetchEpssScore(String cveId) {
        if (cveId == null || cveId.isBlank()) {
            return DEFAULT_SCORE;
        }

        String normalized = cveId.trim().toUpperCase(Locale.ROOT);
        try {
            String url = UriComponentsBuilder.fromHttpUrl(epssBaseUrl)
                    .queryParam("cve", normalized)
                    .toUriString();

            EpssResponse response = restTemplate.getForObject(url, EpssResponse.class);
            if (response == null || response.getData() == null || response.getData().isEmpty()) {
                log.debug("EPSS empty response for {}", normalized);
                return DEFAULT_SCORE;
            }

            for (EpssResponse.EpssData item : response.getData()) {
                if (item != null && normalized.equalsIgnoreCase(item.getCve())) {
                    return parseScore(item.getEpss());
                }
            }

            log.debug("EPSS score missing for {}", normalized);
            return DEFAULT_SCORE;
        } catch (Exception ex) {
            log.warn("EPSS lookup failed for {}: {}", normalized, ex.getMessage());
            log.debug("EPSS error details", ex);
            return DEFAULT_SCORE;
        }
    }

    private double parseScore(String value) {
        if (value == null || value.isBlank()) {
            return DEFAULT_SCORE;
        }
        try {
            return Double.parseDouble(value.trim());
        } catch (NumberFormatException ex) {
            log.warn("Invalid EPSS score format: {}", value);
            return DEFAULT_SCORE;
        }
    }
}
