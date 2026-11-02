package com.example.sbom.threatintel.client;

import com.example.sbom.threatintel.dto.KevResponse;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;

import java.util.Collections;
import java.util.HashSet;
import java.util.Locale;
import java.util.Set;

/**
 * Experimental threat-intel client for CISA KEV catalog. This is isolated from
 * the existing SBOM analysis pipeline to enable future research.
 */
@Component
public class KevApiClient {

    private static final Logger log = LoggerFactory.getLogger(KevApiClient.class);
    private static final long CACHE_TTL_MS = 6 * 60 * 60 * 1000L;

    private final RestTemplate restTemplate;
    private final Object refreshLock = new Object();

    @Value("${threatintel.kev.feed-url:https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json}")
    private String kevFeedUrl;

    private volatile Set<String> cachedKevCves = Collections.emptySet();
    private volatile long lastLoadMillis = 0L;

    public KevApiClient(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }

    public boolean isKevExploited(String cveId) {
        if (cveId == null || cveId.isBlank()) {
            return false;
        }

        String normalized = cveId.trim().toUpperCase(Locale.ROOT);
        ensureLoaded();
        return cachedKevCves.contains(normalized);
    }

    private void ensureLoaded() {
        if (isCacheValid()) {
            return;
        }
        synchronized (refreshLock) {
            if (isCacheValid()) {
                return;
            }
            Set<String> loaded = loadKevCatalog();
            if (!loaded.isEmpty()) {
                cachedKevCves = loaded;
                lastLoadMillis = System.currentTimeMillis();
            }
        }
    }

    private boolean isCacheValid() {
        return cachedKevCves != null
                && !cachedKevCves.isEmpty()
                && (System.currentTimeMillis() - lastLoadMillis) < CACHE_TTL_MS;
    }

    private Set<String> loadKevCatalog() {
        try {
            KevResponse response = restTemplate.getForObject(kevFeedUrl, KevResponse.class);
            if (response == null || response.getVulnerabilities() == null) {
                log.warn("KEV response empty from {}", kevFeedUrl);
                return Collections.emptySet();
            }

            Set<String> cves = new HashSet<>();
            for (KevResponse.KevVulnerability v : response.getVulnerabilities()) {
                if (v != null && v.getCveID() != null && !v.getCveID().isBlank()) {
                    cves.add(v.getCveID().trim().toUpperCase(Locale.ROOT));
                }
            }

            log.info("KEV catalog loaded: {} CVEs", cves.size());
            return cves;
        } catch (Exception ex) {
            log.warn("KEV load failed: {}", ex.getMessage());
            log.debug("KEV error details", ex);
            return Collections.emptySet();
        }
    }
}
