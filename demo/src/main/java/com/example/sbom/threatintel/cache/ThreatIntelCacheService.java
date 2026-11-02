package com.example.sbom.threatintel.cache;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.Locale;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;
import java.util.function.Function;

/**
 * Experimental threat-intel cache to reduce repeated EPSS lookups.
 */
@Service
public class ThreatIntelCacheService {

    private static final Logger log = LoggerFactory.getLogger(ThreatIntelCacheService.class);
    private static final double DEFAULT_SCORE = 0.0;

    private final ConcurrentMap<String, Double> epssCache = new ConcurrentHashMap<>();

    public double getOrLoadEpssScore(String cveId, Function<String, Double> loader) {
        if (cveId == null || cveId.isBlank()) {
            return DEFAULT_SCORE;
        }
        String normalized = cveId.trim().toUpperCase(Locale.ROOT);
        return epssCache.computeIfAbsent(normalized, key -> {
            log.debug("EPSS cache miss for {}", key);
            Double value = loader.apply(key);
            return value != null ? value : DEFAULT_SCORE;
        });
    }
}
