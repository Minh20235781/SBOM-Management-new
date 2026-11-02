package com.example.sbom.threatintel.service;

import com.example.sbom.threatintel.cache.ThreatIntelCacheService;
import com.example.sbom.threatintel.client.EpssApiClient;
import com.example.sbom.threatintel.client.KevApiClient;
import com.example.sbom.threatintel.dto.ThreatIntelDTO;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Experimental aggregation layer for threat-intel features, kept isolated
 * from existing SBOM analysis flows for future ML research.
 */
@Service
public class ThreatIntelAggregationService {

    private static final Logger log = LoggerFactory.getLogger(ThreatIntelAggregationService.class);

    private final EpssApiClient epssApiClient;
    private final KevApiClient kevApiClient;
    private final ThreatIntelCacheService cacheService;

    public ThreatIntelAggregationService(EpssApiClient epssApiClient,
                                         KevApiClient kevApiClient,
                                         ThreatIntelCacheService cacheService) {
        this.epssApiClient = epssApiClient;
        this.kevApiClient = kevApiClient;
        this.cacheService = cacheService;
    }

    public List<ThreatIntelDTO> aggregateThreatIntel(List<String> cveIds) {
        if (cveIds == null || cveIds.isEmpty()) {
            log.debug("Threat intel aggregation skipped: empty CVE list");
            return Collections.emptyList();
        }

        List<ThreatIntelDTO> results = new ArrayList<>(cveIds.size());
        for (String cveId : cveIds) {
            double epssScore = cacheService.getOrLoadEpssScore(cveId, epssApiClient::fetchEpssScore);
            boolean kevExploited = kevApiClient.isKevExploited(cveId);

            ThreatIntelDTO dto = new ThreatIntelDTO();
            dto.setCveId(cveId);
            dto.setEpssScore(epssScore);
            dto.setKevExploited(kevExploited);
            results.add(dto);
        }

        log.info("Threat intel aggregation complete: {} CVEs", results.size());
        return results;
    }
}
