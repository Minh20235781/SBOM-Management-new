package com.example.sbom.gnn.dataset.service;

import com.example.sbom.entity.PackageEntity;
import com.example.sbom.entity.VulnerabilityEntity;
import com.example.sbom.gnn.dataset.dto.DatasetFeatureResultDTO;
import com.example.sbom.gnn.dataset.dto.DatasetNodeFeatureDTO;
import com.example.sbom.gnn.dataset.util.DatasetMathUtil;
import com.example.sbom.threatintel.dto.ThreatIntelDTO;
import com.example.sbom.threatintel.service.ThreatIntelAggregationService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/** Feature engineering for the experimental GNN dataset. */
@Service
public class DatasetFeatureEngineeringService {

    private static final Logger log = LoggerFactory.getLogger(DatasetFeatureEngineeringService.class);

    private final ThreatIntelAggregationService threatIntelAggregationService;

    public DatasetFeatureEngineeringService(ThreatIntelAggregationService threatIntelAggregationService) {
        this.threatIntelAggregationService = threatIntelAggregationService;
    }

    public DatasetNodeFeatureDTO buildFeatures(PackageEntity pkg, double moduleRank) {
        return buildFeaturesWithStats(pkg, moduleRank).getNode();
    }

    public DatasetFeatureResultDTO buildFeaturesWithStats(PackageEntity pkg, double moduleRank) {
        if (pkg == null) {
            throw new IllegalArgumentException("package is required");
        }

        List<VulnerabilityEntity> vulnerabilities = pkg.getVulnerabilities() != null
                ? pkg.getVulnerabilities()
                : Collections.emptyList();

        int vulnerabilityCount = vulnerabilities.size();

        double maxCvss = 0.0;
        double sumCvss = 0.0;
        int cvssCount = 0;

        List<String> cveIds = new ArrayList<>();
        for (VulnerabilityEntity vulnerability : vulnerabilities) {
            if (vulnerability == null) {
                continue;
            }
            if (vulnerability.getVulnId() != null && !vulnerability.getVulnId().isBlank()) {
                cveIds.add(vulnerability.getVulnId());
            }
            if (vulnerability.getCvssScore() != null) {
                double score = vulnerability.getCvssScore();
                maxCvss = Math.max(maxCvss, score);
                sumCvss += score;
                cvssCount++;
            }
        }

        List<ThreatIntelDTO> intel = threatIntelAggregationService.aggregateThreatIntel(cveIds);
        double maxEpss = 0.0;
        double sumEpss = 0.0;
        int epssCount = 0;
        int kevCount = 0;
        int epssCovered = 0;

        if (!cveIds.isEmpty() && (intel == null || intel.isEmpty())) {
            log.warn("Threat-intel enrichment returned empty for package: {}", pkg.getName());
        }

        for (ThreatIntelDTO dto : intel) {
            if (dto == null) {
                continue;
            }
            double epss = dto.getEpssScore();
            maxEpss = Math.max(maxEpss, epss);
            sumEpss += epss;
            epssCount++;
            if (epss > 0.0) {
                epssCovered++;
            }
            if (dto.isKevExploited()) {
                kevCount++;
            }
        }

        DatasetNodeFeatureDTO node = new DatasetNodeFeatureDTO();
        node.setPackageName(pkg.getName());
        node.setModuleRank(moduleRank);
        node.setMaxCvss(maxCvss);
        node.setAvgCvss(DatasetMathUtil.average(sumCvss, cvssCount));
        node.setMaxEpss(maxEpss);
        node.setAvgEpss(DatasetMathUtil.average(sumEpss, epssCount));
        node.setKevCount(kevCount);
        node.setVulnerabilityCount(vulnerabilityCount);
        node.setSeverityWeight(DatasetMathUtil.severityWeight(vulnerabilities));

        DatasetFeatureResultDTO result = new DatasetFeatureResultDTO();
        result.setNode(node);
        result.setVulnerabilityCount(vulnerabilityCount);
        result.setKevCount(kevCount);
        result.setEpssCoveredCount(epssCovered);

        log.debug("Dataset features built: package={}, vulns={}, kevCount={}",
            node.getPackageName(), vulnerabilityCount, kevCount);
        return result;
    }
}
