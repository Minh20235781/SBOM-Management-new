package com.example.sbom.ai.ml.service;

import com.example.sbom.entity.PackageEntity;
import com.example.sbom.entity.VulnerabilityEntity;
import org.springframework.stereotype.Service;

import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Optional;

@Service
public class FeatureExtractionService {

    public List<Double> extractFeatures(PackageEntity pkg) {
        List<VulnerabilityEntity> vulns = Optional.ofNullable(pkg.getVulnerabilities())
                .orElse(Collections.emptyList());

        int totalVulnerabilities = vulns.size();
        int criticalCount = 0;
        int highCount = 0;
        int mediumCount = 0;
        int lowCount = 0;

        double maxCvss = 0.0;
        double sumCvss = 0.0;

        for (VulnerabilityEntity vuln : vulns) {
            String severity = Optional.ofNullable(vuln.getSeverity())
                    .orElse("")
                    .trim()
                    .toUpperCase(Locale.ROOT);

            switch (severity) {
                case "CRITICAL" -> criticalCount++;
                case "HIGH" -> highCount++;
                case "MEDIUM" -> mediumCount++;
                case "LOW" -> lowCount++;
                default -> { }
            }

            double cvss = Optional.ofNullable(vuln.getCvssScore()).orElse(0.0);
            maxCvss = Math.max(maxCvss, cvss);
            sumCvss += cvss;
        }

        double rankScore = Optional.ofNullable(pkg.getRankScore()).orElse(0.0);
        double exposureRisk = rankScore * maxCvss;
        double severityWeight = 4.0 * criticalCount + 3.0 * highCount + 2.0 * mediumCount + lowCount;
        double vulnDensity = sumCvss / (totalVulnerabilities + 1.0);
        double criticalRatio = criticalCount / (totalVulnerabilities + 1.0);

        return List.of(
                rankScore,
                (double) totalVulnerabilities,
                sumCvss,
                exposureRisk,
                severityWeight,
                vulnDensity,
                criticalRatio
        );
    }
}
