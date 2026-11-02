package com.example.sbom.ai.service.calculator;

import com.example.sbom.ai.dto.AnalysisFeatures;
import com.example.sbom.dto.PackageDTO;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import java.util.List;

@Component
public class FeaturesCalculator {

    private static final Logger log = LoggerFactory.getLogger(FeaturesCalculator.class);

    public AnalysisFeatures calculateFeatures(List<PackageDTO> packages) {
        List<PackageDTO> latestPackages = normalizeLatestPackages(packages);
        AnalysisFeatures features = AnalysisFeatures.builder()
            .totalPackages(latestPackages.size())
                .build();

        if (latestPackages.isEmpty()) {
            return setDefaultFeatures(features);
        }

        // Get repo name from first package
        String repoName = extractRepoName(latestPackages);
        features.setRepoName(repoName);

        // Calculate all statistics
        CalculationResult result = calculateStatistics(latestPackages);

        // Set features
        features.setAverageRankScore(result.averageRankScore);
        features.setMaxRankScore(result.maxRankScore);
        features.setVulnAnomaly(result.maxVulnAnomaly);
        features.setSecurePackages(result.secureCount);
        features.setVulnerablePackages(result.vulnerableCount);
        features.setCriticalCount(result.criticalCount);
        features.setHighCount(result.highCount);
        features.setMediumCount(result.mediumCount);
        features.setLowCount(result.lowCount);
        features.setPackageWithMaxRank(result.riskiestPackage);
        features.setHubAnomaly(0.0); // Not available in export

        log.info("Calculated features - Total: {}, Vulnerable: {}, Critical: {}, High: {}, Medium: {}, Low: {}",
            latestPackages.size(), result.vulnerableCount, result.criticalCount,
                result.highCount, result.mediumCount, result.lowCount);

        return features;
    }

    private String extractRepoName(List<PackageDTO> packages) {
        return packages.stream()
                .filter(p -> p.getRepoName() != null && !p.getRepoName().isEmpty())
                .findFirst()
                .map(PackageDTO::getRepoName)
                .orElse(null);
    }

    private List<PackageDTO> normalizeLatestPackages(List<PackageDTO> packages) {
        if (packages == null || packages.isEmpty()) {
            return new ArrayList<>();
        }

        Map<String, PackageDTO> latestByName = new HashMap<>();
        for (PackageDTO pkg : packages) {
            if (pkg == null || pkg.getName() == null || pkg.getName().isBlank()) {
                continue;
            }
            PackageDTO existing = latestByName.get(pkg.getName());
            if (existing == null || compareVersions(pkg.getVersion(), existing.getVersion()) > 0) {
                latestByName.put(pkg.getName(), pkg);
            }
        }

        return new ArrayList<>(latestByName.values());
    }

    private int compareVersions(String v1, String v2) {
        if (v1 == null && v2 == null) return 0;
        if (v1 == null) return -1;
        if (v2 == null) return 1;

        String[] a = v1.split("\\.");
        String[] b = v2.split("\\.");
        int len = Math.max(a.length, b.length);
        for (int i = 0; i < len; i++) {
            int ai = i < a.length ? parseLeadingInt(a[i]) : 0;
            int bi = i < b.length ? parseLeadingInt(b[i]) : 0;
            if (ai != bi) return Integer.compare(ai, bi);
        }
        return v1.compareTo(v2);
    }

    private int parseLeadingInt(String s) {
        if (s == null) return 0;
        String num = s.replaceAll("\\D", "");
        if (num.isEmpty()) return 0;
        try {
            return Integer.parseInt(num);
        } catch (NumberFormatException ex) {
            return 0;
        }
    }

    private CalculationResult calculateStatistics(List<PackageDTO> packages) {
        CalculationResult result = new CalculationResult();

        for (PackageDTO pkg : packages) {
            // Tính vulnAnomaly trước
            double vulnAnomaly = calculateVulnAnomaly(pkg);
            pkg.setVulnAnomaly(vulnAnomaly);

            // Rank stats
            Double rank = pkg.getRankScore() != null ? pkg.getRankScore() : 0.0;
            result.sumRank += rank;
            if (rank > result.maxRankScore) {
                result.maxRankScore = rank;
                result.riskiestPackage = pkg.getName() +
                        (pkg.getVersion() != null ? ":" + pkg.getVersion() : "");
            }

            // Vuln anomaly
            result.maxVulnAnomaly = Math.max(result.maxVulnAnomaly, vulnAnomaly);

            // Vulnerability classification
            if (isVulnerable(pkg)) {
                result.vulnerableCount++;
                countSeverity(pkg, result);
            } else {
                result.secureCount++;
            }
        }

        result.averageRankScore = packages.isEmpty() ? 0.0 : result.sumRank / packages.size();
        return result;
    }

    private double calculateVulnAnomaly(PackageDTO pkg) {
        boolean hasVuln = isVulnerable(pkg);
        if (!hasVuln) return 0.0;

        double anomaly = 0.3;

        // Thêm weight theo severity
        if (pkg.getSeverity() != null) {
            switch (pkg.getSeverity().toLowerCase()) {
                case "critical": anomaly += 0.5; break;
                case "high": anomaly += 0.4; break;
                case "medium": anomaly += 0.3; break;
                case "low": anomaly += 0.2; break;
                default: anomaly += 0.1; break;
            }
        }

        // Thêm weight theo CVSS
        if (pkg.getCvss() != null && pkg.getCvss() > 0) {
            anomaly += (pkg.getCvss() / 10.0 * 0.2);
        }

        // Thêm weight theo rank score
        if (pkg.getRankScore() != null) {
            anomaly += (pkg.getRankScore() * 0.1);
        }

        return Math.min(anomaly, 1.0);
    }

    private boolean isVulnerable(PackageDTO pkg) {
        // Check vulnerabilities field
        if (pkg.getVulnerabilities() != null) {
            String vulns = pkg.getVulnerabilities();
            if (!"Secure".equalsIgnoreCase(vulns) &&
                    !"None".equalsIgnoreCase(vulns) &&
                    (vulns.contains("CVE") || vulns.contains("GHSA"))) {
                return true;
            }
        }

        // Check severity field
        if (pkg.getSeverity() != null) {
            String severity = pkg.getSeverity().toLowerCase();
            return !"secure".equals(severity) &&
                    !"none".equals(severity) &&
                    (severity.equals("critical") || severity.equals("high") ||
                            severity.equals("medium") || severity.equals("low"));
        }

        return false;
    }

    private void countSeverity(PackageDTO pkg, CalculationResult result) {
        if (pkg.getSeverity() != null) {
            String severity = pkg.getSeverity().toLowerCase();
            switch (severity) {
                case "critical": result.criticalCount++; break;
                case "high": result.highCount++; break;
                case "medium": result.mediumCount++; break;
                case "low": result.lowCount++; break;
                default: if (!"secure".equals(severity)) result.mediumCount++; break;
            }
        }
    }

    private AnalysisFeatures setDefaultFeatures(AnalysisFeatures features) {
        features.setAverageRankScore(0.0);
        features.setMaxRankScore(0.0);
        features.setVulnAnomaly(0.0);
        features.setSecurePackages(0);
        features.setVulnerablePackages(0);
        features.setCriticalCount(0);
        features.setHighCount(0);
        features.setMediumCount(0);
        features.setLowCount(0);
        features.setPackageWithMaxRank(null);
        features.setHubAnomaly(0.0);
        return features;
    }

    // Helper class to hold calculation results
    private static class CalculationResult {
        double sumRank = 0.0;
        double maxRankScore = 0.0;
        double maxVulnAnomaly = 0.0;
        double averageRankScore = 0.0;
        int secureCount = 0;
        int vulnerableCount = 0;
        int criticalCount = 0;
        int highCount = 0;
        int mediumCount = 0;
        int lowCount = 0;
        String riskiestPackage = null;
    }
}