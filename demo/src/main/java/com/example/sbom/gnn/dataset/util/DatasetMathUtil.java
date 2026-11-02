package com.example.sbom.gnn.dataset.util;

import com.example.sbom.entity.VulnerabilityEntity;

import java.util.Collection;
import java.util.Locale;

/**
 * Utility helpers for experimental dataset feature engineering.
 */
public final class DatasetMathUtil {

    private DatasetMathUtil() {
    }

    public static double average(double sum, int count) {
        return count > 0 ? sum / count : 0.0;
    }

    public static double clamp01(double value) {
        if (value < 0.0) {
            return 0.0;
        }
        if (value > 1.0) {
            return 1.0;
        }
        return value;
    }

    public static double vulnerabilityDensity(int vulnerabilityCount) {
        // Density proxy: more CVEs increases density but saturates to avoid extremes.
        return clamp01(vulnerabilityCount / (vulnerabilityCount + 3.0));
    }

    public static double severityWeight(Collection<VulnerabilityEntity> vulnerabilities) {
        int critical = 0;
        int high = 0;
        int medium = 0;
        int low = 0;

        if (vulnerabilities != null) {
            for (VulnerabilityEntity vulnerability : vulnerabilities) {
                if (vulnerability == null || vulnerability.getSeverity() == null) {
                    continue;
                }
                String severity = vulnerability.getSeverity().trim().toLowerCase(Locale.ROOT);
                switch (severity) {
                    case "critical" -> critical++;
                    case "high" -> high++;
                    case "medium" -> medium++;
                    case "low" -> low++;
                    default -> { }
                }
            }
        }

        int total = critical + high + medium + low;
        if (total == 0) {
            return 0.0;
        }

        double weighted = 4.0 * critical + 3.0 * high + 2.0 * medium + low;
        double normalized = weighted / (4.0 * total);
        double density = vulnerabilityDensity(total);
        return clamp01(normalized * density);
    }
}
