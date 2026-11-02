package com.example.sbom.ai.service;

import java.util.LinkedHashMap;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import com.example.sbom.ai.dto.AnalysisFeatures;

/** Security score calculation service. */
@Service
public class RepoScoringService {

    private static final Logger log = LoggerFactory.getLogger(RepoScoringService.class);

    // Vulnerability Penalty Coefficients
    private static final double CRITICAL_PENALTY = 15.0;
    private static final double HIGH_PENALTY = 10.0;
    private static final double MEDIUM_PENALTY = 3.0;
    private static final double LOW_PENALTY = 0.5;

    private static final double VULN_RATIO_MULTIPLIER = 15.0;
    private static final double RANK_PENALTY_MULTIPLIER = 10.0;
    private static final double BASE_SCORE = 100.0;

    /**
     * Calculate Security Score v2.0.
     * Formula: score = 100 - vulnPenalty - vulnRatioPenalty - rankPenalty
     */
    public Integer calculateScore(AnalysisFeatures f) {
        if (f == null) return 0;

        double vulnPenalty = 0.0;
        vulnPenalty += f.getCriticalCount() * CRITICAL_PENALTY;
        vulnPenalty += f.getHighCount() * HIGH_PENALTY;
        vulnPenalty += f.getMediumCount() * MEDIUM_PENALTY;
        vulnPenalty += f.getLowCount() * LOW_PENALTY;

        double totalPackages = Math.max(1, f.getTotalPackages());
        double vulnerableRatio = (double) f.getVulnerablePackages() / totalPackages;
        double vulnRatioPenalty = vulnerableRatio * VULN_RATIO_MULTIPLIER;

        double rankPenalty = f.getAverageRankScore() * RANK_PENALTY_MULTIPLIER;

        double score = BASE_SCORE - vulnPenalty - vulnRatioPenalty - rankPenalty;
        int finalScore = (int) Math.round(Math.max(0, Math.min(100, score)));

        log.info("Security Score v2.0 - Total: {}, Vulnerable: {}, Critical: {}, High: {}, Medium: {}, Low: {}, " +
                        "VulnPenalty: {}, VulnRatioPenalty: {} (ratio={}), RankPenalty: {}, FinalScore: {}",
                totalPackages, f.getVulnerablePackages(),
                f.getCriticalCount(), f.getHighCount(), f.getMediumCount(), f.getLowCount(),
                vulnPenalty, vulnRatioPenalty, String.format("%.4f", vulnerableRatio),
                rankPenalty, finalScore);

        return finalScore;
    }

    public String getGrade(Integer score) {
        if (score == null) return "F";
        int s = Math.max(0, Math.min(100, score));
        if (s >= 90) return "A";
        if (s >= 80) return "B";
        if (s >= 70) return "C";
        if (s >= 60) return "D";
        return "F";
    }

    public String getGradeColor(String grade) {
        if (grade == null) return "#FF0000";

        return switch (grade.toUpperCase()) {
            case "A" -> "#4CAF50";
            case "B" -> "#8BC34A";
            case "C" -> "#FFC107";
            case "D" -> "#FF9800";
            case "F" -> "#F44336";
            default -> "#9E9E9E";
        };
    }

    public String getGradeColor(Integer score) {
        String grade = getGrade(score);
        return getGradeColor(grade);
    }

    /** Returns a breakdown map describing how the score was computed. */
    public Map<String, Object> getScoreBreakdown(AnalysisFeatures f) {
        Map<String, Object> out = new LinkedHashMap<>();
        if (f == null) return out;

        double criticalPenalty = f.getCriticalCount() * CRITICAL_PENALTY;
        double highPenalty = f.getHighCount() * HIGH_PENALTY;
        double mediumPenalty = f.getMediumCount() * MEDIUM_PENALTY;
        double lowPenalty = f.getLowCount() * LOW_PENALTY;

        double totalPackages = Math.max(1, f.getTotalPackages());
        double vulnerableRatio = (double) f.getVulnerablePackages() / totalPackages;
        double vulnRatioPenalty = vulnerableRatio * VULN_RATIO_MULTIPLIER;

        double totalVulnPenalty = criticalPenalty + highPenalty + mediumPenalty + lowPenalty;
        double rankPenalty = f.getAverageRankScore() * RANK_PENALTY_MULTIPLIER;

        double raw = BASE_SCORE - totalVulnPenalty - vulnRatioPenalty - rankPenalty;
        int finalScore = (int) Math.round(Math.max(0, Math.min(100, raw)));

        out.put("version", "2.0");
        out.put("baseScore", BASE_SCORE);
        out.put("criticalPenalty", criticalPenalty);
        out.put("highPenalty", highPenalty);
        out.put("mediumPenalty", mediumPenalty);
        out.put("lowPenalty", lowPenalty);
        out.put("totalVulnPenalty", totalVulnPenalty);
        out.put("vulnerableRatio", vulnerableRatio);
        out.put("vulnRatioPenalty", vulnRatioPenalty);
        out.put("averageRankScore", f.getAverageRankScore());
        out.put("rankPenalty", rankPenalty);
        out.put("rawScore", raw);
        out.put("finalScore", finalScore);
        out.put("grade", getGrade(finalScore));
        out.put("gradeColor", getGradeColor(finalScore));
        out.put("totalPackages", f.getTotalPackages());
        out.put("vulnerablePackages", f.getVulnerablePackages());
        out.put("securePackages", f.getSecurePackages());
        out.put("criticalCount", f.getCriticalCount());
        out.put("highCount", f.getHighCount());
        out.put("mediumCount", f.getMediumCount());
        out.put("lowCount", f.getLowCount());

        log.debug("Score Breakdown v2.0 - VulnPenalty: {}, VulnRatioPenalty: {}, RankPenalty: {}, Raw: {}, Final: {}",
                totalVulnPenalty, vulnRatioPenalty, rankPenalty, raw, finalScore);

        return out;
    }
}
