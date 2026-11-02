package com.example.sbom.service;

import com.example.sbom.entity.PackageEntity;
import com.example.sbom.entity.RiskAssessment;
import com.example.sbom.entity.VulnerabilityEntity;
import com.example.sbom.repository.PackageRepository;
import com.example.sbom.repository.ProjectRepository;
import com.example.sbom.repository.RiskAssessmentRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.util.List;
import java.util.Locale;

/**
 * Creates and queries {@link RiskAssessment} snapshots.
 *
 * The "compute" method aggregates over current data; it is intentionally
 * cheap (one or two queries + Java reductions) so it can be called from
 * the upload AOP aspect after each scan without measurable overhead.
 */
@Service
public class RiskAssessmentService {

    private static final Logger log = LoggerFactory.getLogger(RiskAssessmentService.class);

    private static final double BASE_SCORE = 100.0;
    // Logarithmic weights — the previous linear weights
    private static final double CRITICAL_WEIGHT = 20.0;
    private static final double HIGH_WEIGHT = 12.0;
    private static final double MEDIUM_WEIGHT = 4.0;
    private static final double LOW_WEIGHT = 0.5;
    private static final int CRITICAL_CAP = 50;
    private static final int HIGH_CAP = 100;
    private static final int MEDIUM_CAP = 200;
    private static final int LOW_CAP = 500;
    // Vuln ratio (packages with vulns / total packages)
    // caps at 30 points so a project that's 100% vulnerable
    // still loses at most 30, not 100.
    private static final double VULN_RATIO_WEIGHT = 30.0;
    private static final double RANK_PENALTY_WEIGHT = 5.0;

    private final RiskAssessmentRepository riskAssessmentRepository;
    private final PackageRepository packageRepository;
    private final ProjectRepository projectRepository;

    public RiskAssessmentService(RiskAssessmentRepository riskAssessmentRepository,
                                 PackageRepository packageRepository,
                                 ProjectRepository projectRepository) {
        this.riskAssessmentRepository = riskAssessmentRepository;
        this.packageRepository = packageRepository;
        this.projectRepository = projectRepository;
    }

    /**
     * Compute and persist a new risk assessment for the given project.
     * Optionally scoped to a single module and/or a specific SBOM file.
     */
    @Transactional
    public RiskAssessment snapshot(Long projectId, Long moduleId, Long sbomFileId) {
        if (!projectRepository.existsById(projectId)) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND,
                    "Project not found: id=" + projectId);
        }

        List<PackageEntity> packages = (moduleId != null)
                ? packageRepository.findAll().stream()
                    .filter(p -> p.getProject() != null && p.getProject().getId().equals(projectId))
                    .filter(p -> moduleId == null || isPackageInModule(p, moduleId))
                    .toList()
                : packageRepository.findAll().stream()
                    .filter(p -> p.getProject() != null && p.getProject().getId().equals(projectId))
                    .toList();

        // Module filtering by sbom_file_id is best-effort: there is no direct
        // link between Package and SbomFile yet (Phase 4 will add it). We
        // therefore just record the link to the file and report the project
        // totals, which is what the trend chart actually needs.
        int total = packages.size();
        int critical = 0, high = 0, medium = 0, low = 0;
        int totalVulns = 0;
        int packagesWithVulns = 0;
        double rankSum = 0.0;

        for (PackageEntity pkg : packages) {
            rankSum += pkg.getRankScore() == null ? 0.0 : pkg.getRankScore();
            List<VulnerabilityEntity> vulns = pkg.getVulnerabilities();
            if (vulns == null || vulns.isEmpty()) continue;
            packagesWithVulns++;
            for (VulnerabilityEntity v : vulns) {
                totalVulns++;
                String sev = v.getSeverity() == null ? "" : v.getSeverity().toUpperCase(Locale.ROOT);
                switch (sev) {
                    case "CRITICAL" -> critical++;
                    case "HIGH" -> high++;
                    case "MEDIUM" -> medium++;
                    case "LOW" -> low++;
                    default -> { /* unknown severity, do not count */ }
                }
            }
        }

        double score = computeScore(total, critical, high, medium, low,
                total == 0 ? 0.0 : rankSum / total, packagesWithVulns);
        String grade = toGrade(score);

        RiskAssessment ra = new RiskAssessment();
        ra.setProjectId(projectId);
        ra.setModuleId(moduleId);
        ra.setSbomFileId(sbomFileId);
        ra.setScore(score);
        ra.setGrade(grade);
        ra.setTotalPackages(total);
        ra.setTotalVulnerabilities(totalVulns);
        ra.setCriticalCount(critical);
        ra.setHighCount(high);
        ra.setMediumCount(medium);
        ra.setLowCount(low);
        ra.setSummaryJson(null);

        ra = riskAssessmentRepository.saveAndFlush(ra);
        log.info("RiskAssessmentService: snapshot id={} projectId={} score={} grade={} totalVulns={}",
                ra.getId(), projectId, score, grade, totalVulns);
        return ra;
    }

    @Transactional(readOnly = true)
    public List<RiskAssessment> listByProject(Long projectId, int limit) {
        if (!projectRepository.existsById(projectId)) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND,
                    "Project not found: id=" + projectId);
        }
        List<RiskAssessment> all = riskAssessmentRepository.findByProjectIdOrderByAssessedAtDesc(projectId);
        if (limit > 0 && all.size() > limit) {
            return all.subList(0, limit);
        }
        return all;
    }

    @Transactional(readOnly = true)
    public RiskAssessment getLatest(Long projectId) {
        if (!projectRepository.existsById(projectId)) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND,
                    "Project not found: id=" + projectId);
        }
        return riskAssessmentRepository.findFirstByProjectIdOrderByAssessedAtDesc(projectId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND,
                        "No risk assessment yet for project " + projectId));
    }

 /**
 * Same as {@link #getLatest} but returns {@code Optional.empty()}
 * when no scan has been recorded yet. Used by the /commits
 * endpoint which must handle "project exists, never scanned"
 * gracefully (every commit is then treated as "new").
 */
 @Transactional(readOnly = true)
 public java.util.Optional<RiskAssessment> findLatest(Long projectId) {
 if (!projectRepository.existsById(projectId)) {
 throw new ResponseStatusException(HttpStatus.NOT_FOUND,
 "Project not found: id=" + projectId);
 }
 return riskAssessmentRepository.findFirstByProjectIdOrderByAssessedAtDesc(projectId);
 }
    private double computeScore(int totalPackages, int critical, int high,
                                int medium, int low, double avgRankScore,
                                int packagesWithVulns) {
        if (totalPackages == 0) return BASE_SCORE;

        double criticalPenalty = Math.log10(1.0 + Math.min(critical, CRITICAL_CAP)) * CRITICAL_WEIGHT;
        double highPenalty = Math.log10(1.0 + Math.min(high, HIGH_CAP)) * HIGH_WEIGHT;
        double mediumPenalty = Math.log10(1.0 + Math.min(medium, MEDIUM_CAP)) * MEDIUM_WEIGHT;
        double lowPenalty = Math.log10(1.0 + Math.min(low, LOW_CAP)) * LOW_WEIGHT;

        double vulnRatio = (double) packagesWithVulns / totalPackages;
        double vulnRatioPenalty = vulnRatio * VULN_RATIO_WEIGHT;

        double rankPenalty = avgRankScore * RANK_PENALTY_WEIGHT;

        return clamp(BASE_SCORE - criticalPenalty - highPenalty - mediumPenalty
                - lowPenalty - vulnRatioPenalty - rankPenalty, 0.0, 100.0);
    }

    private String toGrade(double score) {
        if (score >= 90) return "A";
        if (score >= 80) return "B";
        if (score >= 70) return "C";
        if (score >= 60) return "D";
        return "F";
    }

    private static double clamp(double v, double min, double max) {
        return Math.max(min, Math.min(max, v));
    }

    /**
     * Best-effort module filter. Until we add Package.moduleId in Phase 4
     * we cannot strictly scope a snapshot to a single module; we treat
     * the moduleId parameter as a hint and use it for tagging only.
     */
    private boolean isPackageInModule(PackageEntity pkg, Long moduleId) {
        // Module→Package link is introduced in Phase 4. For now, no-op:
        // all packages with project_id match are included in the snapshot.
        return true;
    }
}
