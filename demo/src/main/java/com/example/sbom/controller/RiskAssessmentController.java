package com.example.sbom.controller;

import com.example.sbom.entity.RiskAssessment;
import com.example.sbom.service.RiskAssessmentService;
import com.example.sbom.service.VulnDiffService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/projects/{projectId}/risk-assessments")
public class RiskAssessmentController {

    private static final Logger log = LoggerFactory.getLogger(RiskAssessmentController.class);

    private final RiskAssessmentService service;
    private final VulnDiffService vulnDiffService;

    public RiskAssessmentController(RiskAssessmentService service,
                                    VulnDiffService vulnDiffService) {
        this.service = service;
        this.vulnDiffService = vulnDiffService;
    }

    /**
     * List all assessments for a project, newest first. Optional {@code limit}
     * query param caps the number of rows returned.
     */
    @GetMapping
    public List<RiskAssessment> list(@PathVariable Long projectId,
                                     @RequestParam(value = "limit", defaultValue = "0") int limit) {
        return service.listByProject(projectId, limit);
    }

    /** Most recent assessment for the project, or 404 if none yet. */
    @GetMapping("/latest")
    public RiskAssessment latest(@PathVariable Long projectId) {
        return service.getLatest(projectId);
    }

    /**
     * Recompute a fresh RiskAssessment snapshot for the project
     * (using the packages/vulns already in the database) and
     * diff it against the previous snapshot. Used by the
     * project detail "Recompute" button when a project was
     * scanned before SbomExportController started auto-snapshotting
     * — running this once backfills the missing data without
     * the cost of a fresh Trivy scan.
     */
    @PostMapping("/recompute")
    public ResponseEntity<?> recompute(@PathVariable Long projectId) {
        try {
            RiskAssessment snapshot = service.snapshot(projectId, null, null);
            VulnDiffService.DiffResult diff = null;
            try {
                diff = vulnDiffService.diff(projectId, snapshot.getId());
            } catch (Exception ex) {
                log.warn("recompute: vuln diff failed for projectId={}, ignoring.", projectId, ex);
            }
            log.info("recompute: projectId={} snapshotId={} score={} grade={} diff={}",
                    projectId, snapshot.getId(), snapshot.getScore(), snapshot.getGrade(),
                    diff);
            return ResponseEntity.ok(snapshot);
        } catch (Exception ex) {
            log.error("recompute: failed for projectId={}", projectId, ex);
            return ResponseEntity.status(500).body(java.util.Map.of(
                    "error", "recompute failed",
                    "message", ex.getMessage() != null ? ex.getMessage() : ex.getClass().getSimpleName()
            ));
        }
    }
}
