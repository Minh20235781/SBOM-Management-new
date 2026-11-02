package com.example.sbom.controller;

import com.example.sbom.entity.Project;
import com.example.sbom.entity.ProjectHistory;
import com.example.sbom.entity.RiskAssessment;
import com.example.sbom.repository.DependencyRepository;
import com.example.sbom.repository.ProjectHistoryRepository;
import com.example.sbom.repository.ProjectRepository;
import com.example.sbom.service.RiskAssessmentService;
import com.example.sbom.service.VulnDiffService;
import com.example.sbom.service.persistence.SbomPersistenceService;
import com.example.sbom.service.scan.CycloneDxParseService;
import com.example.sbom.service.scan.TrivyScanService;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.io.File;

@RestController
@RequestMapping("/api/sbom")
@RequiredArgsConstructor
public class SbomExportController {

    private static final Logger log = LoggerFactory.getLogger(SbomExportController.class);

    private final TrivyScanService trivyScanService;
    private final SbomPersistenceService sbomPersistenceService;
    private final CycloneDxParseService cycloneDxParseService;
    private final DependencyRepository dependencyRepository;
    private final ProjectRepository projectRepository;
    private final ProjectHistoryRepository projectHistoryRepository;
    // Invoke RiskAssessment + VulnDiff here so the dashboard sees
    // the new snapshot immediately (AOP aspect doesn't fire on this path).
    private final RiskAssessmentService riskAssessmentService;
    private final VulnDiffService vulnDiffService;

    @PostMapping("/scan-and-save")
    public ResponseEntity<String> scanAndSave(@RequestParam String repoUrl) {
        try {
            String repoName = repoUrl.substring(repoUrl.lastIndexOf('/') + 1).replace(".git", "");

            if (!dependencyRepository.findByFrom_RepoName(repoName).isEmpty()) {
                return ResponseEntity.ok("SBOM, vulnerabilities & module rank saved successfully");
            }

            Project project = projectRepository
                    .findFirstByName(repoName)
                    .orElseGet(() -> {
                        Project p = new Project();
                        p.setName(repoName);
                        p.setDescription("Auto-created from Trivy scan of " + repoUrl);
                        p.setStatus("ACTIVE");
                        p.setVersion(1);
                        return projectRepository.saveAndFlush(p);
                    });

            ProjectHistory hist = new ProjectHistory();
            hist.setProjectId(project.getId());
            hist.setVersion(project.getVersion());
            hist.setChangeType(ProjectHistory.ChangeType.CREATED);
            hist.setSnapshotJson("{\"source\":\"trivy-scan\",\"repoUrl\":\"" + repoUrl + "\"}");
            projectHistoryRepository.save(hist);

            File sbomFile = trivyScanService.scanRepo(repoUrl);
            sbomPersistenceService.saveSbomWithVulns(sbomFile, repoName, project);
            cycloneDxParseService.parseAndRank(sbomFile);

            RiskAssessment snapshot = null;
            try {
                snapshot = riskAssessmentService.snapshot(project.getId(), null, null);
                log.info("SbomExportController: snapshot id={} projectId={} score={} grade={}",
                        snapshot.getId(), project.getId(), snapshot.getScore(), snapshot.getGrade());
            } catch (Exception ex) {
                log.warn("SbomExportController: risk snapshot failed, ignoring.", ex);
            }
            if (snapshot != null) {
                try {
                    VulnDiffService.DiffResult diff = vulnDiffService.diff(project.getId(), snapshot.getId());
                    log.info("SbomExportController: vuln diff new={} fixed={} stillOpen={} reopened={}",
                            diff.newCount(), diff.fixedCount(), diff.stillOpenCount(), diff.reopenedCount());
                } catch (Exception ex) {
                    log.warn("SbomExportController: vuln diff failed, ignoring.", ex);
                }
            }

            log.info("SbomExportController: scan complete repo={} projectId={}", repoName, project.getId());
            return ResponseEntity.ok("SBOM, vulnerabilities & module rank saved successfully (projectId=" + project.getId() + ")");
        } catch (Exception e) {
            log.error("SbomExportController.scanAndSave failed", e);
            e.printStackTrace();
            return ResponseEntity.status(500).body("Failed: " + e.getMessage());
        }
    }
}
