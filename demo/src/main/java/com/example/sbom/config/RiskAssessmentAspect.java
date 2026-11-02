package com.example.sbom.config;

import com.example.sbom.entity.RiskAssessment;
import com.example.sbom.service.RiskAssessmentService;
import com.example.sbom.service.VulnDiffService;
import org.aspectj.lang.annotation.AfterReturning;
import org.aspectj.lang.annotation.Aspect;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

/**
 * AOP aspect that automatically creates a RiskAssessment snapshot
 * after every successful SBOM upload.
 */
@Aspect
@Component
public class RiskAssessmentAspect {

    private static final Logger log = LoggerFactory.getLogger(RiskAssessmentAspect.class);

    private final RiskAssessmentService riskAssessmentService;
    private final VulnDiffService vulnDiffService;
    private final ProjectLookup projectLookup;

    public RiskAssessmentAspect(
            RiskAssessmentService riskAssessmentService,
            VulnDiffService vulnDiffService,
            ProjectLookup projectLookup) {
        this.riskAssessmentService = riskAssessmentService;
        this.vulnDiffService = vulnDiffService;
        this.projectLookup = projectLookup;
    }

    @AfterReturning(
            pointcut = "execution(* com.example.sbom.service.persistence.SbomPersistenceService.saveSbomWithVulns(..))",
            returning = "result")
    public void afterUpload(Object result) {
        Long projectId;
        RiskAssessment ra;

        try {
            projectId = projectLookup.defaultProjectIdOrNull();
            if (projectId == null) {
                log.debug("RiskAssessmentAspect: no default project found, skipping snapshot.");
                return;
            }
            ra = riskAssessmentService.snapshot(projectId, null, null);
            log.info("RiskAssessmentAspect: snapshot id={} projectId={} score={} grade={}",
                    ra.getId(), projectId, ra.getScore(), ra.getGrade());
        } catch (Exception e) {
            log.warn("RiskAssessmentAspect: failed to create snapshot, ignoring.", e);
            return;
        }

        try {
            VulnDiffService.DiffResult diff = vulnDiffService.diff(projectId, ra.getId());
            log.info("RiskAssessmentAspect: vuln diff new={} fixed={} stillOpen={} reopened={}",
                    diff.newCount(), diff.fixedCount(), diff.stillOpenCount(), diff.reopenedCount());
        } catch (Exception e) {
            log.warn("RiskAssessmentAspect: vuln diff failed, ignoring.", e);
        }
    }
}
