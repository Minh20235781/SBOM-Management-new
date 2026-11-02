package com.example.sbom.config;

import com.example.sbom.repository.VulnerabilityRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.event.ContextRefreshedEvent;
import org.springframework.context.event.EventListener;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

/**
 * Phase 4: ensures every {@code VulnerabilityEntity} has a non-null
 * {@code projectId} by copying the value from the parent package's project.
 *
 * Runs on every Spring context refresh but is a no-op once legacy rows
 * have been backfilled. We use a bulk JPQL update so we don't have to load
 * every row into memory.
 *
 * Order is set to 2 so it runs after {@link ProjectAssigner} (which
 * ensures packages themselves have a project). Without that order the
 * sub-select on {@code p.project.id} could come back null for packages
 * that haven't been migrated yet.
 */
@Component
@Order(2)
public class VulnProjectAssigner {

 private static final Logger log = LoggerFactory.getLogger(VulnProjectAssigner.class);

 private final VulnerabilityRepository vulnerabilityRepository;

 public VulnProjectAssigner(VulnerabilityRepository vulnerabilityRepository) {
 this.vulnerabilityRepository = vulnerabilityRepository;
 }

 @EventListener(ContextRefreshedEvent.class)
 @Transactional
 public void assignUnassignedVulnerabilities() {
 int updated = vulnerabilityRepository.assignUnassignedToProjects();
 if (updated > 0) {
 log.info("VulnProjectAssigner: assigned {} vulnerability row(s) to a project.", updated);
 }
 }
}
