package com.example.sbom.config;

import com.example.sbom.entity.Project;
import com.example.sbom.repository.PackageRepository;
import com.example.sbom.repository.ProjectRepository;
import jakarta.persistence.EntityManager;
import jakarta.persistence.PersistenceContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

/**
 * On startup, ensures a "Default Project" exists and assigns all legacy
 * packages (project_id IS NULL) to it. This makes existing data discoverable
 * through the new project management UI without losing information.
 */
@Component
@Order(1)
public class DataSeeder implements ApplicationRunner {

    private static final Logger log = LoggerFactory.getLogger(DataSeeder.class);
    private static final String DEFAULT_PROJECT_NAME = "Default Project";
    private static final String DEFAULT_PROJECT_DESCRIPTION =
            "Auto-created project that contains legacy data uploaded before project management was introduced.";

    private final ProjectRepository projectRepository;
    private final PackageRepository packageRepository;

    @PersistenceContext
    private EntityManager entityManager;

    public DataSeeder(ProjectRepository projectRepository, PackageRepository packageRepository) {
        this.projectRepository = projectRepository;
        this.packageRepository = packageRepository;
    }

    @Override
    @Transactional
    public void run(ApplicationArguments args) {
        long projectCount = projectRepository.count();
        if (projectCount > 0) {
            log.info("DataSeeder skipped: {} project(s) already exist.", projectCount);
            return;
        }

        Project defaultProject = new Project();
        defaultProject.setName(DEFAULT_PROJECT_NAME);
        defaultProject.setDescription(DEFAULT_PROJECT_DESCRIPTION);
        defaultProject.setStatus("ACTIVE");
        defaultProject.setVersion(1);
        defaultProject = projectRepository.saveAndFlush(defaultProject);
        log.info("DataSeeder: created default project id={} name='{}'",
                defaultProject.getId(), defaultProject.getName());

        // Reassign legacy packages (project_id is null) to the default project.
        // Use a bulk JPQL update so we don't have to load every PackageEntity.
        int updated = entityManager.createQuery(
                        "UPDATE PackageEntity p SET p.project = :project WHERE p.project IS NULL")
                .setParameter("project", defaultProject)
                .executeUpdate();

        if (updated > 0) {
            log.info("DataSeeder: assigned {} legacy package(s) to default project.", updated);
        } else {
            log.info("DataSeeder: no legacy packages needed reassignment.");
        }

        // Sanity check: print final counts so it's easy to verify in the log.
        long totalPackages = packageRepository.count();
        long unassigned = entityManager.createQuery(
                        "SELECT COUNT(p) FROM PackageEntity p WHERE p.project IS NULL", Long.class)
                .getSingleResult();
        log.info("DataSeeder summary: projects={}, totalPackages={}, unassignedPackages={}",
                projectRepository.count(), totalPackages, unassigned);
    }
}
