package com.example.sbom.config;

import com.example.sbom.entity.Project;
import com.example.sbom.repository.PackageRepository;
import com.example.sbom.repository.ProjectRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.event.ContextRefreshedEvent;
import org.springframework.context.event.EventListener;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

/**
 * Runs after every Spring context refresh (typically on startup). Finds any
 * package with project_id = NULL and assigns it to the "Default Project".
 *
 * Rationale: the existing scan/upload code paths create PackageEntity rows
 * without setting a project, so we patch that up here to keep the data
 * consistent for the new project management UI. This is a no-op if the
 * default project does not exist (e.g. a brand-new empty database on the
 * very first run, in which case DataSeeder creates the project and also
 * handles legacy data in the same transaction).
 */
@Component
public class ProjectAssigner {

    private static final Logger log = LoggerFactory.getLogger(ProjectAssigner.class);
    private static final String DEFAULT_PROJECT_NAME = "Default Project";

    private final ProjectRepository projectRepository;
    private final PackageRepository packageRepository;

    public ProjectAssigner(ProjectRepository projectRepository,
                           PackageRepository packageRepository) {
        this.projectRepository = projectRepository;
        this.packageRepository = packageRepository;
    }

    @EventListener(ContextRefreshedEvent.class)
    @Transactional
    public void assignUnassignedPackages() {
        Project defaultProject = projectRepository
                .findFirstByName(DEFAULT_PROJECT_NAME)
                .orElse(null);

        if (defaultProject == null) {
            return;
        }

        int updated = packageRepository.assignUnassignedToProject(defaultProject);
        if (updated > 0) {
            log.info("ProjectAssigner: re-assigned {} package(s) to default project (id={}).",
                    updated, defaultProject.getId());
        }
    }
}
