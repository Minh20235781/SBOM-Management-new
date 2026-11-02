package com.example.sbom.config;

import com.example.sbom.entity.Project;
import com.example.sbom.repository.ProjectRepository;
import org.springframework.stereotype.Component;

/**
 * Tiny helper to find the Default Project without forcing every consumer
 * to know its name. Kept separate from the aspect for testability.
 */
@Component
public class ProjectLookup {

    private static final String DEFAULT_PROJECT_NAME = "Default Project";

    private final ProjectRepository projectRepository;

    public ProjectLookup(ProjectRepository projectRepository) {
        this.projectRepository = projectRepository;
    }

    public Long defaultProjectIdOrNull() {
        return projectRepository.findFirstByName(DEFAULT_PROJECT_NAME)
                .map(Project::getId)
                .orElse(null);
    }
}
