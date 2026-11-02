package com.example.sbom.service;

import com.example.sbom.dto.ProjectCreateRequest;
import com.example.sbom.dto.ProjectUpdateRequest;
import com.example.sbom.entity.Project;
import com.example.sbom.entity.ProjectHistory;
import com.example.sbom.repository.DependencyRepository;
import com.example.sbom.repository.PackageRepository;
import com.example.sbom.repository.ProjectHistoryRepository;
import com.example.sbom.repository.ProjectRepository;
import com.example.sbom.repository.RiskAssessmentRepository;
import com.example.sbom.repository.VulnStatusHistoryRepository;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.server.ResponseStatusException;

import java.util.List;
import java.util.Map;

/**
 * CRUD service for {@link Project} with full history tracking.
 *
 * Convention: before any mutation, we write a row to project_history with
 * a full snapshot of the previous (or new) state. That way every change is
 * auditable and we can roll back to a specific version if needed.
 */
@Service
public class ProjectService {

    private static final Logger log = LoggerFactory.getLogger(ProjectService.class);

    private final ProjectRepository projectRepository;
    private final ProjectHistoryRepository projectHistoryRepository;
    private final PackageRepository packageRepository;
    private final RiskAssessmentRepository riskAssessmentRepository;
    private final VulnStatusHistoryRepository vulnStatusHistoryRepository;
    private final DependencyRepository dependencyRepository;
    private final ObjectMapper objectMapper;

    public ProjectService(ProjectRepository projectRepository,
                          ProjectHistoryRepository projectHistoryRepository,
                          PackageRepository packageRepository,
                          RiskAssessmentRepository riskAssessmentRepository,
                          VulnStatusHistoryRepository vulnStatusHistoryRepository,
                          DependencyRepository dependencyRepository,
                          ObjectMapper objectMapper) {
        this.projectRepository = projectRepository;
        this.projectHistoryRepository = projectHistoryRepository;
        this.packageRepository = packageRepository;
        this.riskAssessmentRepository = riskAssessmentRepository;
        this.vulnStatusHistoryRepository = vulnStatusHistoryRepository;
        this.dependencyRepository = dependencyRepository;
        this.objectMapper = objectMapper;
    }

    @Transactional(readOnly = true)
    public List<Project> list() {
        return projectRepository.findAll();
    }

    @Transactional(readOnly = true)
    public long countPackages(Long projectId) {
        return packageRepository.countByProjectId(projectId);
    }

    @Transactional(readOnly = true)
    public Project getById(Long id) {
        return projectRepository.findById(id)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND,
                        "Project not found: id=" + id));
    }

    @Transactional
    public Project create(ProjectCreateRequest req) {
        String name = req.getName().trim();
        if (projectRepository.findFirstByName(name).isPresent()) {
            throw new ResponseStatusException(HttpStatus.CONFLICT,
                    "Project name already exists: " + name);
        }
        Project project = new Project();
        project.setName(name);
        project.setDescription(req.getDescription());
        project.setStatus("ACTIVE");
        project.setVersion(1);
        project = projectRepository.saveAndFlush(project);

        recordHistory(project, ProjectHistory.ChangeType.CREATED);
        log.info("ProjectService: created project id={} name='{}'", project.getId(), project.getName());
        return project;
    }

    @Transactional
    public Project update(Long id, ProjectUpdateRequest req) {
        Project project = getById(id);
        String newName = req.getName().trim();

        if (!project.getName().equals(newName)
                && projectRepository.findFirstByName(newName).isPresent()) {
            throw new ResponseStatusException(HttpStatus.CONFLICT,
                    "Project name already exists: " + newName);
        }

        project.setName(newName);
        project.setDescription(req.getDescription());
        project.setVersion(project.getVersion() + 1);
        project = projectRepository.saveAndFlush(project);

        recordHistory(project, ProjectHistory.ChangeType.UPDATED);
        log.info("ProjectService: updated project id={} new version={}", project.getId(), project.getVersion());
        return project;
    }

    /**
     * Wipe every project-scoped artifact — risk snapshots,
     * vuln status history, package links, dependency graph
     * rows — and keep the Project row itself. Intended for
     * the "Reset" flow in Settings: lets a user re-scan a
     * project from a clean slate without going through the
     * delete-then-recreate dance.
     *
     * Note: the historical {@code delete(id)} method was
     * removed because every project ended up with at least
     * one linked package, making the 409 CONFLICT guard
     * effectively dead code. To start over, call reset +
     * run a fresh Trivy scan.
     *
     * Returned counts are only useful for log lines; the
     * caller treats any non-throw outcome as success.
     */
    @Transactional
    public Map<String, Integer> reset(Long id) {
        Project project = getById(id);
        String repoName = project.getName();

        int riskDeleted = riskAssessmentRepository.deleteByProjectId(id);
        int vulnStatusDeleted = vulnStatusHistoryRepository.deleteByProjectId(id);

        // Unlink every package from this project. We keep
        // the PackageEntity rows themselves (they're the
        // historical record of what was scanned) but drop
        // the project FK and the vuln rows underneath them
        // so the next scan produces a fresh state.
        List<com.example.sbom.entity.PackageEntity> packages =
                packageRepository.findAll().stream()
                        .filter(p -> p.getProject() != null && p.getProject().getId().equals(id))
                        .toList();
        for (com.example.sbom.entity.PackageEntity pkg : packages) {
            pkg.setProject(null);
            if (pkg.getVulnerabilities() != null) {
                // Detach the vuln rows so the FK back to
                // PackageEntity is severed; we then drop them.
                pkg.getVulnerabilities().forEach(v -> v.setPkg(null));
                pkg.getVulnerabilities().clear();
            }
            packageRepository.save(pkg);
        }
        int packagesUnlinked = packages.size();

        // Drop graph edges (DependencyEntity rows) that
        // reference this repo. We rely on repo_name because
        // there is no project FK on DependencyEntity.
        int graphEdges = dependencyRepository.findByFrom_RepoName(repoName).size();
        dependencyRepository.deleteAll(dependencyRepository.findByFrom_RepoName(repoName));

        recordHistory(project, ProjectHistory.ChangeType.RESTORED);

        log.info("ProjectService: reset project id={} name='{}' — riskDeleted={} vulnStatusDeleted={} packagesUnlinked={} graphEdgesCleared={}",
                id, repoName, riskDeleted, vulnStatusDeleted, packagesUnlinked, graphEdges);

        return Map.of(
                "riskAssessmentsDeleted", riskDeleted,
                "vulnStatusDeleted", vulnStatusDeleted,
                "packagesUnlinked", packagesUnlinked,
                "graphEdgesCleared", graphEdges
        );
    }

    @Transactional(readOnly = true)
    public List<ProjectHistory> getHistory(Long projectId) {
        // Ensure the project exists so we can return 404 instead of empty list.
        getById(projectId);
        return projectHistoryRepository.findByProjectIdOrderByChangedAtDesc(projectId);
    }

    private void recordHistory(Project project, ProjectHistory.ChangeType type) {
        ProjectHistory h = new ProjectHistory();
        h.setProjectId(project.getId());
        h.setVersion(project.getVersion());
        h.setChangeType(type);
        h.setSnapshotJson(serialize(project));
        projectHistoryRepository.save(h);
    }

    private String serialize(Project project) {
        try {
            Map<String, Object> snapshot = Map.of(
                    "id", project.getId(),
                    "name", project.getName(),
                    "description", project.getDescription() == null ? "" : project.getDescription(),
                    "status", project.getStatus(),
                    "version", project.getVersion(),
                    "createdAt", project.getCreatedAt() == null ? "" : project.getCreatedAt().toString(),
                    "updatedAt", project.getUpdatedAt() == null ? "" : project.getUpdatedAt().toString()
            );
            return objectMapper.writeValueAsString(snapshot);
        } catch (JsonProcessingException e) {
            log.warn("ProjectService: failed to serialize project snapshot id={}", project.getId(), e);
            return "{}";
        }
    }
}
