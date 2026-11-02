package com.example.sbom.service;

import com.example.sbom.dto.ModuleRequest;
import com.example.sbom.entity.Module;
import com.example.sbom.entity.ModuleHistory;
import com.example.sbom.entity.RepoConfig;
import com.example.sbom.repository.ModuleHistoryRepository;
import com.example.sbom.repository.ModuleRepository;
import com.example.sbom.repository.ProjectRepository;
import com.example.sbom.repository.RepoConfigRepository;
import com.example.sbom.repository.SbomFileRepository;
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

@Service
public class ModuleService {

    private static final Logger log = LoggerFactory.getLogger(ModuleService.class);

    private final ModuleRepository moduleRepository;
    private final ModuleHistoryRepository historyRepository;
    private final ProjectRepository projectRepository;
    private final RepoConfigRepository repoConfigRepository;
    private final SbomFileRepository sbomFileRepository;
    private final ObjectMapper objectMapper;

    public ModuleService(ModuleRepository moduleRepository,
                         ModuleHistoryRepository historyRepository,
                         ProjectRepository projectRepository,
                         RepoConfigRepository repoConfigRepository,
                         SbomFileRepository sbomFileRepository,
                         ObjectMapper objectMapper) {
        this.moduleRepository = moduleRepository;
        this.historyRepository = historyRepository;
        this.projectRepository = projectRepository;
        this.repoConfigRepository = repoConfigRepository;
        this.sbomFileRepository = sbomFileRepository;
        this.objectMapper = objectMapper;
    }

    @Transactional(readOnly = true)
    public List<Module> listByProject(Long projectId) {
        ensureProjectExists(projectId);
        return moduleRepository.findByProjectIdOrderByCreatedAtAsc(projectId);
    }

    @Transactional(readOnly = true)
    public Module get(Long projectId, Long id) {
        Module m = moduleRepository.findById(id)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND,
                        "Module not found: id=" + id));
        if (!m.getProjectId().equals(projectId)) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND,
                    "Module " + id + " does not belong to project " + projectId);
        }
        return m;
    }

    @Transactional
    public Module create(Long projectId, ModuleRequest req) {
        ensureProjectExists(projectId);
        String name = req.getName().trim();
        if (moduleRepository.findByProjectIdAndName(projectId, name).isPresent()) {
            throw new ResponseStatusException(HttpStatus.CONFLICT,
                    "Module name already exists in project: " + name);
        }
        if (req.getRepoConfigId() != null) {
            ensureRepoConfigBelongsToProject(projectId, req.getRepoConfigId());
        }

        Module m = new Module();
        m.setProjectId(projectId);
        m.setName(name);
        m.setRepoConfigId(req.getRepoConfigId());
        m.setPathInRepo(blankToNull(req.getPathInRepo()));
        m.setSbomPattern(blankToNull(req.getSbomPattern()));
        m.setVersion(1);
        m = moduleRepository.saveAndFlush(m);
        recordHistory(m, ModuleHistory.ChangeType.CREATED);
        log.info("ModuleService: created id={} projectId={} name='{}'", m.getId(), projectId, m.getName());
        return m;
    }

    @Transactional
    public Module update(Long projectId, Long id, ModuleRequest req) {
        Module m = get(projectId, id);
        String newName = req.getName().trim();

        if (!m.getName().equals(newName)
                && moduleRepository.findByProjectIdAndName(projectId, newName).isPresent()) {
            throw new ResponseStatusException(HttpStatus.CONFLICT,
                    "Module name already exists in project: " + newName);
        }
        if (req.getRepoConfigId() != null) {
            ensureRepoConfigBelongsToProject(projectId, req.getRepoConfigId());
        }

        m.setName(newName);
        m.setRepoConfigId(req.getRepoConfigId());
        m.setPathInRepo(blankToNull(req.getPathInRepo()));
        m.setSbomPattern(blankToNull(req.getSbomPattern()));
        m.setVersion(m.getVersion() + 1);
        m = moduleRepository.saveAndFlush(m);
        recordHistory(m, ModuleHistory.ChangeType.UPDATED);
        log.info("ModuleService: updated id={} new version={}", m.getId(), m.getVersion());
        return m;
    }

    @Transactional
    public void delete(Long projectId, Long id) {
        Module m = get(projectId, id);
        long fileCount = sbomFileRepository.countByModuleId(id);
        if (fileCount > 0) {
            throw new ResponseStatusException(HttpStatus.CONFLICT,
                    "Cannot delete Module: " + fileCount + " SBOM file(s) still reference it.");
        }
        recordHistory(m, ModuleHistory.ChangeType.DELETED);
        moduleRepository.delete(m);
        log.info("ModuleService: deleted id={}", id);
    }

    @Transactional(readOnly = true)
    public List<ModuleHistory> getHistory(Long projectId, Long id) {
        get(projectId, id);
        return historyRepository.findByModuleIdOrderByChangedAtDesc(id);
    }

    private void ensureProjectExists(Long projectId) {
        if (!projectRepository.existsById(projectId)) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND,
                    "Project not found: id=" + projectId);
        }
    }

    private void ensureRepoConfigBelongsToProject(Long projectId, Long repoConfigId) {
        RepoConfig cfg = repoConfigRepository.findById(repoConfigId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND,
                        "RepoConfig not found: id=" + repoConfigId));
        if (!cfg.getProjectId().equals(projectId)) {
            throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
                    "RepoConfig " + repoConfigId + " does not belong to project " + projectId);
        }
    }

    private void recordHistory(Module m, ModuleHistory.ChangeType type) {
        ModuleHistory h = new ModuleHistory();
        h.setModuleId(m.getId());
        h.setProjectId(m.getProjectId());
        h.setVersion(m.getVersion());
        h.setChangeType(type);
        h.setSnapshotJson(serialize(m));
        historyRepository.save(h);
    }

    private String serialize(Module m) {
        try {
            Map<String, Object> snapshot = Map.of(
                    "id", m.getId(),
                    "projectId", m.getProjectId(),
                    "name", m.getName(),
                    "repoConfigId", m.getRepoConfigId() == null ? -1 : m.getRepoConfigId(),
                    "pathInRepo", m.getPathInRepo() == null ? "" : m.getPathInRepo(),
                    "sbomPattern", m.getSbomPattern() == null ? "" : m.getSbomPattern(),
                    "version", m.getVersion(),
                    "createdAt", m.getCreatedAt() == null ? "" : m.getCreatedAt().toString(),
                    "updatedAt", m.getUpdatedAt() == null ? "" : m.getUpdatedAt().toString()
            );
            return objectMapper.writeValueAsString(snapshot);
        } catch (JsonProcessingException e) {
            log.warn("ModuleService: failed to serialize snapshot id={}", m.getId(), e);
            return "{}";
        }
    }

    private static String blankToNull(String value) {
        return (value == null || value.isBlank()) ? null : value.trim();
    }
}
