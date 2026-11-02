package com.example.sbom.service;

import com.example.sbom.dto.RepoConfigRequest;
import com.example.sbom.entity.RepoConfig;
import com.example.sbom.entity.RepoConfigHistory;
import com.example.sbom.repository.ModuleRepository;
import com.example.sbom.repository.ProjectRepository;
import com.example.sbom.repository.RepoConfigHistoryRepository;
import com.example.sbom.repository.RepoConfigRepository;
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
public class RepoConfigService {

    private static final Logger log = LoggerFactory.getLogger(RepoConfigService.class);

    private final RepoConfigRepository repoConfigRepository;
    private final RepoConfigHistoryRepository historyRepository;
    private final ModuleRepository moduleRepository;
    private final ProjectRepository projectRepository;
    private final ObjectMapper objectMapper;

    public RepoConfigService(RepoConfigRepository repoConfigRepository,
                             RepoConfigHistoryRepository historyRepository,
                             ModuleRepository moduleRepository,
                             ProjectRepository projectRepository,
                             ObjectMapper objectMapper) {
        this.repoConfigRepository = repoConfigRepository;
        this.historyRepository = historyRepository;
        this.moduleRepository = moduleRepository;
        this.projectRepository = projectRepository;
        this.objectMapper = objectMapper;
    }

    @Transactional(readOnly = true)
    public List<RepoConfig> listByProject(Long projectId) {
        ensureProjectExists(projectId);
        return repoConfigRepository.findByProjectIdOrderByCreatedAtAsc(projectId);
    }

    @Transactional(readOnly = true)
    public RepoConfig get(Long projectId, Long id) {
        RepoConfig cfg = repoConfigRepository.findById(id)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND,
                        "RepoConfig not found: id=" + id));
        if (!cfg.getProjectId().equals(projectId)) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND,
                    "RepoConfig " + id + " does not belong to project " + projectId);
        }
        return cfg;
    }

    @Transactional
    public RepoConfig create(Long projectId, RepoConfigRequest req) {
        ensureProjectExists(projectId);
        if (repoConfigRepository.findByProjectIdAndRepoUrl(projectId, req.getRepoUrl().trim()).isPresent()) {
            throw new ResponseStatusException(HttpStatus.CONFLICT,
                    "RepoConfig already exists for url: " + req.getRepoUrl());
        }
        RepoConfig cfg = new RepoConfig();
        cfg.setProjectId(projectId);
        cfg.setRepoUrl(req.getRepoUrl().trim());
        cfg.setBranch(orDefault(req.getBranch(), "main"));
        cfg.setScanSchedule(blankToNull(req.getScanSchedule()));
        cfg.setScanTool(orDefault(req.getScanTool(), "TRIVY"));
        cfg.setVersion(1);
        cfg = repoConfigRepository.saveAndFlush(cfg);
        recordHistory(cfg, RepoConfigHistory.ChangeType.CREATED);
        log.info("RepoConfigService: created id={} projectId={} url='{}'",
                cfg.getId(), projectId, cfg.getRepoUrl());
        return cfg;
    }

    @Transactional
    public RepoConfig update(Long projectId, Long id, RepoConfigRequest req) {
        RepoConfig cfg = get(projectId, id);
        String newUrl = req.getRepoUrl().trim();

        if (!cfg.getRepoUrl().equals(newUrl)
                && repoConfigRepository.findByProjectIdAndRepoUrl(projectId, newUrl).isPresent()) {
            throw new ResponseStatusException(HttpStatus.CONFLICT,
                    "RepoConfig already exists for url: " + newUrl);
        }

        cfg.setRepoUrl(newUrl);
        cfg.setBranch(orDefault(req.getBranch(), "main"));
        cfg.setScanSchedule(blankToNull(req.getScanSchedule()));
        cfg.setScanTool(orDefault(req.getScanTool(), "TRIVY"));
        cfg.setVersion(cfg.getVersion() + 1);
        cfg = repoConfigRepository.saveAndFlush(cfg);

        recordHistory(cfg, RepoConfigHistory.ChangeType.UPDATED);
        log.info("RepoConfigService: updated id={} new version={}", cfg.getId(), cfg.getVersion());
        return cfg;
    }

    @Transactional
    public void delete(Long projectId, Long id) {
        RepoConfig cfg = get(projectId, id);
        long moduleCount = moduleRepository.countByRepoConfigId(id);
        if (moduleCount > 0) {
            throw new ResponseStatusException(HttpStatus.CONFLICT,
                    "Cannot delete RepoConfig: " + moduleCount + " module(s) still reference it.");
        }
        recordHistory(cfg, RepoConfigHistory.ChangeType.DELETED);
        repoConfigRepository.delete(cfg);
        log.info("RepoConfigService: deleted id={}", id);
    }

    @Transactional(readOnly = true)
    public List<RepoConfigHistory> getHistory(Long projectId, Long id) {
        get(projectId, id);
        return historyRepository.findByRepoConfigIdOrderByChangedAtDesc(id);
    }

    private void ensureProjectExists(Long projectId) {
        if (!projectRepository.existsById(projectId)) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND,
                    "Project not found: id=" + projectId);
        }
    }

    private void recordHistory(RepoConfig cfg, RepoConfigHistory.ChangeType type) {
        RepoConfigHistory h = new RepoConfigHistory();
        h.setRepoConfigId(cfg.getId());
        h.setProjectId(cfg.getProjectId());
        h.setVersion(cfg.getVersion());
        h.setChangeType(type);
        h.setSnapshotJson(serialize(cfg));
        historyRepository.save(h);
    }

    private String serialize(RepoConfig cfg) {
        try {
            Map<String, Object> snapshot = Map.of(
                    "id", cfg.getId(),
                    "projectId", cfg.getProjectId(),
                    "repoUrl", cfg.getRepoUrl(),
                    "branch", cfg.getBranch() == null ? "" : cfg.getBranch(),
                    "scanSchedule", cfg.getScanSchedule() == null ? "" : cfg.getScanSchedule(),
                    "scanTool", cfg.getScanTool() == null ? "" : cfg.getScanTool(),
                    "version", cfg.getVersion(),
                    "lastScanAt", cfg.getLastScanAt() == null ? "" : cfg.getLastScanAt().toString(),
                    "createdAt", cfg.getCreatedAt() == null ? "" : cfg.getCreatedAt().toString(),
                    "updatedAt", cfg.getUpdatedAt() == null ? "" : cfg.getUpdatedAt().toString()
            );
            return objectMapper.writeValueAsString(snapshot);
        } catch (JsonProcessingException e) {
            log.warn("RepoConfigService: failed to serialize snapshot id={}", cfg.getId(), e);
            return "{}";
        }
    }

    private static String orDefault(String value, String fallback) {
        return (value == null || value.isBlank()) ? fallback : value.trim();
    }

    private static String blankToNull(String value) {
        return (value == null || value.isBlank()) ? null : value.trim();
    }
}
