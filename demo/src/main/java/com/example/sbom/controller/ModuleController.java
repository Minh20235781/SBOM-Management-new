package com.example.sbom.controller;

import com.example.sbom.ai.ml.service.ModuleScanService;
import com.example.sbom.dto.ModuleRequest;
import com.example.sbom.entity.Module;
import com.example.sbom.entity.ModuleDetectionCache;
import com.example.sbom.entity.ModuleHistory;
import com.example.sbom.repository.ModuleDetectionCacheRepository;
import com.example.sbom.service.GitHubService;
import com.example.sbom.service.ModuleService;
import com.example.sbom.service.ProjectService;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.validation.Valid;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.time.Duration;
import java.time.Instant;
import java.util.Collections;
import java.util.List;

@RestController
@RequestMapping("/api/projects/{projectId}/modules")
public class ModuleController {

    private static final Logger log = LoggerFactory.getLogger(ModuleController.class);

    /** How long a cached GitHub detection stays valid. The
     *  user can force a re-fetch with {@code ?refresh=true}. */
    private static final Duration CACHE_TTL = Duration.ofHours(1);

    private final ModuleService service;
    private final GitHubService gitHubService;
    private final ProjectService projectService;
    private final ModuleDetectionCacheRepository cacheRepository;
    private final ModuleScanService moduleScanService;
    private final ObjectMapper objectMapper;

    public ModuleController(ModuleService service,
                            GitHubService gitHubService,
                            ProjectService projectService,
                            ModuleDetectionCacheRepository cacheRepository,
                            ModuleScanService moduleScanService,
                            ObjectMapper objectMapper) {
        this.service = service;
        this.gitHubService = gitHubService;
        this.projectService = projectService;
        this.cacheRepository = cacheRepository;
        this.moduleScanService = moduleScanService;
        this.objectMapper = objectMapper;
    }

    @GetMapping
    public List<Module> list(@PathVariable Long projectId) {
        return service.listByProject(projectId);
    }

    @GetMapping("/{id}")
    public Module get(@PathVariable Long projectId, @PathVariable Long id) {
        return service.get(projectId, id);
    }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    public Module create(@PathVariable Long projectId,
                         @Valid @RequestBody ModuleRequest req) {
        return service.create(projectId, req);
    }

    @PutMapping("/{id}")
    public Module update(@PathVariable Long projectId,
                         @PathVariable Long id,
                         @Valid @RequestBody ModuleRequest req) {
        return service.update(projectId, id, req);
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> delete(@PathVariable Long projectId, @PathVariable Long id) {
        service.delete(projectId, id);
        return ResponseEntity.noContent().build();
    }

    @GetMapping("/{id}/history")
    public List<ModuleHistory> history(@PathVariable Long projectId, @PathVariable Long id) {
        return service.getHistory(projectId, id);
    }

    /**
     * Run a Trivy scan against the module's upstream repo
     * and persist the resulting SBOM as a module-scoped
     * {@link com.example.sbom.entity.SbomFile}. Legacy
     * endpoint: Trivy `repo` against the URL — whole repo
     * is scanned, SBOM attributed to this module. This
     * path has been working in production for a while; do
     * not change its behaviour.
     */
    @PostMapping("/{id}/scan")
    public ModuleScanService.ScanResult scan(@PathVariable Long projectId,
                                            @PathVariable Long id) {
        return moduleScanService.scanModuleRepo(projectId, id);
    }

    /**
     * Per-module subdir scan (added later, on a separate
     * endpoint so the existing /scan callers are
     * untouched). Shallow-clones the repo, then runs
     * Trivy `fs <module-path>` so the SBOM contains only
     * the packages declared by this module.
     */
    @PostMapping("/{id}/scan-fs")
    public ModuleScanService.ScanResult scanFs(@PathVariable Long projectId,
                                              @PathVariable Long id) {
        return moduleScanService.scanModuleFs(projectId, id);
    }

    /**
     * Auto-detect modules by talking to GitHub: list the
     * repo tree and parse the parent build manifest. Returns
     * the detected list, the build system, the default
     * branch, and (if anything went wrong) a non-null
     * {@code error} string the UI can show.
     *
     * This is a read-only suggestion — it does NOT insert
     * Module rows. The user (or a follow-up POST) decides
     * which detected modules to materialise.
     *
     * Cached for {@value #CACHE_TTL_HOURS} hour per
     * (project, owner/repo@branch) so the GitHub tree API
     * isn't hammered on every project open. Pass
     * {@code ?refresh=true} to force a re-fetch.
     */
    private static final String CACHE_TTL_HOURS = "1";

    @GetMapping("/auto-detect")
    public GitHubService.DetectResult autoDetect(@PathVariable Long projectId,
                                                @RequestParam(value = "refresh", defaultValue = "false") boolean refresh) {
        var project = projectService.getById(projectId);
        String description = project.getDescription();

        // First, resolve the GitHub URL (if any) so we can
        // look up a cache row for the (project, owner/repo)
        // tuple. We intentionally do NOT include the branch
        // here — GitHub may have a different default branch
        // than what we cached under, but the repo itself
        // is a stable cache key.
        String ownerRepo = gitHubService.extractOwnerRepo(description)
                .map(o -> o[0] + "/" + o[1])
                .orElse(null);

        if (!refresh && ownerRepo != null) {
            var cached = cacheRepository
                    .findByProjectIdAndRepoSignature(projectId, ownerRepo)
                    .orElse(null);
            if (cached != null && cached.getFetchedAt() != null
                    && Duration.between(cached.getFetchedAt(), Instant.now()).compareTo(CACHE_TTL) < 0) {
                log.info("auto-detect: cache hit for projectId={} signature={} (age={}m)",
                        projectId, ownerRepo, Duration.between(cached.getFetchedAt(), Instant.now()).toMinutes());
                return decode(cached);
            }
        }

        GitHubService.DetectResult result = gitHubService.detectModules(description);
        persist(projectId, result);
        return result;
    }

    private void persist(Long projectId, GitHubService.DetectResult result) {
        // Build the cache key from owner+repo (not branch)
        // so the cache survives a branch-default rename.
        String owner = result.owner();
        String repo = result.repo();
        if (owner == null || repo == null) return;
        String signature = owner + "/" + repo;
        try {
            List<GitHubService.DetectedModule> mods =
                    result.modules() == null ? Collections.emptyList() : result.modules();
            String modulesJson = objectMapper.writeValueAsString(mods);
            ModuleDetectionCache row = cacheRepository
                    .findByProjectIdAndRepoSignature(projectId, signature)
                    .orElseGet(ModuleDetectionCache::new);
            row.setProjectId(projectId);
            row.setRepoSignature(signature);
            row.setOwner(owner);
            row.setRepo(repo);
            row.setDefaultBranch(result.defaultBranch());
            row.setBuildSystem(result.buildSystem());
            row.setModulesJson(modulesJson);
            row.setErrorMessage(result.error());
            row.setFetchedAt(Instant.now());
            cacheRepository.save(row);
            log.info("auto-detect: cache stored projectId={} signature={} modules={}",
                    projectId, signature, mods.size());
        } catch (Exception ex) {
            log.warn("auto-detect: failed to persist cache for projectId={}: {}",
                    projectId, ex.getMessage());
        }
    }

    private GitHubService.DetectResult decode(ModuleDetectionCache cached) {
        List<GitHubService.DetectedModule> mods;
        try {
            if (cached.getModulesJson() == null || cached.getModulesJson().isBlank()) {
                mods = Collections.emptyList();
            } else {
                mods = objectMapper.readValue(
                        cached.getModulesJson(),
                        new TypeReference<List<GitHubService.DetectedModule>>() {});
            }
        } catch (Exception ex) {
            log.warn("auto-detect: cache decode failed for id={}: {}", cached.getId(), ex.getMessage());
            mods = Collections.emptyList();
        }
        return new GitHubService.DetectResult(
                cached.getOwner(),
                cached.getRepo(),
                cached.getDefaultBranch(),
                cached.getBuildSystem(),
                mods,
                cached.getErrorMessage());
    }
}
