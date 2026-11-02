package com.example.sbom.controller;

import com.example.sbom.dto.ProjectCreateRequest;
import com.example.sbom.dto.ProjectResponse;
import com.example.sbom.dto.ProjectUpdateRequest;
import com.example.sbom.entity.CommitsCache;
import com.example.sbom.entity.Project;
import com.example.sbom.entity.ProjectHistory;
import com.example.sbom.entity.RiskAssessment;
import com.example.sbom.entity.VulnStatusHistory;
import com.example.sbom.repository.CommitsCacheRepository;
import com.example.sbom.repository.VulnStatusHistoryRepository;
import com.example.sbom.service.GitHubService;
import com.example.sbom.service.ProjectService;
import com.example.sbom.service.RiskAssessmentService;
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
import java.time.OffsetDateTime;
import java.time.format.DateTimeParseException;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

/**
 * Project management endpoints. All mutations are wrapped by
 * {@link ProjectService} which writes a row to project_history so the
 * timeline view in Phase 9 has data to render.
 */
@RestController
@RequestMapping("/api/projects")
public class ProjectController {

    private static final Logger log = LoggerFactory.getLogger(ProjectController.class);

    /** Cache TTL for the recent-commits endpoint. The 15-minute
     *  window keeps the UI feeling fresh while avoiding the
     *  per-commit file-tree calls that blow through the
     *  anonymous GitHub rate limit in minutes. */
    private static final Duration COMMITS_CACHE_TTL = Duration.ofMinutes(15);

    private final ProjectService projectService;
    private final GitHubService gitHubService;
    private final CommitsCacheRepository commitsCacheRepository;
    private final RiskAssessmentService riskAssessmentService;
    private final VulnStatusHistoryRepository vulnStatusHistoryRepository;
    private final ObjectMapper objectMapper;

    /**
     * Short-lived cache for {@link #decorateWithState} inputs.
     * Without this, every {@code GET /commits} call (cache hit or
     * miss) pays for two DB queries ({@code findLatest} +
     * {@code countImpactForScan}). With the cache, repeated page
     * opens within {@value #STATE_CACHE_TTL_SECONDS}s reuse the
     * same values. 30s is short enough to feel fresh right after
     * a scan and long enough to coalesce bursty traffic.
     */
    private final java.util.concurrent.ConcurrentHashMap<Long, CachedState> stateCache = new java.util.concurrent.ConcurrentHashMap<>();
    private static final long STATE_CACHE_TTL_SECONDS = 30;

    private record CachedState(Instant assessedAt, long impactCount, long storedAtEpochMillis) {}

    public ProjectController(ProjectService projectService,
                             GitHubService gitHubService,
                             CommitsCacheRepository commitsCacheRepository,
                             RiskAssessmentService riskAssessmentService,
                             VulnStatusHistoryRepository vulnStatusHistoryRepository,
                             ObjectMapper objectMapper) {
        this.projectService = projectService;
        this.gitHubService = gitHubService;
        this.commitsCacheRepository = commitsCacheRepository;
        this.riskAssessmentService = riskAssessmentService;
        this.vulnStatusHistoryRepository = vulnStatusHistoryRepository;
        this.objectMapper = objectMapper;
    }

    @GetMapping
    public List<ProjectResponse> list() {
        return projectService.list().stream()
                .map(p -> ProjectResponse.from(p, projectService.countPackages(p.getId())))
                .toList();
    }

    @GetMapping("/{id}")
    public ProjectResponse get(@PathVariable Long id) {
        Project p = projectService.getById(id);
        return ProjectResponse.from(p, projectService.countPackages(id));
    }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    public ProjectResponse create(@Valid @RequestBody ProjectCreateRequest req) {
        Project created = projectService.create(req);
        return ProjectResponse.from(created, 0L);
    }

    @PutMapping("/{id}")
    public ProjectResponse update(@PathVariable Long id,
                                  @Valid @RequestBody ProjectUpdateRequest req) {
        Project updated = projectService.update(id, req);
        return ProjectResponse.from(updated, projectService.countPackages(id));
    }

    // Note: the previous DELETE /api/projects/{id} endpoint
    // was removed — ProjectService.delete() always returned
    // HTTP 409 once any package was linked, so the call was
    // effectively dead code on the FE. Use /reset instead to
    // clear data, or leave the project in place.

    /**
     * Reset a project's data without deleting the project
     * row: drops risk snapshots, vuln-status history, the
     * package→project links, and the dependency-graph rows
     * tied to the project's repo name. After this call the
     * project is a clean shell, ready for a fresh Trivy
     * scan via the existing /api/sbom/scan-and-save entry
     * point.
     */
    @PostMapping("/{id}/reset")
    public java.util.Map<String, Object> reset(@PathVariable Long id) {
        java.util.Map<String, Integer> counts = projectService.reset(id);
        return java.util.Map.of(
                "status", "ok",
                "projectId", id,
                "cleared", counts
        );
    }

    @GetMapping("/{id}/history")
    public List<ProjectHistory> history(@PathVariable Long id) {
        return projectService.getHistory(id);
    }

    /**
     * Most recent commits on the project's upstream repo
     * (read from the project description URL). Each commit
     * carries a small "file tree" of the changes — the list
     * of files added/modified/deleted in that commit, plus
     * a +/- count — plus a derived {@code state} flag:
     * <ul>
     *   <li>{@code "new"} — newer than the latest scan (a
     *       re-scan may surface new vulns or fixes).</li>
     *   <li>{@code "scanned-with-impact"} — covered by the
     *       latest scan which produced NEW / FIXED / REOPENED
     *       diff rows.</li>
     *   <li>{@code "no-impact"} — covered by the latest scan
     *       but the diff was empty (CI workflows, refactors).</li>
     * </ul>
     * Returns an empty list on failure (e.g. the description
     * doesn't reference a GitHub repo, or GitHub is unreachable)
     * so the UI can render a friendly "no data" state without
     * a 5xx.
     *
     * Cached for 15 minutes per (project, owner/repo) so the
     * GitHub API isn't re-hit on every page open. Pass
     * {@code ?refresh=true} to force a re-fetch. Note that
     * state decoration is computed at response time, not
     * cached, so it always reflects the latest scan.
     */
    @GetMapping("/{id}/commits")
    public List<GitHubService.CommitWithState> commits(@PathVariable Long id,
                                                       @RequestParam(value = "limit", defaultValue = "5") int limit,
                                                       @RequestParam(value = "refresh", defaultValue = "false") boolean refresh) {
        var project = projectService.getById(id);
        String description = project.getDescription();
        String signature = gitHubService.extractOwnerRepo(description)
                .map(o -> o[0] + "/" + o[1])
                .orElse(null);

        List<GitHubService.CommitInfo> commits;
        if (!refresh && signature != null) {
            var cached = commitsCacheRepository
                    .findByProjectIdAndRepoSignature(id, signature)
                    .orElse(null);
            if (cached != null && cached.getFetchedAt() != null
                    && Duration.between(cached.getFetchedAt(), Instant.now()).compareTo(COMMITS_CACHE_TTL) < 0) {
                log.info("commits: cache hit projectId={} signature={} (age={}s, limit={})",
                        id, signature,
                        Duration.between(cached.getFetchedAt(), Instant.now()).toSeconds(),
                        limit);
                commits = decodeCommits(cached, limit);
            } else {
                commits = gitHubService.listCommits(description, limit);
                persist(id, signature, commits);
            }
        } else {
            commits = gitHubService.listCommits(description, limit);
            persist(id, signature, commits);
        }

        return decorateWithState(id, commits);
    }

    /**
     * Compute the {@link GitHubService.CommitWithState#state()}
     * for each commit by comparing its date to the project's
     * latest risk snapshot and, when covered by that snapshot,
     * checking whether the vuln diff produced any state
     * transitions (NEW / FIXED / REOPENED).
     */
    private List<GitHubService.CommitWithState> decorateWithState(Long projectId,
                                                                  List<GitHubService.CommitInfo> commits) {
        CachedState cached = lookupState(projectId);
        Instant assessedAt = cached.assessedAt();
        long impactCount = cached.impactCount();

        if (commits == null || commits.isEmpty()) {
            return Collections.emptyList();
        }
        return commits.stream()
                .map(c -> classify(c, assessedAt, impactCount))
                .toList();
    }

    /**
     * Look up (and cache) the two values used by {@link #classify}:
     * the latest risk snapshot's assessed-at instant and the impact
     * count of that snapshot. Cached for {@value #STATE_CACHE_TTL_SECONDS}
     * seconds per project. Cache miss falls back to the DB.
     */
    private CachedState lookupState(Long projectId) {
        long now = System.currentTimeMillis();
        CachedState hit = stateCache.get(projectId);
        if (hit != null && (now - hit.storedAtEpochMillis()) < STATE_CACHE_TTL_SECONDS * 1000) {
            return hit;
        }
        Optional<RiskAssessment> latest = riskAssessmentService.findLatest(projectId);
        Instant assessedAt = latest.map(RiskAssessment::getAssessedAt).orElse(null);
        Long scanId = latest.map(RiskAssessment::getId).orElse(null);
        long impactCount = (scanId != null)
                ? vulnStatusHistoryRepository.countImpactForScan(scanId)
                : 0L;
        CachedState fresh = new CachedState(assessedAt, impactCount, now);
        stateCache.put(projectId, fresh);
        return fresh;
    }

    private GitHubService.CommitWithState classify(GitHubService.CommitInfo c,
                                                    Instant assessedAt,
                                                    long impactCount) {
        if (assessedAt == null) {
            // Project never scanned — classify by file tree:
            // a commit touching a dependency manifest is "new"
            // (worth re-scanning), otherwise it's "no-impact".
            return GitHubService.isLikelyDependencyAffecting(c)
                    ? GitHubService.CommitWithState.newCommit(c)
                    : GitHubService.CommitWithState.noImpactInferred(c);
        }
        Instant commitDate = parseIso(c.date());
        if (commitDate == null) {
            // Cannot parse the date — be safe and treat as new
            // so the user is at least offered a re-scan.
            return GitHubService.CommitWithState.newCommit(c);
        }
        if (commitDate.isAfter(assessedAt)) {
            // New — but only worth re-scanning if the file tree
            // touches a dependency manifest. CI/source/test commits
            // get the inferred "no-impact" badge instead.
            return GitHubService.isLikelyDependencyAffecting(c)
                    ? GitHubService.CommitWithState.newCommit(c)
                    : GitHubService.CommitWithState.noImpactInferred(c);
        }
        if (impactCount > 0) {
            return GitHubService.CommitWithState.scannedWithImpact(c,
                    "Latest scan changed " + impactCount + " vuln row(s)");
        }
        return GitHubService.CommitWithState.noImpactVerified(c);
    }

    /**
     * GitHub commits come back as ISO-8601 strings. We try
     * a couple of common variants (with/without fractional
     * seconds and timezone). Returns {@code null} when the
     * value cannot be parsed so the caller can fall back to
     * a safe default.
     */
    private Instant parseIso(String iso) {
        if (iso == null || iso.isBlank()) return null;
        try {
            return Instant.parse(iso);
        } catch (DateTimeParseException ignore) {
            try {
                return OffsetDateTime.parse(iso).toInstant();
            } catch (DateTimeParseException ignore2) {
                return null;
            }
        }
    }

    private void persist(Long projectId, String signature, List<GitHubService.CommitInfo> commits) {
        if (signature == null) return; // no GitHub URL → no point caching an empty result
        try {
            // We store the canonical (limit=10) payload and let
            // the read path slice it down to whatever limit
            // the caller asked for. That way a future request
            // for limit=10 doesn't have to re-hit GitHub just
            // because the previous request was for limit=5.
            List<GitHubService.CommitInfo> canonical =
                    commits != null ? commits : Collections.emptyList();
            String json = objectMapper.writeValueAsString(canonical);
            CommitsCache row = commitsCacheRepository
                    .findByProjectIdAndRepoSignature(projectId, signature)
                    .orElseGet(CommitsCache::new);
            row.setProjectId(projectId);
            row.setRepoSignature(signature);
            row.setCommitsJson(json);
            row.setFetchedAt(Instant.now());
            commitsCacheRepository.save(row);
            log.info("commits: cache stored projectId={} signature={} rows={}",
                    projectId, signature, canonical.size());
        } catch (Exception ex) {
            log.warn("commits: failed to persist cache projectId={}: {}",
                    projectId, ex.getMessage());
        }
    }

    private List<GitHubService.CommitInfo> decodeCommits(CommitsCache cached, int limit) {
        try {
            if (cached.getCommitsJson() == null || cached.getCommitsJson().isBlank()) {
                return Collections.emptyList();
            }
            List<GitHubService.CommitInfo> all = objectMapper.readValue(
                    cached.getCommitsJson(),
                    new TypeReference<List<GitHubService.CommitInfo>>() {});
            if (limit > 0 && all.size() > limit) {
                return all.subList(0, limit);
            }
            return all;
        } catch (Exception ex) {
            log.warn("commits: cache decode failed id={}: {}", cached.getId(), ex.getMessage());
            return Collections.emptyList();
        }
    }
}
