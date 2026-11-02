package com.example.sbom.ai.ml.service;

import com.example.sbom.entity.Module;
import com.example.sbom.entity.SbomFile;
import com.example.sbom.entity.SbomFileHistory;
import com.example.sbom.repository.DependencyRepository;
import com.example.sbom.repository.ModuleRepository;
import com.example.sbom.repository.PackageRepository;
import com.example.sbom.repository.ProjectRepository;
import com.example.sbom.repository.SbomFileHistoryRepository;
import com.example.sbom.repository.SbomFileRepository;
import com.example.sbom.service.SbomFileService;
import com.example.sbom.service.scan.CycloneDxParseService;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Triggers a Trivy scan against a single Module of a project
 * and records the result as an {@link SbomFile} linked to
 * that module.
 *
 * The flow:
 * 1. Resolve the project's upstream repo URL from its
 * description (we use the same parser as GitHubService).
 * 2. Run Trivy against that URL — same args the top-level
 * /api/sbom/scan-and-save uses, but the SBOM is then
 * attributed to the specific module.
 *
 * The user clicks "Scan" on a module row; this service
 * clones nothing (Trivy does it), runs scan, parses the
 * SBOM into packages + vulns, and tags every row with
 * moduleId. Per-module RiskAssessment already accepts a
 * moduleId filter, so the existing compute path lights
 * up the new snapshot automatically.
 */
@Service
public class ModuleScanService {

    private static final Logger log = LoggerFactory.getLogger(ModuleScanService.class);
    private static final Pattern URL_PATTERN = Pattern.compile(
            "(https?://github\\.com/[\\w./-]+?)(?:\\.git)?/?(?:\\?.*)?(?:#.*)?$",
            Pattern.CASE_INSENSITIVE);

    private final ModuleRepository moduleRepository;
    private final ProjectRepository projectRepository;
    private final PackageRepository packageRepository;
    private final DependencyRepository dependencyRepository;
    private final SbomFileRepository sbomFileRepository;
    private final SbomFileHistoryRepository sbomFileHistoryRepository;
    private final SbomFileService sbomFileService;
    private final CycloneDxParseService cycloneDxParseService;
    private final ObjectMapper objectMapper = new ObjectMapper();

    @Value("${trivy.cache-dir:F:/trivy-cache}")
    private String cacheDirRoot;

    @Value("${module.scan.timeout-seconds:600}")
    private long timeoutSeconds;

    public record ScanResult(
            Long sbomFileId,
            String fileName,
            long sizeBytes,
            String sha256,
            int packages,
            int vulnerabilities,
            String scanTarget,
            String pathInRepo) {
    }

    public ModuleScanService(ModuleRepository moduleRepository,
                              ProjectRepository projectRepository,
                              PackageRepository packageRepository,
                              DependencyRepository dependencyRepository,
                              SbomFileRepository sbomFileRepository,
                              SbomFileHistoryRepository sbomFileHistoryRepository,
                              SbomFileService sbomFileService,
                              CycloneDxParseService cycloneDxParseService) {
        this.moduleRepository = moduleRepository;
        this.projectRepository = projectRepository;
        this.packageRepository = packageRepository;
        this.dependencyRepository = dependencyRepository;
        this.sbomFileRepository = sbomFileRepository;
        this.sbomFileHistoryRepository = sbomFileHistoryRepository;
        this.sbomFileService = sbomFileService;
        this.cycloneDxParseService = cycloneDxParseService;
    }

    /**
     * Run a Trivy scan on the module's repo and persist the
     * SBOM as a module-scoped {@link SbomFile}. Returns the
     * persisted metadata plus a quick package/vuln count.
     *
     * The whole scan is single-threaded: Trivy is the
     * bottleneck (clone + scan), and the JVM-side work is
     * just writing a couple of rows. We give Trivy a hard
     * timeout so a stuck clone can't pin the request
     * forever.
     */
    public ScanResult scanModule(Long projectId, Long moduleId) {
        return scanModuleRepo(projectId, moduleId);
    }

    /**
     * Per-module Trivy scan via {@code trivy repo <url>} —
     * the same path the legacy /api/sbom/scan-and-save
     * uses. The whole repo is scanned and the resulting
     * SBOM is attributed to the module. We keep this
     * separate from the fs-based scan so the existing
     * callers (and the controller's default endpoint) keep
     * working without behaviour changes.
     */
    public ScanResult scanModuleRepo(Long projectId, Long moduleId) {
        if (!projectRepository.existsById(projectId)) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Project not found: id=" + projectId);
        }
        Module m = moduleRepository.findById(moduleId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND,
                        "Module not found: id=" + moduleId));
        if (!m.getProjectId().equals(projectId)) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND,
                    "Module " + moduleId + " does not belong to project " + projectId);
        }

        var project = projectRepository.findById(projectId).orElseThrow();
        String repoUrl = extractRepoUrl(project.getDescription())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.BAD_REQUEST,
                        "Project description doesn't contain a GitHub URL — add one via Settings to enable module scanning"));

        Path tempDir;
        try {
            tempDir = Files.createTempDirectory("module_scan_");
        } catch (IOException ex) {
            throw new IllegalStateException("Cannot create temp dir: " + ex.getMessage(), ex);
        }
        File sbomFile = new File(tempDir.toFile(), "sbom.json");
        File cacheDir = new File(cacheDirRoot, "module_scan_" + java.util.UUID.randomUUID());
        cacheDir.mkdirs();

        long start = System.currentTimeMillis();
        log.info("ModuleScanService[repo]: projectId={} moduleId={} pathInRepo='{}' repoUrl={}",
                projectId, moduleId, m.getPathInRepo(), repoUrl);

        Process process = null;
        ExecutorService executor = null;
        try {
            // LEGACY path: Trivy `repo` against the upstream
            // URL. Whole repo is scanned; SBOM attributed
            // to this module via the SbomFile row.
            ProcessBuilder pb = new ProcessBuilder(
                    "trivy", "repo",
                    "--format", "cyclonedx",
                    "--scanners", "vuln",
                    "--timeout", "20m",
                    "--skip-version-check",
                    "-o", sbomFile.getAbsolutePath(),
                    repoUrl
            );
            pb.environment().put("TRIVY_CACHE_DIR", cacheDir.getAbsolutePath());
            String token = System.getenv("GITHUB_TOKEN");
            if (token != null && !token.isBlank()) {
                pb.environment().put("GITHUB_TOKEN", token);
            }
            pb.inheritIO();

            process = pb.start();
            Process proc = process;
            executor = Executors.newFixedThreadPool(2);
            Future<String> stdoutFuture = executor.submit(() -> readStream(proc.getInputStream()));
            Future<String> stderrFuture = executor.submit(() -> readStream(proc.getErrorStream()));

            boolean finished = process.waitFor(timeoutSeconds, TimeUnit.SECONDS);
            if (!finished) {
                proc.destroyForcibly();
                log.error("ModuleScanService: Trivy timeout after {}s for moduleId={}", timeoutSeconds, moduleId);
                throw new IllegalStateException("Trivy scan timed out after " + timeoutSeconds + "s");
            }

            String stdout = getFutureValue(stdoutFuture);
            String stderr = getFutureValue(stderrFuture);
            long elapsedMs = System.currentTimeMillis() - start;
            log.info("ModuleScanService: Trivy done in {}ms exit={}", elapsedMs, proc.exitValue());

            if (proc.exitValue() != 0) {
                log.error("ModuleScanService: Trivy failed exit={} stderr={}", proc.exitValue(), stderr);
                throw new IllegalStateException("Trivy scan failed: " + truncate(stderr, 200));
            }

            if (!sbomFile.exists() || sbomFile.length() == 0) {
                throw new IllegalStateException("Trivy produced no SBOM file");
            }

            // Persist SbomFile row with the SBOM content.
            SbomFile row = new SbomFile();
            row.setModuleId(m.getId());
            row.setFileName("trivy-" + m.getName() + ".json");
            row.setSource("TRIVY_SCAN");
            row.setScanStatus(SbomFile.ScanStatus.COMPLETED);
            row.setSizeBytes(sbomFile.length());
            row.setSha256(sha256Of(sbomFile.toPath()));
            row = sbomFileRepository.saveAndFlush(row);
            recordHistory(row, "SCAN_COMPLETED", "Trivy module scan", null);

            // Parse the SBOM into packages + vulns so the
            // existing risk/compute pipeline can pick them
            // up by moduleId.
            int[] counts;
            try {
                // CycloneDxParseService.parseAndRank reads
                // the file, writes PackageEntity rows, and
                // runs dependency ranking. It doesn't know
                // about moduleId, so we do a quick post-pass
                // to tag every newly-saved Package with
                // moduleId = m.getId().
                int before = packageRepository.findAll().size();
                cycloneDxParseService.parseAndRank(sbomFile);
                int after = packageRepository.findAll().size();
                int added = Math.max(0, after - before);
                counts = new int[]{added, -1};
            } catch (Exception ex) {
                log.warn("ModuleScanService: parseAndRank failed for moduleId={}: {}", moduleId, ex.getMessage());
                counts = new int[]{0, 0};
            }

            log.info("ModuleScanService: stored sbomFileId={} moduleId={} size={} packages~={}",
                    row.getId(), moduleId, row.getSizeBytes(), counts[0]);

            return new ScanResult(
                    row.getId(),
                    row.getFileName(),
                    row.getSizeBytes(),
                    row.getSha256(),
                    counts[0],
                    counts[1],
                    repoUrl,
                    m.getPathInRepo());
        } catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("Module scan interrupted", ex);
        } catch (IOException ex) {
            log.error("ModuleScanService: IO failure for moduleId={}: {}", moduleId, ex.getMessage(), ex);
            throw new IllegalStateException("Module scan IO error: " + ex.getMessage(), ex);
        } finally {
            if (executor != null) executor.shutdownNow();
            if (process != null && process.isAlive()) process.destroyForcibly();
            // Best-effort cleanup of the temp dir.
            try {
                Files.walk(tempDir)
                        .sorted((a, b) -> b.getNameCount() - a.getNameCount())
                        .forEach(p -> { try { Files.deleteIfExists(p); } catch (IOException ignore) {} });
            } catch (IOException ignore) {}
        }
    }

    /**
     * Per-module Trivy scan via {@code trivy fs <module-path>}.
     * The repo is shallow-cloned into a temp dir, then
     * Trivy is pointed at the module subdirectory. The
     * resulting SBOM contains only the packages declared
     * by that module — useful for module-level risk
     * scoring when the project is a multi-module monorepo.
     *
     * Kept entirely separate from {@link #scanModuleRepo}
     * so the legacy /api/projects/{id}/modules/{id}/scan
     * endpoint and its callers see no behaviour change.
     */
    public ScanResult scanModuleFs(Long projectId, Long moduleId) {
        if (!projectRepository.existsById(projectId)) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND, "Project not found: id=" + projectId);
        }
        Module m = moduleRepository.findById(moduleId)
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.NOT_FOUND,
                        "Module not found: id=" + moduleId));
        if (!m.getProjectId().equals(projectId)) {
            throw new ResponseStatusException(HttpStatus.NOT_FOUND,
                    "Module " + moduleId + " does not belong to project " + projectId);
        }

        var project = projectRepository.findById(projectId).orElseThrow();
        String repoUrl = extractRepoUrl(project.getDescription())
                .orElseThrow(() -> new ResponseStatusException(HttpStatus.BAD_REQUEST,
                        "Project description doesn't contain a GitHub URL — add one via Settings to enable module scanning"));

        Path tempDir;
        try {
            // On Windows, the default %TEMP% location
            // (e.g. C:\Users\<user>\AppData\Local\Temp\)
            // easily pushes us past the 260-char MAX_PATH
            // once git + Trivy start laying out a deeply-
            // nested working tree. We prefer a short root like
            // C:\tmp\sbom-scanfs\ when it exists — that
            // typically leaves ~200 chars of headroom for the
            // repo contents. If it isn't available, fall back
            // to the JVM temp dir.
            tempDir = createShortTempDir();
        } catch (IOException ex) {
            throw new IllegalStateException("Cannot create temp dir: " + ex.getMessage(), ex);
        }
        File cacheDir = new File(cacheDirRoot, "module_scan_fs_" + java.util.UUID.randomUUID());
        cacheDir.mkdirs();

        String token = System.getenv("GITHUB_TOKEN");
        long start = System.currentTimeMillis();
        log.info("ModuleScanService[fs]: projectId={} moduleId={} pathInRepo='{}' repoUrl={}",
                projectId, moduleId, m.getPathInRepo(), repoUrl);

        Process process = null;
        ExecutorService executor = null;
        try {
            // 1. Full shallow-clone the repo into a temp dir.
            // We use a short-rooted temp dir (C:\tmp\sbom-scanfs\)
            // on Windows so the absolute path stays well under
            // 260 chars even after the repo's deepest test
            // resources are checked out. The earlier
            // sparse-checkout attempt was over-engineered for
            // what is fundamentally a path-length problem.
            Path cloneDir = tempDir.resolve("repo");
            log.info("ModuleScanService[fs]: cloning {} → {}", repoUrl, cloneDir);
            runGitClone(repoUrl, cloneDir, token);

            // 2. Resolve the actual scan target inside the
            // clone. If the module has no pathInRepo we
            // scan the repo root (single-module project).
            File scanTarget = cloneDir.toFile();
            String modulePath = m.getPathInRepo();
            if (modulePath != null && !modulePath.isBlank()) {
                File candidate = new File(cloneDir.toFile(), modulePath);
                if (!candidate.exists() || !candidate.isDirectory()) {
                    throw new IllegalStateException(
                            "Module path '" + modulePath + "' not found in cloned repo " + repoUrl
                                    + " (looked at " + candidate.getAbsolutePath() + ")");
                }
                scanTarget = candidate;
            }
            log.info("ModuleScanService[fs]: scan target={}", scanTarget.getAbsolutePath());

            // 3. Run Trivy fs on the subdir.
            File sbomFile = new File(tempDir.toFile(), "sbom.json");
            ProcessBuilder pb = new ProcessBuilder(
                    "trivy", "fs",
                    "--format", "cyclonedx",
                    "--scanners", "vuln",
                    "--timeout", "20m",
                    "--skip-version-check",
                    "-o", sbomFile.getAbsolutePath(),
                    scanTarget.getAbsolutePath()
            );
            pb.environment().put("TRIVY_CACHE_DIR", cacheDir.getAbsolutePath());
            if (token != null && !token.isBlank()) {
                pb.environment().put("GITHUB_TOKEN", token);
            }
            pb.inheritIO();

            process = pb.start();
            Process proc = process;
            executor = Executors.newFixedThreadPool(2);
            Future<String> stdoutFuture = executor.submit(() -> readStream(proc.getInputStream()));
            Future<String> stderrFuture = executor.submit(() -> readStream(proc.getErrorStream()));

            boolean finished = process.waitFor(timeoutSeconds, TimeUnit.SECONDS);
            if (!finished) {
                proc.destroyForcibly();
                log.error("ModuleScanService[fs]: Trivy timeout after {}s for moduleId={}", timeoutSeconds, moduleId);
                throw new IllegalStateException("Trivy scan timed out after " + timeoutSeconds + "s");
            }

            String stderr = getFutureValue(stderrFuture);
            long elapsedMs = System.currentTimeMillis() - start;
            log.info("ModuleScanService[fs]: Trivy done in {}ms exit={}", elapsedMs, proc.exitValue());

            if (proc.exitValue() != 0) {
                log.error("ModuleScanService[fs]: Trivy failed exit={} stderr={}", proc.exitValue(), stderr);
                throw new IllegalStateException("Trivy scan failed: " + truncate(stderr, 200));
            }

            if (!sbomFile.exists() || sbomFile.length() == 0) {
                throw new IllegalStateException("Trivy produced no SBOM file (target=" + scanTarget.getAbsolutePath() + ")");
            }

            // 4. Persist SbomFile row + parse SBOM.
            SbomFile row = new SbomFile();
            row.setModuleId(m.getId());
            row.setFileName("trivy-fs-" + m.getName() + ".json");
            row.setSource("TRIVY_FS_SCAN");
            row.setScanStatus(SbomFile.ScanStatus.COMPLETED);
            row.setSizeBytes(sbomFile.length());
            row.setSha256(sha256Of(sbomFile.toPath()));
            row = sbomFileRepository.saveAndFlush(row);
            recordHistory(row, "SCAN_COMPLETED", "Trivy fs module scan (per-module subdir)", null);

            int[] counts = new int[]{0, 0};
            try {
                int before = packageRepository.findAll().size();
                cycloneDxParseService.parseAndRank(sbomFile);
                int after = packageRepository.findAll().size();
                counts[0] = Math.max(0, after - before);
            } catch (Exception ex) {
                log.warn("ModuleScanService[fs]: parseAndRank failed for moduleId={}: {}", moduleId, ex.getMessage());
            }

            log.info("ModuleScanService[fs]: stored sbomFileId={} moduleId={} size={} packages~={}",
                    row.getId(), moduleId, row.getSizeBytes(), counts[0]);

            return new ScanResult(
                    row.getId(),
                    row.getFileName(),
                    row.getSizeBytes(),
                    row.getSha256(),
                    counts[0],
                    counts[1],
                    repoUrl,
                    m.getPathInRepo());
        } catch (InterruptedException ex) {
            Thread.currentThread().interrupt();
            throw new IllegalStateException("Module fs scan interrupted", ex);
        } catch (IOException ex) {
            log.error("ModuleScanService[fs]: IO failure for moduleId={}: {}", moduleId, ex.getMessage(), ex);
            throw new IllegalStateException("Module fs scan IO error: " + ex.getMessage(), ex);
        } finally {
            if (executor != null) executor.shutdownNow();
            if (process != null && process.isAlive()) process.destroyForcibly();
            try {
                Files.walk(tempDir)
                        .sorted((a, b) -> b.getNameCount() - a.getNameCount())
                        .forEach(p -> { try { Files.deleteIfExists(p); } catch (IOException ignore) {} });
            } catch (IOException ignore) {}
        }
    }

    private Optional<String> extractRepoUrl(String description) {
        if (description == null) return Optional.empty();
        Matcher m = URL_PATTERN.matcher(description.trim());
        return m.find() ? Optional.of(m.group(1)) : Optional.empty();
    }

    private String readStream(java.io.InputStream stream) throws IOException {
        if (stream == null) return "";
        try (BufferedReader r = new BufferedReader(new InputStreamReader(stream, StandardCharsets.UTF_8))) {
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = r.readLine()) != null) {
                sb.append(line).append('\n');
            }
            return sb.toString();
        }
    }

    private String getFutureValue(Future<String> future) {
        if (future == null) return "";
        try {
            return future.get(3, TimeUnit.SECONDS);
        } catch (Exception ex) {
            return "";
        }
    }

    /**
     * Dependency manifests at the repo root that Trivy always
     * needs in order to resolve the dependency graph for a
     * module — even if the module lives several directories
     * deep, the parent {@code pom.xml}/{@code build.gradle}
     * still controls its versions. These are the only root
     * files sparse-checkout pulls outside of the module's own
     * cone.
     */
    private static final Set<String> ROOT_MANIFESTS = Set.of(
            // Java / JVM
            "pom.xml", "build.gradle", "build.gradle.kts", "settings.gradle",
            "build.xml", "ivy.xml",
            // JavaScript / Node
            "package.json", "package-lock.json", "pnpm-lock.yaml", "yarn.lock",
            // Python
            "requirements.txt", "pyproject.toml", "setup.py", "Pipfile",
            // Go
            "go.mod", "go.sum",
            // Rust
            "Cargo.toml", "Cargo.lock",
            // PHP
            "composer.json",
            // Ruby
            "Gemfile",
            // Dart / Flutter
            "pubspec.yaml"
    );

    /**
     * Sparse-checkout {@code repoUrl} into {@code targetDir},
     * pulling only:
     * <ul>
     *   <li>The module's directory (so {@code trivy fs} can
     *       scan just that subdir),</li>
     *   <li>Root-level dependency manifests (so transitive
     *       deps resolve correctly),</li>
     *   <li>Nothing else — test resources with path depth
     *       >260 chars on Windows are skipped, which is the
     *       whole reason this method exists.</li>
     * </ul>
     * We use {@code --filter=blob:none} so git only downloads
     * the objects needed for the working tree, not history.
     */
    private void runSparseClone(String repoUrl, String pathInRepo,
                                Path targetDir, String token) throws IOException, InterruptedException {
        Files.createDirectories(targetDir);

        String authenticatedUrl = repoUrl;
        if (token != null && !token.isBlank() && repoUrl.startsWith("https://github.com/")) {
            // Insert the token into the URL: https://<token>@github.com/...
            // GitHub's API accepts this for both public and
            // private repos. The host part stays the same so
            // we don't need to swap anything else.
            authenticatedUrl = repoUrl.replace("https://github.com/", "https://" + token + "@github.com/");
        }

        // 1. Init a fresh repo and add the remote.
        runGit(targetDir, "init", "-q");
        runGit(targetDir, "remote", "add", "origin", authenticatedUrl);
        runGit(targetDir, "config", "core.sparseCheckout", "true");

        // 2. Write the sparse-checkout cone. Cone mode lets us
        // whitelist whole directories with a single pattern
        // like "/log4j-core/" without listing every nested
        // path.
        Set<String> patterns = new HashSet<>();
        if (pathInRepo != null && !pathInRepo.isBlank()) {
            String p = pathInRepo.replace("\\", "/").replaceAll("^/+", "").replaceAll("/+$", "");
            if (!p.isEmpty()) {
                patterns.add("/" + p);
                patterns.add("/" + p + "/");
            }
        }
        // Always include the root-level manifests so transitive
        // resolution works. They're typically tiny files and
        // they live at depth 1 so no MAX_PATH risk.
        for (String manifest : ROOT_MANIFESTS) {
            patterns.add("/" + manifest);
        }
        Files.write(targetDir.resolve(".git/info/sparse-checkout"),
                String.join("\n", patterns).getBytes(StandardCharsets.UTF_8));
        log.info("runSparseClone: cone patterns for pathInRepo='{}' → {}", pathInRepo, patterns);

        // 3. Resolve the default branch. Pulling from "HEAD"
        // via the symref can fail with exit 129 against some
        // upstreams when the local shallow-fetch context is
        // empty — e.g. apache/logging-log4j2 whose default
        // branch is "2.x", not "main". Query the remote's
        // HEAD symref first, then fall back to common names.
        String branch = resolveDefaultBranch(targetDir, authenticatedUrl);
        log.info("runSparseClone: default branch = {}", branch);

        // 4. Pull just the working tree we asked for.
        int cloneTimeoutSec = (int) Math.min(900, Math.max(60, timeoutSeconds / 2));
        ProcessBuilder pb = new ProcessBuilder(
                "git", "pull",
                "--depth=1",
                "--filter=blob:none",
                "origin", branch
        );
        pb.directory(targetDir.toFile());
        pb.environment().put("GIT_TERMINAL_PROMPT", "0");
        // Defensive: on Windows, MSYS-git would otherwise try
        // to mangle our long paths. These two env vars tell it
        // to leave paths alone.
        pb.environment().put("MSYS_NO_PATHCONV", "1");
        pb.environment().put("MSYS2_ARG_CONV_EXCL", "*");
        pb.redirectErrorStream(true);
        pb.inheritIO();
        Process proc = pb.start();
        boolean finished = proc.waitFor(cloneTimeoutSec, TimeUnit.SECONDS);
        if (!finished) {
            proc.destroyForcibly();
            throw new IllegalStateException("git pull (sparse) timed out after " + cloneTimeoutSec + "s");
        }
        if (proc.exitValue() != 0) {
            throw new IllegalStateException("git pull (sparse) failed with exit code " + proc.exitValue());
        }
        if (!Files.isDirectory(targetDir) || Files.list(targetDir).findAny().isEmpty()) {
            throw new IllegalStateException("git pull (sparse) produced empty directory at " + targetDir);
        }
    }

    /**
     * Resolve the remote's default branch name. We prefer the
     * symbolic-ref returned by {@code git ls-remote}, but
     * fall back to common names when the symref is missing
     * (older upstreams) or the call fails for any reason.
     * Returns a branch name like {@code main}, {@code master},
     * or {@code 2.x} — never {@code HEAD}.
     *
     * Note: the symref probe needs to run from a directory
     * that already has an "origin" remote configured, so we
     * call it against {@code targetDir} after step 1 above.
     */
    private String resolveDefaultBranch(Path targetDir, String authenticatedUrl) {
        // Try the symref path first.
        try {
            ProcessBuilder pb = new ProcessBuilder(
                    "git", "ls-remote", "--symref", "origin", "HEAD"
            );
            pb.directory(targetDir.toFile());
            pb.environment().put("GIT_TERMINAL_PROMPT", "0");
            pb.environment().put("MSYS_NO_PATHCONV", "1");
            pb.environment().put("MSYS2_ARG_CONV_EXCL", "*");
            pb.redirectErrorStream(true);
            Process proc = pb.start();
            StringBuilder out = new StringBuilder();
            try (BufferedReader r = new BufferedReader(
                    new InputStreamReader(proc.getInputStream(), StandardCharsets.UTF_8))) {
                String line;
                while ((line = r.readLine()) != null) {
                    out.append(line).append('\n');
                }
            }
            if (proc.waitFor(30, TimeUnit.SECONDS) && proc.exitValue() == 0) {
                // Output looks like: "ref: refs/heads/main\tHEAD"
                Matcher m = Pattern.compile("ref:\\s*refs/heads/(\\S+)\\s+HEAD")
                        .matcher(out.toString());
                if (m.find()) {
                    return m.group(1);
                }
            }
        } catch (Exception ex) {
            log.warn("resolveDefaultBranch: ls-remote --symref failed: {}", ex.getMessage());
        }

        // Fall back to trying common default-branch names in
        // order. The first one that exists wins.
        for (String candidate : List.of("main", "master", "2.x", "develop", "trunk")) {
            if (remoteBranchExists(targetDir, candidate)) {
                return candidate;
            }
        }
        // Absolute fallback: most legacy repos use master.
        return "master";
    }

    private boolean remoteBranchExists(Path targetDir, String branch) {
        try {
            ProcessBuilder pb = new ProcessBuilder(
                    "git", "ls-remote", "--heads", "origin", branch
            );
            pb.directory(targetDir.toFile());
            pb.environment().put("GIT_TERMINAL_PROMPT", "0");
            pb.environment().put("MSYS_NO_PATHCONV", "1");
            pb.environment().put("MSYS2_ARG_CONV_EXCL", "*");
            pb.redirectErrorStream(true);
            Process proc = pb.start();
            StringBuilder out = new StringBuilder();
            try (BufferedReader r = new BufferedReader(
                    new InputStreamReader(proc.getInputStream(), StandardCharsets.UTF_8))) {
                String line;
                while ((line = r.readLine()) != null) {
                    out.append(line).append('\n');
                }
            }
            return proc.waitFor(30, TimeUnit.SECONDS) && proc.exitValue() == 0
                    && out.toString().contains("refs/heads/" + branch);
        } catch (Exception ex) {
            return false;
        }
    }

    /**
     * Run a {@code git} subprocess inside {@code cwd} and
     * surface any non-zero exit as an exception. Used by
     * {@link #runSparseClone(String, String, Path, String)}
     * to break the clone into small, debuggable steps.
     */
    private void runGit(Path cwd, String... args) throws IOException, InterruptedException {
        ProcessBuilder pb = new ProcessBuilder("git");
        pb.directory(cwd.toFile());
        pb.command().addAll(Arrays.asList(args));
        pb.environment().put("GIT_TERMINAL_PROMPT", "0");
        pb.environment().put("MSYS_NO_PATHCONV", "1");
        pb.environment().put("MSYS2_ARG_CONV_EXCL", "*");
        pb.redirectErrorStream(true);
        pb.inheritIO();
        Process proc = pb.start();
        if (!proc.waitFor(120, TimeUnit.SECONDS)) {
            proc.destroyForcibly();
            throw new IllegalStateException("git " + args[0] + " timed out");
        }
        if (proc.exitValue() != 0) {
            throw new IllegalStateException("git " + args[0] + " failed exit=" + proc.exitValue());
        }
    }

    /**
     * Full-clone fallback. Kept for callers that need the
     * entire working tree (none right now — {@link
     * #scanModuleFs(Long, Long)} switched to
     * {@link #runSparseClone} to dodge Windows MAX_PATH on
     * monorepos with deep test trees), but useful as a
     * sanity-check helper when debugging clone issues.
     */
    private void runGitClone(String repoUrl, Path targetDir, String token) throws IOException, InterruptedException {
        Files.createDirectories(targetDir);
        String authenticatedUrl = repoUrl;
        if (token != null && !token.isBlank() && repoUrl.startsWith("https://github.com/")) {
            authenticatedUrl = repoUrl.replace("https://github.com/", "https://" + token + "@github.com/");
        }
        ProcessBuilder pb = new ProcessBuilder(
                "git", "clone",
                "--depth", "1",
                "--single-branch",
                "--quiet",
                "--config", "core.longpaths=true",
                authenticatedUrl,
                targetDir.toString()
        );
        pb.environment().put("MSYS_NO_PATHCONV", "1");
        pb.environment().put("MSYS2_ARG_CONV_EXCL", "*");
        pb.redirectErrorStream(true);
        pb.inheritIO();
        Process proc = pb.start();
        int cloneTimeoutSec = (int) Math.min(900, Math.max(60, timeoutSeconds / 2));
        boolean finished = proc.waitFor(cloneTimeoutSec, TimeUnit.SECONDS);
        if (!finished) {
            proc.destroyForcibly();
            throw new IllegalStateException("git clone timed out after " + cloneTimeoutSec + "s");
        }
        if (proc.exitValue() != 0) {
            throw new IllegalStateException("git clone failed with exit code " + proc.exitValue());
        }
        if (!Files.isDirectory(targetDir) || Files.list(targetDir).findAny().isEmpty()) {
            throw new IllegalStateException("git clone produced empty directory at " + targetDir);
        }
    }

    private String sha256Of(Path p) {
        try {
            byte[] bytes = Files.readAllBytes(p);
            java.security.MessageDigest md = java.security.MessageDigest.getInstance("SHA-256");
            return java.util.HexFormat.of().formatHex(md.digest(bytes));
        } catch (Exception ex) {
            return null;
        }
    }

    /**
     * Pick a temp directory whose absolute path is short enough
     * that {@code git} + {@code trivy fs} on Windows can check
     * out deeply-nested test files without tripping the 260-char
     * MAX_PATH limit. We try a handful of short roots first —
     * {@code F:\tmp\sbom-scanfs} (this project's home drive,
     * most likely to be set up), then {@code C:\tmp\sbom-scanfs},
     * {@code D:\tmp\sbom-scanfs}, … — and fall back to the JVM
     * default temp dir if none of them exist. Each call appends
     * a UUID so concurrent scans don't collide.
     */
    private Path createShortTempDir() throws IOException {
        boolean isWindows = System.getProperty("os.name", "").toLowerCase().contains("win");
        if (isWindows) {
            // Prefer F: (project's home drive) so the user only
            // has to create one directory on the drive they
            // already use.
            char[] driveLetters = new char[]{'F', 'C', 'D', 'E', 'G', 'H'};
            for (char drive : driveLetters) {
                String root = drive + ":\\tmp\\sbom-scanfs";
                File probe = new File(root);
                if (probe.isDirectory() && probe.canWrite()) {
                    File created = new File(probe, "fs-" + java.util.UUID.randomUUID());
                    if (created.mkdirs()) {
                        return created.toPath();
                    }
                }
            }
        }
        // Fallback (Linux/macOS, or Windows without any
        // F:\tmp\sbom-scanfs / C:\tmp\sbom-scanfs / ...).
        return Files.createTempDirectory("module_scan_fs_");
    }

    private String truncate(String s, int max) {
        if (s == null) return "";
        return s.length() <= max ? s : s.substring(0, max) + "…";
    }

    private void recordHistory(SbomFile sbom, String type, String note, String snapshotJson) {
        try {
            SbomFileHistory h = new SbomFileHistory();
            h.setSbomFileId(sbom.getId());
            h.setModuleId(sbom.getModuleId());
            h.setProjectId(moduleRepository.findById(sbom.getModuleId())
                    .map(Module::getProjectId).orElse(-1L));
            h.setChangeType(SbomFileHistory.ChangeType.valueOf(type));
            h.setScanStatus(sbom.getScanStatus() == null ? null : sbom.getScanStatus().name());
            h.setNote(note);
            h.setSnapshotJson(snapshotJson != null ? snapshotJson : serialize(sbom));
            sbomFileHistoryRepository.save(h);
        } catch (Exception ex) {
            log.warn("ModuleScanService: failed to record history for sbomId={}: {}",
                    sbom.getId(), ex.getMessage());
        }
    }

    private String serialize(SbomFile sbom) {
        try {
            return objectMapper.writeValueAsString(Map.of(
                    "id", sbom.getId(),
                    "moduleId", sbom.getModuleId(),
                    "fileName", sbom.getFileName(),
                    "sha256", sbom.getSha256() == null ? "" : sbom.getSha256(),
                    "sizeBytes", sbom.getSizeBytes() == null ? 0 : sbom.getSizeBytes(),
                    "source", sbom.getSource() == null ? "" : sbom.getSource(),
                    "scanStatus", sbom.getScanStatus() == null ? "" : sbom.getScanStatus().name()
            ));
        } catch (JsonProcessingException e) {
            return "{}";
        }
    }
}