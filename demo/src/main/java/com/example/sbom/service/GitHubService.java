package com.example.sbom.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.annotation.PostConstruct;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpEntity;
import org.springframework.http.ResponseEntity;
import org.springframework.http.client.SimpleClientHttpRequestFactory;
import org.springframework.stereotype.Service;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Talks to the public GitHub REST API to discover the structure
 * of a project repo: list of source files, recent commits, etc.
 *
 * Used by the module auto-detect flow on the project detail
 * page (no manual form-fill required) and the "recent commits"
 * card that lets the user spot upstream changes since the
 * last scan.
 *
 * For private repos we attach a Bearer token from the
 * {@code GITHUB_TOKEN} environment variable. Unauthenticated
 * requests work for public repos at a 60 req/h rate limit.
 */
@Service
public class GitHubService {

    private static final Logger log = LoggerFactory.getLogger(GitHubService.class);

    private static final String API_BASE = "https://api.github.com";
    private static final Pattern URL_PATTERN = Pattern.compile(
            "https?://github\\.com/([\\w.-]+)/([\\w.-]+?)(?:\\.git)?/?(?:\\?.*)?(?:#.*)?$",
            Pattern.CASE_INSENSITIVE);

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Value("${github.api-base:https://api.github.com}")
    private String apiBase;

    @Value("${github.connect-timeout-ms:4000}")
    private int connectTimeoutMs;

    @Value("${github.read-timeout-ms:8000}")
    private int readTimeoutMs;

    private final RestTemplate restTemplate = new RestTemplate();
    private final String token = System.getenv("GITHUB_TOKEN");

    @PostConstruct
    public void configureTimeouts() {
        SimpleClientHttpRequestFactory factory = new SimpleClientHttpRequestFactory();
        factory.setConnectTimeout(connectTimeoutMs);
        factory.setReadTimeout(readTimeoutMs);
        restTemplate.setRequestFactory(factory);
    }

    /** Result of an auto-detect sweep. {@code error} is non-null
     *  when the upstream call failed; {@code modules} may still
     *  be partially populated from a fallback. */
    public record DetectedModule(
            String name,
            String pathInRepo,
            String buildFile,
            String declaredInParent) {
        public DetectedModule(String name, String pathInRepo, String buildFile) {
            this(name, pathInRepo, buildFile, null);
        }
    }

    public record DetectResult(
            String owner,
            String repo,
            String defaultBranch,
            String buildSystem,
            List<DetectedModule> modules,
            String error) {
        public boolean isEmpty() {
            return modules == null || modules.isEmpty();
        }
    }

    public record CommitInfo(
            String sha,
            String shortSha,
            String message,
            String author,
            String date,
            String url,
            int additions,
            int deletions,
            int totalChanges,
            List<FileChange> tree) {
    }

    /**
     * Commit enriched with project-local state derived from the
     * latest risk snapshot + vuln diff, plus a heuristic guess
     * at whether the commit is likely to change the dependency
     * list (based on the files in its tree):
     * <ul>
     *   <li>{@code state = "new"} — commit landed after the most
     *       recent scan AND its file tree touches a dependency
     *       manifest. A re-scan may surface new vulns or fixes.</li>
     *   <li>{@code state = "no-impact"} (inferred) — commit is
     *       newer than the latest scan but its file tree doesn't
     *       touch any dependency manifest (CI workflow bumps,
     *       source refactors, doc changes, test-only edits). A
     *       re-scan is unlikely to change anything.</li>
     *   <li>{@code state = "scanned-with-impact"} — the latest scan
     *       that covered this commit produced NEW / FIXED / REOPENED
     *       vuln rows, so re-scanning again may be useful.</li>
     *   <li>{@code state = "no-impact"} (verified) — the latest scan
     *       that covered this commit changed nothing in the vuln diff.</li>
     * </ul>
     * The UI uses this to suppress the "Re-scan" button on no-impact
     * commits and to show a small badge describing what changed.
     * {@code likelyNoImpact} is the underlying heuristic — true for
     * the two no-impact states, false otherwise.
     */
    public record CommitWithState(
            CommitInfo commit,
            String state,
            String impactSummary,
            boolean likelyNoImpact) {

        public static CommitWithState newCommit(CommitInfo c) {
            return new CommitWithState(c, "new", null, false);
        }

        public static CommitWithState scannedWithImpact(CommitInfo c, String summary) {
            return new CommitWithState(c, "scanned-with-impact", summary, false);
        }

        /** "no-impact" inferred from the file tree (commit not yet scanned
         *  but unlikely to change dependency manifest). */
        public static CommitWithState noImpactInferred(CommitInfo c) {
            return new CommitWithState(c, "no-impact",
                    "File diff has no dependency manifest — re-scan unlikely to change vulns",
                    true);
        }

        /** "no-impact" verified by the latest scan (diff was empty). */
        public static CommitWithState noImpactVerified(CommitInfo c) {
            return new CommitWithState(c, "no-impact",
                    "Re-scan produced no NEW/FIXED/REOPENED rows",
                    true);
        }
    }

    /**
     * Filenames (case-insensitive, base name only) that indicate a
     * commit is likely to affect the dependency manifest. Used by
     * {@link #isLikelyDependencyAffecting(CommitInfo)} to short-circuit
     * "New" commits whose file tree is purely CI / source / docs.
     */
    private static final java.util.Set<String> DEPENDENCY_MANIFEST_NAMES = java.util.Set.of(
            // Java / JVM
            "pom.xml", "build.gradle", "build.gradle.kts", "settings.gradle",
            "build.xml", "ivy.xml",
            // JavaScript / Node
            "package.json", "package-lock.json", "pnpm-lock.yaml", "yarn.lock",
            "bun.lockb",
            // Python
            "requirements.txt", "pyproject.toml", "setup.py", "setup.cfg",
            "pipfile", "pipfile.lock", "poetry.lock",
            // Go
            "go.mod", "go.sum",
            // Rust
            "cargo.toml", "cargo.lock",
            // PHP
            "composer.json", "composer.lock",
            // Ruby
            "gemfile", "gemfile.lock",
            // Erlang / Elixir
            "mix.exs", "rebar.config",
            // Dart / Flutter
            "pubspec.yaml", "pubspec.lock"
    );

    /**
     * Heuristic: does this commit's file tree touch any dependency
     * manifest file? If yes, a re-scan is potentially worth running.
     * If no, the commit is purely CI / source / test / docs and a
     * re-scan is almost certainly going to produce the same SBOM.
     */
    public static boolean isLikelyDependencyAffecting(CommitInfo c) {
        if (c == null || c.tree() == null || c.tree().isEmpty()) {
            return false;
        }
        for (FileChange f : c.tree()) {
            String name = f.filename();
            if (name == null || name.isBlank()) continue;
            int slash = name.lastIndexOf('/');
            String base = slash >= 0 ? name.substring(slash + 1) : name;
            if (DEPENDENCY_MANIFEST_NAMES.contains(base.toLowerCase())) {
                return true;
            }
        }
        return false;
    }

    /**
     * Single file change within a commit, mapped from
     * GitHub's commits API {@code files} array. Used by the
     * UI to render a per-commit file tree.
     */
    public record FileChange(
            String filename,
            String status,
            int additions,
            int deletions,
            int changes) {
    }

    /**
     * Extract {@code owner/repo} from a project description like
     * "Auto-created from Trivy scan of https://github.com/apache/logging-log4j2.git".
     * Returns empty if the description doesn't carry a GitHub URL.
     */
    public Optional<String[]> extractOwnerRepo(String description) {
        if (description == null) return Optional.empty();
        Matcher m = URL_PATTERN.matcher(description.trim());
        if (!m.find()) return Optional.empty();
        return Optional.of(new String[]{m.group(1), m.group(2)});
    }

    /**
     * Detect logical modules in a repo by listing its files
     * and looking for build manifests ({@code pom.xml},
     * {@code package.json}, {@code go.mod}). For Maven repos
     * the parent {@code pom.xml} is parsed for its explicit
     * {@code <modules>} declaration so we report the
     * author-defined list rather than every directory with
     * a stray pom.xml.
     */
    public DetectResult detectModules(String description) {
        Optional<String[]> ownerRepo = extractOwnerRepo(description);
        if (ownerRepo.isEmpty()) {
            return new DetectResult(null, null, null, "unknown",
                    Collections.emptyList(),
                    "Project description doesn't contain a GitHub URL");
        }
        String owner = ownerRepo.get()[0];
        String repo = ownerRepo.get()[1];

        // 1. Resolve the default branch. If this fails the
        // caller still gets a populated error field.
        String defaultBranch;
        try {
            defaultBranch = getDefaultBranch(owner, repo);
        } catch (Exception ex) {
            log.warn("detectModules: failed to resolve default branch for {}/{}: {}",
                    owner, repo, ex.getMessage());
            return new DetectResult(owner, repo, null, "unknown",
                    Collections.emptyList(),
                    "Could not reach GitHub: " + ex.getMessage());
        }

        // 2. Pull the recursive tree so we get every path in
        // one call. Falls back to top-level if the repo is
        // large enough that GitHub truncates the tree.
        List<String> paths;
        try {
            paths = getRepoTree(owner, repo, defaultBranch);
        } catch (Exception ex) {
            log.warn("detectModules: tree fetch failed for {}/{}: {}",
                    owner, repo, ex.getMessage());
            return new DetectResult(owner, repo, defaultBranch, "unknown",
                    Collections.emptyList(),
                    "GitHub tree fetch failed: " + ex.getMessage());
        }

        // 3. Decide build system from file presence.
        String buildSystem = "unknown";
        boolean hasPom = paths.stream().anyMatch(p -> p.endsWith("/pom.xml") || p.equals("pom.xml"));
        boolean hasPackageJson = paths.stream().anyMatch(p -> p.endsWith("/package.json") || p.equals("package.json"));
        boolean hasGoMod = paths.stream().anyMatch(p -> p.endsWith("/go.mod") || p.equals("go.mod"));
        if (hasPom) buildSystem = "maven";
        else if (hasPackageJson) buildSystem = "npm";
        else if (hasGoMod) buildSystem = "go";

        // 4. Try to read the parent pom's <modules> list for
        // the canonical module names. If that fails, fall
        // back to scanning every path that contains a
        // manifest file.
        List<DetectedModule> modules = new ArrayList<>();
        if ("maven".equals(buildSystem)) {
            modules = detectMavenModules(owner, repo, defaultBranch, paths);
        } else if ("npm".equals(buildSystem)) {
            modules = detectNpmModules(owner, repo, defaultBranch, paths);
        } else if ("go".equals(buildSystem)) {
            modules = detectGoModules(owner, repo, defaultBranch, paths);
        }

        return new DetectResult(owner, repo, defaultBranch, buildSystem, modules, null);
    }

    /** Fetch the default branch name for a repo. */
    public String getDefaultBranch(String owner, String repo) {
        JsonNode root = getJson("/repos/" + owner + "/" + repo);
        JsonNode branch = root.get("default_branch");
        if (branch == null || branch.asText().isBlank()) {
            throw new IllegalStateException("No default_branch in GitHub response");
        }
        return branch.asText();
    }

    /**
     * Fetch the N most recent commits, with a per-commit file
     * tree (added/modified/deleted files + +/- line counts).
     *
     * GitHub returns commits without file details on the list
     * endpoint, so we make one extra call per commit to
     * {@code /repos/{owner}/{repo}/commits/{sha}} for the
     * file tree. The auth-token path (env {@code GITHUB_TOKEN})
     * gets 5000 req/h, so even 20 commits × 2 calls is fine;
     * anonymous callers hit 60 req/h quickly.
     *
     * Returns an empty list (with a logged warning) on failure
     * so the UI can show "no data" without a 5xx.
     */
    public List<CommitInfo> listCommits(String description, int limit) {
        Optional<String[]> ownerRepo = extractOwnerRepo(description);
        if (ownerRepo.isEmpty()) return Collections.emptyList();
        String owner = ownerRepo.get()[0];
        String repo = ownerRepo.get()[1];

        try {
            String branch = getDefaultBranch(owner, repo);
            int clampedLimit = Math.max(1, Math.min(limit, 10));
            JsonNode arr = getJsonArray(
                    "/repos/" + owner + "/" + repo + "/commits"
                            + "?per_page=" + clampedLimit
                            + "&sha=" + branch);
            List<CommitInfo> commits = new ArrayList<>();
            for (JsonNode c : arr) {
                String sha = c.path("sha").asText("");
                if (sha.isEmpty()) continue;
                String message = c.path("commit").path("message").asText("");
                String author = c.path("commit").path("author").path("name").asText("");
                String date = c.path("commit").path("author").path("date").asText("");
                String url = c.path("html_url").asText("");

                List<FileChange> tree = fetchCommitFileTree(owner, repo, sha);
                int adds = 0, dels = 0, total = 0;
                for (FileChange f : tree) {
                    adds += f.additions();
                    dels += f.deletions();
                    total += f.changes();
                }
                commits.add(new CommitInfo(
                        sha,
                        sha.length() > 7 ? sha.substring(0, 7) : sha,
                        firstLine(message),
                        author,
                        date,
                        url,
                        adds,
                        dels,
                        total,
                        tree));
            }
            return commits;
        } catch (Exception ex) {
            log.warn("listCommits: failed for {}/{}: {}", owner, repo, ex.getMessage());
            return Collections.emptyList();
        }
    }

    /**
     * Fetch the file list for a single commit. Each
     * {@code files[].filename/status/additions/deletions/changes}
     * becomes a {@link FileChange}. The list is sorted by
     * total change count desc so the biggest files in the
     * commit surface first in the UI.
     */
    private List<FileChange> fetchCommitFileTree(String owner, String repo, String sha) {
        try {
            JsonNode root = getJson(
                    "/repos/" + owner + "/" + repo + "/commits/" + sha);
            JsonNode files = root.get("files");
            if (files == null || !files.isArray()) return Collections.emptyList();
            List<FileChange> out = new ArrayList<>();
            for (JsonNode f : files) {
                String filename = f.path("filename").asText("");
                if (filename.isEmpty()) continue;
                out.add(new FileChange(
                        filename,
                        f.path("status").asText("modified"),
                        f.path("additions").asInt(0),
                        f.path("deletions").asInt(0),
                        f.path("changes").asInt(0)));
            }
            out.sort((a, b) -> Integer.compare(b.changes(), a.changes()));
            return out;
        } catch (Exception ex) {
            // A single commit's file tree failing shouldn't
            // blank the whole list — log and return empty.
            log.warn("fetchCommitFileTree: failed for {}/{}@{}: {}",
                    owner, repo, sha.substring(0, Math.min(7, sha.length())), ex.getMessage());
            return Collections.emptyList();
        }
    }

    // ---------- internals ----------

    private List<DetectedModule> detectMavenModules(String owner, String repo, String branch, List<String> paths) {
        // Try the parent pom.xml at repo root first. The
        // <modules> section is the author-defined list and
        // matches what `mvn -pl` would treat as subprojects.
        try {
            String rootPom = fetchRawFile(owner, repo, branch, "pom.xml");
            if (rootPom != null) {
                List<String> declared = parseMavenModules(rootPom);
                if (!declared.isEmpty()) {
                    List<DetectedModule> out = new ArrayList<>();
                    for (String name : declared) {
                        out.add(new DetectedModule(name, name, "pom.xml", "root"));
                    }
                    return out;
                }
            }
        } catch (Exception ex) {
            log.warn("detectMavenModules: root pom fetch failed: {}", ex.getMessage());
        }
        // Fallback: every directory with its own pom.xml.
        return collectByManifest(paths, "pom.xml", "");
    }

    private List<DetectedModule> detectNpmModules(String owner, String repo, String branch, List<String> paths) {
        // Try root package.json for the "workspaces" list
        // (yarn / pnpm). If absent, scan every package.json.
        try {
            String rootPkg = fetchRawFile(owner, repo, branch, "package.json");
            if (rootPkg != null) {
                JsonNode root = objectMapper.readTree(rootPkg);
                List<String> declared = new ArrayList<>();
                JsonNode workspaces = root.path("workspaces");
                if (workspaces.isArray()) {
                    for (JsonNode w : workspaces) declared.add(w.asText());
                } else if (workspaces.isObject()) {
                    JsonNode pkgs = workspaces.path("packages");
                    if (pkgs.isArray()) {
                        for (JsonNode w : pkgs) declared.add(w.asText());
                    }
                }
                if (!declared.isEmpty()) {
                    List<DetectedModule> out = new ArrayList<>();
                    for (String path : declared) {
                        String trimmed = path.replaceAll("/\\*$", "").replaceAll("/$", "");
                        String name = trimmed.isEmpty() ? "root" : trimmed;
                        out.add(new DetectedModule(name, trimmed, "package.json", "root"));
                    }
                    return out;
                }
            }
        } catch (Exception ex) {
            log.warn("detectNpmModules: root package.json fetch failed: {}", ex.getMessage());
        }
        return collectByManifest(paths, "package.json", "node_modules/");
    }

    private List<DetectedModule> detectGoModules(String owner, String repo, String branch, List<String> paths) {
        // Go rarely has multi-module repos; we just report
        // the root go.mod so the UI can show "go build system"
        // and not look empty.
        if (paths.contains("go.mod") || paths.contains("/go.mod")) {
            return List.of(new DetectedModule("root", "", "go.mod", null));
        }
        return Collections.emptyList();
    }

    private List<DetectedModule> collectByManifest(List<String> paths, String manifest, String skipPrefix) {
        List<DetectedModule> out = new ArrayList<>();
        for (String p : paths) {
            if (skipPrefix != null && !skipPrefix.isEmpty() && p.contains(skipPrefix)) continue;
            if (!(p.endsWith("/" + manifest) || p.equals(manifest))) continue;
            // Skip build wrapper duplicates: skip /target/,
            // /build/, /dist/ etc.
            if (p.contains("/target/") || p.contains("/build/") || p.contains("/dist/")) continue;
            String dir = p.equals(manifest) ? "" : p.substring(0, p.length() - manifest.length() - 1);
            String name = dir.isEmpty() ? "root" : dir;
            out.add(new DetectedModule(name, dir, manifest));
        }
        return out;
    }

    /** Parse {@code <modules><module>foo</module>...</modules>}. */
    private List<String> parseMavenModules(String pomXml) {
        List<String> modules = new ArrayList<>();
        // Cheap regex; good enough for typical pom.xml where
        // the <modules> block sits near the top and doesn't
        // contain any <module> with attributes.
        Matcher m = Pattern.compile(
                "<modules[^>]*>(.*?)</modules>",
                Pattern.DOTALL | Pattern.CASE_INSENSITIVE).matcher(pomXml);
        if (!m.find()) return modules;
        String block = m.group(1);
        Matcher mod = Pattern.compile(
                "<module\\s*>([^<]+)</module\\s*>",
                Pattern.CASE_INSENSITIVE).matcher(block);
        while (mod.find()) {
            String name = mod.group(1).trim();
            if (!name.isEmpty()) modules.add(name);
        }
        return modules;
    }

    private List<String> getRepoTree(String owner, String repo, String branch) {
        // Use the recursive=1 variant of git/trees; that
        // returns every blob path in one call without
        // hitting the contents API N times.
        JsonNode root = getJson(
                "/repos/" + owner + "/" + repo
                        + "/git/trees/" + branch + "?recursive=1");
        List<String> paths = new ArrayList<>();
        JsonNode tree = root.get("tree");
        if (tree != null && tree.isArray()) {
            for (JsonNode node : tree) {
                String type = node.path("type").asText("");
                if (!"blob".equals(type)) continue;
                String path = node.path("path").asText("");
                if (!path.isEmpty()) paths.add(path);
            }
        }
        return paths;
    }

    private String fetchRawFile(String owner, String repo, String branch, String path) {
        URI uri = URI.create(apiBase + "/repos/" + owner + "/" + repo
                + "/contents/" + path + "?ref=" + branch);
        HttpHeaders headers = authHeaders();
        headers.set("Accept", "application/vnd.github.raw");
        try {
            ResponseEntity<byte[]> resp = restTemplate.exchange(
                    uri, HttpMethod.GET, new HttpEntity<>(headers), byte[].class);
            if (resp.getBody() == null) return null;
            return new String(resp.getBody(), StandardCharsets.UTF_8);
        } catch (HttpClientErrorException.NotFound nf) {
            return null;
        } catch (RestClientException ex) {
            log.warn("fetchRawFile: {} -> {}", uri, ex.getMessage());
            throw ex;
        }
    }

    private JsonNode getJson(String path) {
        HttpHeaders headers = authHeaders();
        headers.set("Accept", "application/vnd.github+json");
        ResponseEntity<String> resp = restTemplate.exchange(
                apiBase + path, HttpMethod.GET, new HttpEntity<>(headers), String.class);
        try {
            return objectMapper.readTree(resp.getBody());
        } catch (Exception ex) {
            throw new IllegalStateException("GitHub returned non-JSON: " + ex.getMessage(), ex);
        }
    }

    private JsonNode getJsonArray(String path) {
        HttpHeaders headers = authHeaders();
        headers.set("Accept", "application/vnd.github+json");
        ResponseEntity<String> resp = restTemplate.exchange(
                apiBase + path, HttpMethod.GET, new HttpEntity<>(headers), String.class);
        try {
            return objectMapper.readTree(resp.getBody());
        } catch (Exception ex) {
            throw new IllegalStateException("GitHub returned non-JSON: " + ex.getMessage(), ex);
        }
    }

    private HttpHeaders authHeaders() {
        HttpHeaders headers = new HttpHeaders();
        headers.set("User-Agent", "sbom-dashboard");
        headers.set("X-GitHub-Api-Version", "2022-11-28");
        if (token != null && !token.isBlank()) {
            headers.set("Authorization", "Bearer " + token);
        }
        return headers;
    }

    private static String firstLine(String s) {
        if (s == null) return "";
        int nl = s.indexOf('\n');
        return nl < 0 ? s.trim() : s.substring(0, nl).trim();
    }

    // Exposed for tests / debugging; currently unused at runtime.
    Map<String, Integer> debugCounts() {
        return Map.of("cached", 0);
    }

    public String tokenSource() {
        return token == null || token.isBlank() ? "anonymous" : "env:github_token";
    }

    @SuppressWarnings("unused")
    private static String lower(String s) {
        return s == null ? null : s.toLowerCase(Locale.ROOT);
    }
}
