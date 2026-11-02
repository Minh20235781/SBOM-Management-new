package com.example.sbom.service.scan;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;

@Service
public class TrivyScanService {
    private static final Logger log = LoggerFactory.getLogger(TrivyScanService.class);
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    @Value("${trivy.cache-dir:./trivy-cache}")
    private String cacheDirRoot;

    /**
     * Scan repo bằng Trivy và xuất CycloneDX SBOM
     * @param repoUrl URL GitHub repo
     * @return File SBOM CycloneDX
     */
    public File scanRepo(String repoUrl) throws IOException, InterruptedException {
        File tempDir = Files.createTempDirectory("trivy_scan_").toFile();
        File sbomFile = new File(tempDir, "sbom.json");
        File cacheRoot = new File(cacheDirRoot);
        if (!cacheRoot.exists() && !cacheRoot.mkdirs()) {
            log.warn("Failed to create Trivy cache root at {}", cacheRoot.getAbsolutePath());
        }
        File cacheDir = cacheRoot; // Dùng chung cache để không tải lại DB 130MB mỗi lần quét

        ProcessBuilder pb = new ProcessBuilder(
                "trivy", "repo",
                "--format", "cyclonedx",
                "--scanners", "vuln",
                "--offline-scan", // Tránh lỗi 429 Too Many Requests từ Maven Central
                "--timeout", "20m",
                "--skip-version-check",
                "-o", sbomFile.getAbsolutePath(),
                repoUrl
        );

        pb.redirectErrorStream(true);

        // Nếu env có GITHUB_TOKEN, truyền vào để scan repo private
        Map<String, String> env = pb.environment();
        env.put("TRIVY_CACHE_DIR", cacheDir.getAbsolutePath());
        String token = System.getenv("GITHUB_TOKEN");
        if (token != null && !token.isBlank()) {
            env.put("GITHUB_TOKEN", token);
            log.info("GITHUB_TOKEN found in environment — will pass to Trivy process.");
        }

        log.info("Using Trivy cache dir: {}", cacheDir.getAbsolutePath());

        pb.inheritIO(); // cho log in ra console (useful)
        log.info("Starting Trivy scan for repo: {}", repoUrl);
        Process p = pb.start();
        int exit = p.waitFor();
        if (exit != 0) {
            throw new RuntimeException("Trivy scan failed with exit code " + exit);
        }
        log.info("Trivy scan finished. SBOM at: {}", sbomFile.getAbsolutePath());
        return sbomFile;
    }

    public TrivyScanResult scanRepoMerged(String repoPathOrUrl) throws IOException, InterruptedException {
        File repoPath = new File(repoPathOrUrl);
        if (repoPath.exists() && repoPath.isDirectory()) {
            return scanLocalRepository(repoPath);
        }

        File sbomFile = scanRepo(repoPathOrUrl);
        return parseCycloneDx(sbomFile);
    }

    private TrivyScanResult scanLocalRepository(File repoRoot) throws IOException, InterruptedException {
        File tempDir = Files.createTempDirectory("trivy_scan_merged_").toFile();
        File cacheRoot = new File(cacheDirRoot);
        if (!cacheRoot.exists() && !cacheRoot.mkdirs()) {
            log.warn("Failed to create Trivy cache root at {}", cacheRoot.getAbsolutePath());
        }
        File cacheDir = cacheRoot;

        Set<File> scanRoots = detectScanRoots(repoRoot);
        Map<String, String> mergedComponents = new LinkedHashMap<>();
        Map<String, Integer> ecosystemCounts = new LinkedHashMap<>();
        Set<String> purlEcosystems = new LinkedHashSet<>();
        Map<String, String> componentEcosystems = new LinkedHashMap<>();

        for (File scanRoot : scanRoots) {
            File out = new File(tempDir, sanitize(scanRoot.getAbsolutePath()) + ".json");
            ProcessBuilder pb = new ProcessBuilder(
                    "trivy", "fs",
                    "--format", "cyclonedx",
                    "--scanners", "vuln",
                    "--offline-scan",
                    "--timeout", "20m",
                    "--skip-version-check",
                    "-o", out.getAbsolutePath(),
                    scanRoot.getAbsolutePath()
            );
            prepareEnvironment(pb, cacheDir);
            log.info("Starting Trivy filesystem scan: {}", scanRoot.getAbsolutePath());
            int exit = runProcess(pb);
            if (exit != 0) {
                log.warn("Trivy scan failed for {} with exit code {}", scanRoot.getAbsolutePath(), exit);
                continue;
            }

            TrivyScanResult partial = parseCycloneDx(out);
            mergeComponents(mergedComponents, ecosystemCounts, purlEcosystems, componentEcosystems, partial);
        }

        File mergedOut = new File(tempDir, "merged_sbom.json");
        writeMergedCycloneDx(mergedOut, mergedComponents);
        return new TrivyScanResult(mergedComponents, ecosystemCounts, purlEcosystems, componentEcosystems, mergedOut);
    }

    private Set<File> detectScanRoots(File repoRoot) throws IOException {
        Set<File> roots = new LinkedHashSet<>();
        roots.add(repoRoot);

        Files.walk(repoRoot.toPath(), 5)
                .filter(path -> isModuleBoundary(path.getFileName() == null ? "" : path.getFileName().toString()))
                .map(Path::getParent)
                .filter(Objects::nonNull)
                .map(Path::toFile)
                .filter(File::isDirectory)
                .forEach(roots::add);

        return roots;
    }

    private boolean isModuleBoundary(String fileName) {
        String lower = fileName.toLowerCase(Locale.ROOT);
        return lower.equals("pom.xml")
                || lower.equals("package.json")
                || lower.equals("package-lock.json")
                || lower.equals("pnpm-lock.yaml")
                || lower.equals("yarn.lock")
                || lower.equals("requirements.txt")
                || lower.equals("pyproject.toml")
                || lower.equals("build.gradle")
                || lower.equals("build.gradle.kts");
    }

    private void prepareEnvironment(ProcessBuilder pb, File cacheDir) {
        Map<String, String> env = pb.environment();
        env.put("TRIVY_CACHE_DIR", cacheDir.getAbsolutePath());
        String token = System.getenv("GITHUB_TOKEN");
        if (token != null && !token.isBlank()) {
            env.put("GITHUB_TOKEN", token);
            log.info("GITHUB_TOKEN found in environment — will pass to Trivy process.");
        }
    }

    private int runProcess(ProcessBuilder pb) throws IOException, InterruptedException {
        pb.redirectErrorStream(true);
        Process process = pb.start();
        return process.waitFor();
    }

    private TrivyScanResult parseCycloneDx(File sbomFile) throws IOException {
        Map<String, String> components = new LinkedHashMap<>();
        Map<String, Integer> ecosystemCounts = new LinkedHashMap<>();
        Set<String> purlEcosystems = new LinkedHashSet<>();
        Map<String, String> componentEcosystems = new LinkedHashMap<>();

        JsonNode root = OBJECT_MAPPER.readTree(sbomFile);
        JsonNode items = root.path("components");
        if (items.isArray()) {
            for (JsonNode component : items) {
                String name = textValue(component, "name");
                String version = textValue(component, "version");
                String purl = textValue(component, "purl");
                if (name == null || name.isBlank()) {
                    name = purl;
                }
                if (name == null || name.isBlank() || isInvalidComponent(name, purl, version)) {
                    continue;
                }
                String existing = components.get(name);
                if (existing == null || compareVersions(version, existing) > 0) {
                    components.put(name, version);
                }
                String ecosystem = extractEcosystem(purl, name);
                if (ecosystem != null) {
                    purlEcosystems.add(ecosystem);
                    ecosystemCounts.merge(ecosystem, 1, Integer::sum);
                    componentEcosystems.put(name, ecosystem);
                }
            }
        }

        return new TrivyScanResult(components, ecosystemCounts, purlEcosystems, componentEcosystems, sbomFile);
    }

    private void mergeComponents(Map<String, String> mergedComponents,
                                 Map<String, Integer> ecosystemCounts,
                                 Set<String> purlEcosystems,
                                 Map<String, String> componentEcosystems,
                                 TrivyScanResult partial) {
        if (partial == null) return;
        partial.getComponents().forEach((name, version) -> {
            String existing = mergedComponents.get(name);
            if (existing == null || compareVersions(version, existing) > 0) {
                mergedComponents.put(name, version);
            }
        });
        partial.getComponentEcosystems().forEach((name, ecosystem) ->
                componentEcosystems.putIfAbsent(name, ecosystem));
        partial.getEcosystemCounts().forEach((ecosystem, count) ->
                ecosystemCounts.merge(ecosystem, count, Integer::sum));
        purlEcosystems.addAll(partial.getPurlEcosystems());
    }

    private void writeMergedCycloneDx(File output, Map<String, String> components) throws IOException {
        com.fasterxml.jackson.databind.node.ObjectNode root = OBJECT_MAPPER.createObjectNode();
        com.fasterxml.jackson.databind.node.ArrayNode array = root.putArray("components");
        for (Map.Entry<String, String> entry : components.entrySet()) {
            com.fasterxml.jackson.databind.node.ObjectNode node = array.addObject();
            node.put("name", entry.getKey());
            if (entry.getValue() != null) {
                node.put("version", entry.getValue());
            }
        }
        try (FileWriter writer = new FileWriter(output, StandardCharsets.UTF_8)) {
            writer.write(root.toString());
        }
    }

    private boolean isInvalidComponent(String name, String purl, String version) {
        String value = ((name == null ? "" : name) + " " + (purl == null ? "" : purl)).toLowerCase(Locale.ROOT);
        return value.contains("pom.xml")
                || value.contains("/pom.xml")
                || value.contains(":pom:")
                || value.contains("type:pom")
                || value.contains("classifier:pom")
                || value.contains("metadata")
                || version == null || version.isBlank();
    }

    private String extractEcosystem(String purl, String fallbackName) {
        String value = purl == null ? "" : purl.toLowerCase(Locale.ROOT);
        if (value.startsWith("pkg:maven")) return "maven";
        if (value.startsWith("pkg:npm")) return "npm";
        if (value.startsWith("pkg:pypi")) return "pypi";
        if (value.startsWith("pkg:nuget")) return "nuget";
        if (value.startsWith("pkg:gem")) return "gem";
        if (value.startsWith("pkg:golang")) return "golang";
        if (value.startsWith("pkg:deb") || value.startsWith("pkg:rpm") || value.startsWith("pkg:apk")) return "native";
        if (fallbackName != null && fallbackName.toLowerCase(Locale.ROOT).contains("node_modules")) return "npm";
        return "unknown";
    }

    private String textValue(JsonNode node, String field) {
        JsonNode value = node.get(field);
        return value == null || value.isNull() ? null : value.asText(null);
    }

    private String sanitize(String input) {
        return input.replaceAll("[^a-zA-Z0-9._-]", "_");
    }

    private int compareVersions(String v1, String v2) {
        if (v1 == null && v2 == null) return 0;
        if (v1 == null) return -1;
        if (v2 == null) return 1;
        String[] a = v1.split("\\.");
        String[] b = v2.split("\\.");
        int len = Math.max(a.length, b.length);
        for (int i = 0; i < len; i++) {
            int ai = i < a.length ? parseLeadingInt(a[i]) : 0;
            int bi = i < b.length ? parseLeadingInt(b[i]) : 0;
            if (ai != bi) return Integer.compare(ai, bi);
        }
        return v1.compareTo(v2);
    }

    private int parseLeadingInt(String s) {
        if (s == null) return 0;
        String num = s.replaceAll("\\D", "");
        if (num.isEmpty()) return 0;
        try {
            return Integer.parseInt(num);
        } catch (NumberFormatException ex) {
            return 0;
        }
    }
}
