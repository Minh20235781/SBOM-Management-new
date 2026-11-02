package com.example.sbom.service.validation;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Comparator;
import java.util.LinkedHashMap;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Service
public class MavenDependencyResolutionService {

    private static final Logger log = LoggerFactory.getLogger(MavenDependencyResolutionService.class);
    private static final Pattern DIGRAPH_PATTERN = Pattern.compile("^digraph\\s+\"(.+)\"\\s*\\{");
    private static final Pattern EDGE_PATTERN = Pattern.compile("\"([^\"]+)\"\\s*->\\s*\"([^\"]+)\"");
    private static final long TIMEOUT_SECONDS = 120;
    private static final int OUTPUT_LIMIT = 20000;

    public MavenDependencyResolutionResult resolveDependencyTree(String repoPath, String repoName) {
        File repoRoot = resolveRepoRoot(repoPath, repoName);
        if (repoRoot == null) {
            return fallbackResult("repo_root_not_found");
        }

        List<File> pomFiles = findPomFiles(repoRoot);
        if (pomFiles.isEmpty()) {
            return fallbackResult("pom_not_found");
        }

        Map<String, String> declaredDependencies = new LinkedHashMap<>();
        Map<String, String> resolvedRuntimeDependencies = new LinkedHashMap<>();
        Set<String> directDeclaredDependencies = new LinkedHashSet<>();
        Set<String> resolvedRuntimeDirectDependencies = new LinkedHashSet<>();
        boolean runtimeFallbackUsed = false;
        String runtimeFallbackReason = null;

        for (File pomFile : pomFiles) {
            Map<String, String> declaredForModule = extractDeclaredDependencies(pomFile);
            mergeDependencies(declaredDependencies, declaredForModule);
            directDeclaredDependencies.addAll(declaredForModule.keySet());
        }

        for (File pomFile : pomFiles) {
            RuntimeParseResult runtime = runDependencyTree(pomFile.getParentFile());
            if (!runtime.success) {
                runtimeFallbackUsed = true;
                if (runtimeFallbackReason == null) {
                    runtimeFallbackReason = runtime.reason;
                }
                continue;
            }
            mergeDependencies(resolvedRuntimeDependencies, runtime.dependencies);
            resolvedRuntimeDirectDependencies.addAll(runtime.directDependencies);
        }

        if (resolvedRuntimeDependencies.isEmpty()) {
            runtimeFallbackUsed = true;
            if (runtimeFallbackReason == null) {
                runtimeFallbackReason = "empty_dependency_tree";
            }
        }

        log.info(
                "Maven dependency resolution finished: repoRoot={}, moduleCount={}, declaredCount={}, resolvedRuntimeCount={}, runtimeFallbackUsed={}, runtimeFallbackReason={}",
                repoRoot.getAbsolutePath(), pomFiles.size(), declaredDependencies.size(), resolvedRuntimeDependencies.size(),
                runtimeFallbackUsed, runtimeFallbackReason
        );

        return new MavenDependencyResolutionResult(
                declaredDependencies,
                resolvedRuntimeDependencies,
                directDeclaredDependencies,
                resolvedRuntimeDirectDependencies,
                pomFiles.size(),
                runtimeFallbackUsed,
                runtimeFallbackReason
        );
    }

    public Map<String, String> resolveDeclaredDependencies(String repoPath, String repoName) {
        return resolveDependencyTree(repoPath, repoName).getDeclaredDependencies();
    }

    public Map<String, String> resolveRuntimeDependencies(String repoPath, String repoName) {
        return resolveDependencyTree(repoPath, repoName).getResolvedRuntimeDependencies();
    }

    private Map<String, String> extractDeclaredDependencies(File pomFile) {
        Map<String, String> result = new LinkedHashMap<>();
        if (pomFile == null || !pomFile.exists()) {
            return result;
        }

        try {
            DocumentBuilderFactory factory = secureDocumentFactory();
            DocumentBuilder builder = factory.newDocumentBuilder();
            Document document = builder.parse(pomFile);
            Element project = document.getDocumentElement();

            NodeList childNodes = project.getChildNodes();
            for (int i = 0; i < childNodes.getLength(); i++) {
                Node child = childNodes.item(i);
                if (!(child instanceof Element childElement)) {
                    continue;
                }
                if (!"dependencies".equals(childElement.getTagName())) {
                    continue;
                }

                NodeList dependencies = childElement.getChildNodes();
                for (int j = 0; j < dependencies.getLength(); j++) {
                    Node dependencyNode = dependencies.item(j);
                    if (!(dependencyNode instanceof Element dependency)) {
                        continue;
                    }
                    if (!"dependency".equals(dependency.getTagName())) {
                        continue;
                    }

                    String artifactId = text(dependency, "artifactId");
                    String groupId = text(dependency, "groupId");
                    String scope = text(dependency, "scope");
                    String type = text(dependency, "type");
                    String version = text(dependency, "version");

                    if (artifactId == null || artifactId.isBlank()) {
                        continue;
                    }
                    if (scope != null && scope.equalsIgnoreCase("test")) {
                        continue;
                    }
                    if (scope != null && scope.equalsIgnoreCase("import")) {
                        continue;
                    }
                    if (type != null && type.equalsIgnoreCase("pom")) {
                        continue;
                    }

                    String key = normalizeKey(groupId, artifactId);
                    String existing = result.get(key);
                    if (existing == null || compareVersions(version, existing) > 0) {
                        result.put(key, version);
                    }
                }
            }
        } catch (Exception ex) {
            log.warn("Failed to parse declared dependencies from {}: {}", pomFile.getAbsolutePath(), ex.getMessage());
        }

        return result;
    }

    private RuntimeParseResult runDependencyTree(File moduleDir) {
        File outputFile = null;
        String pomXmlPath = new File(moduleDir, "pom.xml").getAbsolutePath();

        // Check if pom.xml exists
        File pomFile = new File(pomXmlPath);
        if (!pomFile.exists()) {
            log.error("Maven resolution FAILED: pom.xml not found at {}", pomXmlPath);
            return RuntimeParseResult.failure("pom_not_found", "pom.xml not found at " + pomXmlPath);
        }

        // Check if Maven is available
        try {
            ProcessBuilder mvnCheck = new ProcessBuilder("mvn", "-version");
            Process mvnCheckProcess = mvnCheck.start();
            boolean mvnAvailable = mvnCheckProcess.waitFor(10, TimeUnit.SECONDS);
            if (!mvnAvailable || mvnCheckProcess.exitValue() != 0) {
                log.error("Maven resolution FAILED: Maven not available or not in PATH");
                return RuntimeParseResult.failure("mvn_not_available", "Maven command not found or not executable");
            }
        } catch (Exception ex) {
            log.error("Maven resolution FAILED: Cannot verify Maven availability - {}", ex.getMessage());
            return RuntimeParseResult.failure("mvn_check_failed", ex.getMessage());
        }

        try {
            outputFile = File.createTempFile("mvn_dependency_tree_", ".dot");
            List<String> command = Arrays.asList(
                    "mvn",
                    "-q",
                    "-DskipTests",
                    "dependency:tree",
                    "-DoutputType=dot",
                    "-Dscope=runtime",
                    "-DoutputFile=" + outputFile.getAbsolutePath()
            );

            ProcessBuilder pb = new ProcessBuilder(command);
            pb.directory(moduleDir);
            pb.redirectErrorStream(true);

            log.info("Maven dependency tree STARTING: moduleDir={}, pomPath={}, command={}",
                    moduleDir.getAbsolutePath(), pomXmlPath, String.join(" ", command));

            long startTime = System.currentTimeMillis();
            Process process = pb.start();
            String output = readLimitedOutput(process);
            boolean finished = process.waitFor(TIMEOUT_SECONDS, TimeUnit.SECONDS);
            long elapsedSeconds = (System.currentTimeMillis() - startTime) / 1000;

            if (!finished) {
                process.destroyForcibly();
                log.error("Maven dependency tree FAILED (TIMEOUT): moduleDir={}, timeout={}s, elapsed={}s, output={}",
                        moduleDir.getAbsolutePath(), TIMEOUT_SECONDS, elapsedSeconds, output);
                return RuntimeParseResult.failure("mvn_timeout", output);
            }

            int exitCode = process.exitValue();
            if (exitCode != 0) {
                log.error("Maven dependency tree FAILED (NON-ZERO EXIT): moduleDir={}, exitCode={}, elapsed={}s, output={}",
                        moduleDir.getAbsolutePath(), exitCode, elapsedSeconds, output);
                return RuntimeParseResult.failure("mvn_exit_code_" + exitCode, output);
            }

            log.info("Maven dependency tree SUCCESS: moduleDir={}, exitCode={}, elapsed={}s, outputFile={}",
                    moduleDir.getAbsolutePath(), exitCode, elapsedSeconds, outputFile.getAbsolutePath());

            RuntimeParseResult result = parseDotFile(outputFile);
            if (!result.success) {
                log.error("Maven dependency tree PARSE FAILED: moduleDir={}, reason={}, output={}",
                        moduleDir.getAbsolutePath(), result.reason, output);
            } else {
                log.info("Maven dependency tree PARSE SUCCESS: moduleDir={}, resolvedDeps={}, directDeps={}",
                        moduleDir.getAbsolutePath(), result.dependencies.size(), result.directDependencies.size());
            }
            return result;
        } catch (Exception ex) {
            log.error("Maven dependency tree FAILED (EXCEPTION): moduleDir={}, exception={}, message={}",
                    moduleDir.getAbsolutePath(), ex.getClass().getSimpleName(), ex.getMessage(), ex);
            return RuntimeParseResult.failure("exception_" + ex.getClass().getSimpleName(), ex.getMessage());
        } finally {
            if (outputFile != null) {
                try {
                    Files.deleteIfExists(outputFile.toPath());
                } catch (IOException ignore) {
                    log.debug("Failed to delete temp file {}", outputFile.getAbsolutePath());
                }
            }
        }
    }

    private RuntimeParseResult parseDotFile(File outputFile) throws IOException {
        List<String> lines = Files.readAllLines(outputFile.toPath(), StandardCharsets.UTF_8);
        String rootId = null;
        Map<String, String> dependencies = new LinkedHashMap<>();
        Set<String> directDependencies = new LinkedHashSet<>();

        for (String rawLine : lines) {
            String line = rawLine.trim();
            if (rootId == null) {
                Matcher digraphMatcher = DIGRAPH_PATTERN.matcher(line);
                if (digraphMatcher.find()) {
                    rootId = digraphMatcher.group(1);
                }
            }

            Matcher edgeMatcher = EDGE_PATTERN.matcher(line);
            if (!edgeMatcher.find()) {
                continue;
            }

            String from = edgeMatcher.group(1);
            String to = edgeMatcher.group(2);
            ParsedCoordinate fromCoordinate = parseCoordinate(from);
            ParsedCoordinate toCoordinate = parseCoordinate(to);

            if (toCoordinate != null) {
                addResolvedDependency(dependencies, toCoordinate);
                if (rootId != null && rootId.equals(from)) {
                    directDependencies.add(toCoordinate.artifactKey());
                }
            }
            if (fromCoordinate != null && rootId != null && !rootId.equals(from)) {
                addResolvedDependency(dependencies, fromCoordinate);
            }
        }

        if (dependencies.isEmpty()) {
            return RuntimeParseResult.failure("empty_dependency_output", "no runtime dependencies parsed");
        }

        return RuntimeParseResult.success(dependencies, directDependencies);
    }

    private ParsedCoordinate parseCoordinate(String coordinate) {
        if (coordinate == null) {
            return null;
        }

        String trimmed = coordinate.trim();
        if (trimmed.isEmpty()) {
            return null;
        }

        String lower = trimmed.toLowerCase(Locale.ROOT);
        if (lower.contains("pom.xml") || lower.contains("/pom.xml") || lower.endsWith(":pom") || lower.contains(":pom:") || lower.contains("module descriptor")) {
            return null;
        }

        String[] parts = trimmed.split(":");
        // Relaxed: chỉ cần tối thiểu groupId:artifactId (2 phần), cho phép nhiều hơn
        if (parts.length < 2) {
            log.trace("Skipping coordinate with insufficient parts: {}", trimmed);
            return null;
        }

        String groupId = parts[0].trim();
        String artifactId = parts[1].trim();
        // Relaxed: nếu thiếu groupId hoặc artifactId thì bỏ qua
        if (groupId.isBlank() || artifactId.isBlank()) {
            log.trace("Skipping coordinate with blank groupId or artifactId: {}", trimmed);
            return null;
        }

        // Các trường optional - gán giá trị mặc định nếu thiếu
        String packaging = parts.length > 2 && !parts[2].isBlank() ? parts[2].trim() : "jar";
        String classifier = null;
        String version = null;
        String scope = null;

        // Parse version và scope dựa trên số lượng parts
        if (parts.length >= 4) {
            version = parts[3].trim();
            if (version.isBlank()) {
                version = "unknown";
            }
        } else {
            version = "unknown";
        }

        if (parts.length >= 5) {
            scope = parts[4].trim();
        }

        if (parts.length >= 6) {
            classifier = parts[3].trim(); // classifier ở vị trí 4 khi có 6 parts
            version = parts[4].trim();
            scope = parts[5].trim();
        }

        // Chỉ loại bỏ scope test, cho phép pom type và các scope khác
        if ("test".equalsIgnoreCase(scope)) {
            log.trace("Skipping test-scoped dependency: {}", trimmed);
            return null;
        }

        return new ParsedCoordinate(groupId, artifactId, packaging, classifier, version, scope);
    }

    private void addResolvedDependency(Map<String, String> dependencies, ParsedCoordinate coordinate) {
        if (coordinate == null) {
            return;
        }
        String key = coordinate.artifactKey();
        String existing = dependencies.get(key);
        if (existing == null || compareVersions(coordinate.version, existing) > 0) {
            dependencies.put(key, coordinate.version);
        }
    }

    private List<File> findPomFiles(File repoRoot) {
        try {
            List<File> pomFiles = new ArrayList<>();
            Files.walk(repoRoot.toPath())
                    .filter(path -> path.getFileName() != null && path.getFileName().toString().equalsIgnoreCase("pom.xml"))
                    .filter(path -> !isExcluded(path))
                    .map(Path::toFile)
                    .sorted(Comparator.comparing(File::getAbsolutePath))
                    .forEach(pomFiles::add);
            return pomFiles;
        } catch (IOException ex) {
            log.warn("Failed to locate pom.xml files under {}: {}", repoRoot.getAbsolutePath(), ex.getMessage());
            return List.of();
        }
    }

    private boolean isExcluded(Path path) {
        String normalized = path.toString().toLowerCase(Locale.ROOT);
        return normalized.contains(File.separator + "target" + File.separator)
                || normalized.contains(File.separator + ".git" + File.separator)
                || normalized.contains(File.separator + "node_modules" + File.separator);
    }

    private File resolveRepoRoot(String repoPath, String repoName) {
        if (repoPath != null && !repoPath.isBlank()) {
            File direct = new File(repoPath);
            if (direct.exists() && direct.isDirectory()) {
                return direct;
            }
            if (direct.exists() && direct.isFile()) {
                return direct.getParentFile();
            }
        }

        String baseDir = System.getProperty("user.dir");
        File cwd = new File(baseDir);
        if (containsPom(cwd)) {
            return cwd;
        }

        if (repoName != null && !repoName.isBlank()) {
            File byRepo = new File(baseDir, repoName);
            if (byRepo.exists() && byRepo.isDirectory() && containsPom(byRepo)) {
                return byRepo;
            }
        }

        File demoDir = new File(baseDir, "demo");
        if (demoDir.exists() && demoDir.isDirectory() && containsPom(demoDir)) {
            return demoDir;
        }

        return null;
    }

    private boolean containsPom(File root) {
        File[] files = root.listFiles((dir, name) -> name.equalsIgnoreCase("pom.xml"));
        return files != null && files.length > 0;
    }

    private String text(Element element, String tag) {
        NodeList nodes = element.getElementsByTagName(tag);
        if (nodes.getLength() == 0) {
            return null;
        }
        String value = nodes.item(0).getTextContent();
        return value == null ? null : value.trim();
    }

    private void mergeDependencies(Map<String, String> target, Map<String, String> source) {
        for (Map.Entry<String, String> entry : source.entrySet()) {
            String existing = target.get(entry.getKey());
            if (existing == null || compareVersions(entry.getValue(), existing) > 0) {
                target.put(entry.getKey(), entry.getValue());
            }
        }
    }

    private String normalizeKey(String groupId, String artifactId) {
        if (groupId == null || groupId.isBlank() || artifactId == null || artifactId.isBlank()) {
            return null;
        }
        return groupId.trim() + ":" + artifactId.trim();
    }

    private String readLimitedOutput(Process process) throws IOException {
        StringBuilder builder = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream(), StandardCharsets.UTF_8))) {
            String line;
            while ((line = reader.readLine()) != null) {
                if (builder.length() < OUTPUT_LIMIT) {
                    builder.append(line).append('\n');
                }
            }
        }
        return builder.length() > OUTPUT_LIMIT ? builder.substring(0, OUTPUT_LIMIT) : builder.toString();
    }

    private MavenDependencyResolutionResult fallbackResult(String reason) {
        return new MavenDependencyResolutionResult(
                new LinkedHashMap<>(),
                new LinkedHashMap<>(),
                new LinkedHashSet<>(),
                new LinkedHashSet<>(),
                0,
                true,
                reason
        );
    }

    private DocumentBuilderFactory secureDocumentFactory() throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
        factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
        factory.setExpandEntityReferences(false);
        return factory;
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

    private static final class ParsedCoordinate {
        private final String groupId;
        private final String artifactId;
        private final String packaging;
        private final String classifier;
        private final String version;
        private final String scope;

        private ParsedCoordinate(String groupId, String artifactId, String packaging, String classifier, String version, String scope) {
            this.groupId = groupId;
            this.artifactId = artifactId;
            this.packaging = packaging;
            this.classifier = classifier;
            this.version = version;
            this.scope = scope;
        }

        private String artifactKey() {
            if (groupId == null || groupId.isBlank() || artifactId == null || artifactId.isBlank()) {
                return artifactId != null ? artifactId.trim() : null;
            }
            return groupId.trim() + ":" + artifactId.trim();
        }
    }

    private static final class RuntimeParseResult {
        private final Map<String, String> dependencies;
        private final Set<String> directDependencies;
        private final boolean success;
        private final String reason;

        private RuntimeParseResult(Map<String, String> dependencies, Set<String> directDependencies, boolean success, String reason) {
            this.dependencies = dependencies;
            this.directDependencies = directDependencies;
            this.success = success;
            this.reason = reason;
        }

        private static RuntimeParseResult success(Map<String, String> dependencies, Set<String> directDependencies) {
            return new RuntimeParseResult(dependencies, directDependencies, true, null);
        }

        private static RuntimeParseResult failure(String reason, String ignoredOutput) {
            return new RuntimeParseResult(new LinkedHashMap<>(), new LinkedHashSet<>(), false, reason);
        }
    }

    public static final class MavenDependencyResolutionResult {
        private final Map<String, String> declaredDependencies;
        private final Map<String, String> resolvedRuntimeDependencies;
        private final Set<String> directDeclaredDependencies;
        private final Set<String> resolvedRuntimeDirectDependencies;
        private final int moduleCount;
        private final boolean runtimeFallbackUsed;
        private final String runtimeFallbackReason;

        private MavenDependencyResolutionResult(Map<String, String> declaredDependencies,
                                                Map<String, String> resolvedRuntimeDependencies,
                                                Set<String> directDeclaredDependencies,
                                                Set<String> resolvedRuntimeDirectDependencies,
                                                int moduleCount,
                                                boolean runtimeFallbackUsed,
                                                String runtimeFallbackReason) {
            this.declaredDependencies = declaredDependencies;
            this.resolvedRuntimeDependencies = resolvedRuntimeDependencies;
            this.directDeclaredDependencies = directDeclaredDependencies;
            this.resolvedRuntimeDirectDependencies = resolvedRuntimeDirectDependencies;
            this.moduleCount = moduleCount;
            this.runtimeFallbackUsed = runtimeFallbackUsed;
            this.runtimeFallbackReason = runtimeFallbackReason;
        }

        public Map<String, String> getDeclaredDependencies() {
            return declaredDependencies;
        }

        public Map<String, String> getResolvedRuntimeDependencies() {
            return resolvedRuntimeDependencies;
        }

        public Set<String> getDirectDeclaredDependencies() {
            return directDeclaredDependencies;
        }

        public Set<String> getResolvedRuntimeDirectDependencies() {
            return resolvedRuntimeDirectDependencies;
        }

        public int getModuleCount() {
            return moduleCount;
        }

        public boolean isRuntimeFallbackUsed() {
            return runtimeFallbackUsed;
        }

        public String getRuntimeFallbackReason() {
            return runtimeFallbackReason;
        }
    }
}