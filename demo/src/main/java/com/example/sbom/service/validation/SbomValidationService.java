package com.example.sbom.service.validation;

import com.example.sbom.dto.DependencyConfidenceDTO;
import com.example.sbom.dto.GraphResultDTO;
import com.example.sbom.dto.SbomValidationResponse;
import com.example.sbom.dto.ValidationIssueDTO;
import com.example.sbom.dto.ValidationSummaryDTO;
import com.example.sbom.entity.PackageEntity;
import com.example.sbom.entity.Project;
import com.example.sbom.model.Node;
import com.example.sbom.repository.DependencyRepository;
import com.example.sbom.repository.PackageRepository;
import com.example.sbom.repository.ProjectRepository;
import com.example.sbom.service.graph.GraphBuilderService;
import com.example.sbom.service.persistence.SbomPersistenceService;
import com.example.sbom.service.scan.CycloneDxParseService;
import com.example.sbom.service.scan.TrivyScanResult;
import com.example.sbom.service.scan.TrivyScanService;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.io.File;
import java.io.IOException;
import java.util.*;

/**
 * SbomValidationService - Core validation logic for SBOM trust scoring
 *
 * Key improvements:
 * 1. Smart key matching with flexible comparison (groupId:artifactId vs artifactId)
 * 2. Enhanced ecosystem detection with proper fallback labels
 * 3. Cross-ecosystem comparison isolation (Maven-only comparison for build tree fields)
 */
@Service
@RequiredArgsConstructor
public class SbomValidationService {

    private static final Logger log = LoggerFactory.getLogger(SbomValidationService.class);

    private final TrivyScanService trivyScanService;
    private final SbomPersistenceService sbomPersistenceService;
    private final CycloneDxParseService cycloneDxParseService;
    private final GraphBuilderService graphBuilderService;
    private final PackageRepository packageRepository;
    private final DependencyRepository dependencyRepository;
    private final ProjectRepository projectRepository;
    private final MavenDependencyResolutionService mavenDependencyResolutionService;
    private final VotingValidationService votingValidationService;
    private final WeightedValidationService weightedValidationService;
    private final ConsistencyValidationService consistencyValidationService;
    private final ObjectMapper objectMapper = new ObjectMapper();

    /**
     * Main validation entry point
     */
    public SbomValidationResponse validate(String repoUrl, String repoName, String repoPath) {
        String normalizedRepo = normalizeRepoName(repoUrl, repoName);
        String scanTarget = repoPath != null && !repoPath.isBlank() ? repoPath : repoUrl;

        // Optimization: skip the Trivy scan entirely when the database already
        // holds a complete scan result for this repo (packages + dependency
        // graph). The frontend's "Refresh score" button relies on this — it
        // should be a cheap DB-only recompute, not a 20-60s Trivy clone.
        // If the user explicitly wants a fresh scan, the controller's
        // /api/sbom/scan-and-save path will produce one.
        if (scanTarget != null && !scanTarget.isBlank() && normalizedRepo != null
                && !packageRepository.findByRepoName(normalizedRepo).isEmpty()
                && !dependencyRepository.findByFrom_RepoName(normalizedRepo).isEmpty()) {
            log.info("validate(): DB has packages + dependency graph for repo={}, skipping Trivy scan",
                    normalizedRepo);
            scanTarget = null;
        }

        TrivyScanResult trivyResult;
        try {
            trivyResult = scanTarget != null && !scanTarget.isBlank()
                    ? trivyScanService.scanRepoMerged(scanTarget)
                    : null;
        } catch (Exception ex) {
            throw new RuntimeException("Failed to scan repo: " + ex.getMessage(), ex);
        }

        File sbomFile = trivyResult != null ? trivyResult.getSbomFile() : null;

        List<PackageEntity> sbomPackages = normalizedRepo != null
                ? packageRepository.findByRepoName(normalizedRepo)
                : Collections.emptyList();

        if (sbomPackages.isEmpty() && sbomFile != null && normalizedRepo != null) {
            try {
                sbomPersistenceService.saveSbomWithVulns(sbomFile, normalizedRepo);
                sbomPackages = packageRepository.findByRepoName(normalizedRepo);
            } catch (IOException ex) {
                throw new RuntimeException("Failed to persist SBOM data: " + ex.getMessage(), ex);
            }
        }

        // Build maps from various sources
        Map<String, String> sbomDeps = buildLatestVersionMap(sbomPackages);
        Map<String, String> scannerDeps = trivyResult != null ? trivyResult.getComponents() : Collections.emptyMap();
        Map<String, String> componentEcosystems = trivyResult != null ? trivyResult.getComponentEcosystems() : Collections.emptyMap();

        // When Trivy was skipped (trivyResult == null) but the database
        // already holds packages from a previous scan, fall back to the
        // SBOM-cached view as the "scanner proxy". Otherwise every metric
        // that depends on scannerDeps would short-circuit to 0%, and the
        // page would render an empty trust score even though the project
        // has 100s of real packages in the DB. See plan file for context.
        if (trivyResult == null && !sbomPackages.isEmpty()) {
            scannerDeps = sbomDeps;
            componentEcosystems = buildEcosystemMapFromSbom(sbomPackages);
            log.info("validate(): trivyResult is null, falling back to SBOM-cached scanner view: {} packages, {} ecosystems",
                    scannerDeps.size(), componentEcosystems.values().stream().distinct().count());
        }

        // Maven dependency resolution results
        MavenDependencyResolutionService.MavenDependencyResolutionResult mavenResult =
            mavenDependencyResolutionService.resolveDependencyTree(repoPath, normalizedRepo);
        Map<String, String> declaredDeps = mavenResult.getDeclaredDependencies();
        Map<String, String> resolvedRuntimeDeps = mavenResult.getResolvedRuntimeDependencies();

        // Extract Maven keys as Sets for efficient lookup
        Set<String> declaredKeys = declaredDeps.keySet();
        Set<String> resolvedKeys = resolvedRuntimeDeps.keySet();

        // Build dependency graph data
        GraphResultDTO graph = normalizedRepo != null ? graphBuilderService.buildGraphByRepo(normalizedRepo) : null;
        if ((graph == null || graph.getNodes() == null || graph.getNodes().isEmpty())
                && sbomFile != null
                && normalizedRepo != null
                && dependencyRepository.findByFrom_RepoName(normalizedRepo).isEmpty()) {
            try {
                cycloneDxParseService.parseAndRank(sbomFile);
                graph = graphBuilderService.buildGraphByRepo(normalizedRepo);
            } catch (IOException ex) {
                throw new RuntimeException("Failed to parse dependency graph: " + ex.getMessage(), ex);
            }
        }

        Set<String> graphDeps = extractGraphDeps(graph);
        Set<String> allDeps = new HashSet<>();
        allDeps.addAll(sbomDeps.keySet());
        allDeps.addAll(scannerDeps.keySet());
        allDeps.addAll(declaredKeys);
        allDeps.addAll(resolvedKeys);
        allDeps.addAll(graphDeps);

        // Build dependency list with enhanced validation
        List<DependencyConfidenceDTO> dependencies = new ArrayList<>();
        for (String dep : allDeps) {
            // Step 1: Determine ecosystem FIRST (before any comparison)
            String rawEcosystem = extractEcosystem(dep, componentEcosystems);
            String ecosystem = normalizeEcosystem(rawEcosystem);
            boolean isMavenEcosystem = "maven".equalsIgnoreCase(ecosystem);

            // Step 2: Smart key matching for cross-source comparison
            // Only attempt Maven key matching if this is a Maven package
            boolean inGraph = isKeyMatching(dep, graphDeps);
            boolean inScanner = isKeyMatching(dep, scannerDeps.keySet());
            boolean inDeclared = isMavenEcosystem && isKeyMatching(dep, declaredKeys);
            boolean inResolved = isMavenEcosystem && isKeyMatching(dep, resolvedKeys);

            // Step 3: Determine dependency type (Maven-only for build tree)
            boolean directDependency = inDeclared;
            boolean transitiveDependency = inResolved && !inDeclared;

            // Step 4: Build provenance sources list
            List<String> sources = new ArrayList<>();
            if (inGraph) sources.add("GRAPH");
            if (inScanner) sources.add("SCANNER");
            if (inDeclared) sources.add("DECLARED");
            if (inResolved) sources.add("RESOLVED");

            // Step 5: Build provenance categories
            List<String> provenance = new ArrayList<>();
            if (directDependency) provenance.add("DIRECT_BUILD");
            if (transitiveDependency) provenance.add("TRANSITIVE_BUILD");
            if (inScanner) provenance.add("RUNTIME_SCANNER");
            if (inGraph) provenance.add("GRAPH_DISCOVERED");
            if (!directDependency && !transitiveDependency && !"other".equalsIgnoreCase(ecosystem) && !"unknown".equalsIgnoreCase(ecosystem)) {
                provenance.add("ECOSYSTEM_ONLY");
            }

            // Step 6: Pick best version from available sources
            String version = pickVersion(dep, sbomDeps, declaredDeps, resolvedRuntimeDeps, scannerDeps);

            // Step 7: Create DTO
            DependencyConfidenceDTO dto = new DependencyConfidenceDTO();
            dto.setPackageName(dep);
            dto.setVersion(version);
            dto.setSources(sources);
            dto.setEcosystem(ecosystem);
            dto.setEcosystemDetected(!isUnknownOrEmpty(ecosystem));
            dto.setDirectDependency(directDependency);
            dto.setTransitiveDependency(transitiveDependency);
            dto.setDetectedByScanner(inScanner);
            dto.setResolvedByBuild(inResolved);
            dto.setGraphPresent(inGraph);
            dto.setProvenanceCategories(provenance);
            dto.setInGraph(inGraph);
            dto.setInScanner(inScanner);
            dto.setInDeclared(inDeclared);
            dto.setInResolved(inResolved);
            dto.setConfidence(classifyConfidence(inGraph, inScanner, inResolved, isMavenEcosystem, ecosystem));
            dto.setWeightedScore(rounded(weightScore(inGraph, inScanner, inResolved, isMavenEcosystem)));
            dependencies.add(dto);
        }

        dependencies.sort(Comparator.comparing(DependencyConfidenceDTO::getPackageName));

        // Compute metrics
        // After the SBOM-cached fallback above, componentEcosystems is
        // already populated from PackageEntity.purl when trivyResult is
        // null, so we can derive purlEcosystems / ecosystem detection
        // from the (now-updated) componentEcosystems map. This keeps
        // mavenDetected + ecosystemDetected correct in both scan paths.
        Set<String> effectivePurlEcosystems = componentEcosystems.values().stream()
                .filter(Objects::nonNull)
                .collect(java.util.stream.Collectors.toCollection(LinkedHashSet::new));
        boolean mavenDetected = effectivePurlEcosystems.contains("maven");
        boolean ecosystemDetected = !effectivePurlEcosystems.isEmpty();
        boolean declaredDependenciesAvailable = !declaredDeps.isEmpty();
        boolean resolvedRuntimeAvailable = !resolvedRuntimeDeps.isEmpty();
        boolean buildValidationAvailable = mavenDetected && declaredDependenciesAvailable && resolvedRuntimeAvailable;

        // Build coverage: intersection of declared Maven deps with scanner Maven deps
        Set<String> mavenScannerDeps = filterByEcosystem(scannerDeps.keySet(), componentEcosystems, "maven");
        double buildDependencyCoverage = buildValidationAvailable
            ? rounded(safeRatio(intersection(declaredKeys, mavenScannerDeps).size(), declaredKeys.size()))
            : Double.NaN;
        Double buildCoverageMetric = buildValidationAvailable ? buildDependencyCoverage : null;

        // Graph consistency: intersection of graph deps with scanner deps
        double dependencyGraphConsistency = scannerDeps.isEmpty()
            ? 0.0
            : safeRatio(intersection(graphDeps, scannerDeps.keySet()).size(), scannerDeps.size());

        // External scanner alignment: intersection of resolved runtime deps with scanner Maven deps
        double externalScannerAlignment = resolvedRuntimeDeps.isEmpty()
            ? dependencyGraphConsistency
            : safeRatio(intersection(resolvedKeys, mavenScannerDeps).size(), resolvedKeys.size());

        // Security metadata availability
        double securityMetadataAvailability = scannerDeps.isEmpty()
            ? 0.0
            : safeRatio(countPackagesWithVulns(scannerDeps.keySet(), sbomPackages), scannerDeps.size());

        // Build issues list
        List<ValidationIssueDTO> issues = buildIssues(declaredDeps, resolvedRuntimeDeps, scannerDeps, graphDeps, mavenDetected);
        ValidationSummaryDTO summary = votingValidationService.summarize(dependencies);

        // Compute trust score
        double baseScore = computeBaseScore(buildCoverageMetric, dependencyGraphConsistency, externalScannerAlignment, securityMetadataAvailability, buildValidationAvailable);

        // NEW: Weighted validation - use average weighted score instead of confidence ratios
        // Weighted scores: Graph=0.34, Scanner=0.33, Resolved=0.33 (+ Maven bonus 0.1)
        double totalWeightedScore = 0.0;
        for (DependencyConfidenceDTO dep : dependencies) {
            totalWeightedScore += dep.getWeightedScore();
        }
        double avgWeightedScore = dependencies.isEmpty() ? 0.0 : totalWeightedScore / dependencies.size();

        // Convert weighted score to penalty: high score = low penalty
        // avgWeightedScore = 1.0 → weightedPenalty = 0.0
        // avgWeightedScore = 0.3 → weightedPenalty = 0.7
        double weightedPenalty = 1.0 - avgWeightedScore;

        // Issue penalty remains the same
        double issuePenalty = Math.min(ratio(issues.size(), dependencies.size()), 0.25);

        // Combined penalty: weighted validation (70%) + issues (30%)
        double penalty = (weightedPenalty * 0.70) + (issuePenalty * 0.30);

        double structuralTrustScore = clamp(baseScore - penalty, 0.0, 1.0);

        // Boost score if non-Maven sources are highly consistent
        if (!buildValidationAvailable && dependencyGraphConsistency >= 0.9 && externalScannerAlignment >= 0.9) {
            structuralTrustScore = Math.max(structuralTrustScore, baseScore * 0.9);
        }

        // Build response
        SbomValidationResponse response = new SbomValidationResponse();
        response.setDependencies(dependencies);
        summary.setDeclaredDependencyCount(declaredDeps.size());
        summary.setResolvedRuntimeDependencyCount(resolvedRuntimeDeps.size());
        summary.setScannerComponentCount(scannerDeps.size());
        summary.setGraphNodeCount(graphDeps.size());
        // Visibility" breakdown.
        Map<String, Integer> ecosystemCounts = trivyResult != null
                ? trivyResult.getEcosystemCounts()
                : countEcosystems(componentEcosystems);
        response.setSummary(summary);
        response.setIssues(issues);
        response.setStructuralTrustScore(rounded(structuralTrustScore));
        response.setStructuralTrustQuality(scoreToQuality(structuralTrustScore));
        response.setBuildDependencyCoverage(buildValidationAvailable ? buildCoverageMetric : null);
        response.setDependencyGraphConsistency(rounded(dependencyGraphConsistency));
        response.setExternalScannerAlignment(rounded(externalScannerAlignment));
        response.setSecurityMetadataAvailability(rounded(securityMetadataAvailability));
        response.setRuntimeSupplyChainVisibility(ecosystemCounts);
        response.setBuildValidationAvailable(buildValidationAvailable);
        response.setDeclaredDependenciesAvailable(declaredDependenciesAvailable);
        response.setResolvedRuntimeAvailable(resolvedRuntimeAvailable);
        response.setMavenDetected(mavenDetected);
        response.setEcosystemDetected(ecosystemDetected);
        response.setBuildFallbackUsed(mavenResult.isRuntimeFallbackUsed());
        response.setBuildFallbackReason(mavenResult.getRuntimeFallbackReason());
        response.setValidationInterpretation(buildInterpretation());

        return response;
    }

    /**
     * Project-scoped entry point: look up the project, derive a
     * best-effort repoUrl from its description (e.g. the
     * "Auto-created from Trivy scan of <url>" suffix written by
     * {@code SbomExportController}), and delegate to
     * {@link #validate(String, String, String)}.
     *
     * The description-based URL extraction is purely for the
     * "fresh Trivy scan" path; the rest of the validation
     * falls back to the project's stored package / graph data
     * by repoName, so projects with no URL on file (e.g. the
     * "Default Project" seed of legacy packages) still get a
     * score computed from whatever is in the database.
     */
    public SbomValidationResponse validateByProject(Long projectId) {
        Project project = projectRepository.findById(projectId).orElseThrow(() ->
                new IllegalArgumentException("Project not found: id=" + projectId));
        String repoName = project.getName();
        String repoUrl = extractRepoUrlFromDescription(project.getDescription());
        return validate(repoUrl, repoName, null);
    }

    /**
     * Pull a Git URL out of a project description if one was
     * embedded when the project was auto-created from a scan.
     * Returns null when the description doesn't carry a URL
     * (e.g. the Default Project seed), so the caller can
     * proceed with a DB-only validation.
     */
    private String extractRepoUrlFromDescription(String description) {
        if (description == null || description.isBlank()) return null;
        java.util.regex.Matcher m = java.util.regex.Pattern
                .compile("(https?://\\S+?)(?:\\s|$)")
                .matcher(description);
        if (m.find()) {
            String url = m.group(1);
            // Strip trailing punctuation that often sneaks in
            // from human-written descriptions.
            if (url.endsWith(".") || url.endsWith(",")) {
                url = url.substring(0, url.length() - 1);
            }
            return url;
        }
        return null;
    }

    // ==================== KEY MATCHING UTILITIES ====================

    /**
     * Smart key matching with flexible comparison.
     * Handles the common case where Maven uses "groupId:artifactId" format
     * while other sources (scanner, graph) may use just "artifactId".
     *
     * @param currentDep  The dependency key to check (from the loop)
     * @param targetKeys  Collection of target keys to match against
     * @return true if currentDep matches any key in targetKeys
     */
    private boolean isKeyMatching(String currentDep, Collection<String> targetKeys) {
        if (currentDep == null || currentDep.isBlank() || targetKeys == null || targetKeys.isEmpty()) {
            return false;
        }

        // Direct exact match
        if (targetKeys.contains(currentDep)) {
            return true;
        }

        // Flexible matching: try both directions
        // currentDep format: "groupId:artifactId" or "artifactId"
        // targetKey format: "groupId:artifactId" or "artifactId"

        for (String targetKey : targetKeys) {
            if (targetKey == null || targetKey.isBlank()) {
                continue;
            }

            // Check if currentDep ends with ":" + targetKey (currentDep has groupId, targetKey is artifactId)
            if (currentDep.endsWith(":" + targetKey)) {
                return true;
            }

            // Check if targetKey ends with ":" + currentDep (targetKey has groupId, currentDep is artifactId)
            if (targetKey.endsWith(":" + currentDep)) {
                return true;
            }

            // Extract artifactId from both and compare (fallback for complex cases)
            String currentArtifactId = extractArtifactId(currentDep);
            String targetArtifactId = extractArtifactId(targetKey);
            if (currentArtifactId != null && currentArtifactId.equals(targetArtifactId)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Extract artifactId from a key (last part after colon, or the key itself if no colon)
     */
    private String extractArtifactId(String key) {
        if (key == null || key.isBlank()) {
            return null;
        }
        if (key.contains(":")) {
            String[] parts = key.split(":");
            return parts[parts.length - 1].trim();
        }
        return key.trim();
    }

    // ==================== ECOSYSTEM UTILITIES ====================

    /**
     * Extract ecosystem from the dependency key or lookup from componentEcosystems map.
     * Uses PURL prefix patterns when available.
     */
    private String extractEcosystem(String dep, Map<String, String> componentEcosystems) {
        // First, check if we have explicit ecosystem mapping from Trivy
        if (componentEcosystems != null && componentEcosystems.containsKey(dep)) {
            String ecosystem = componentEcosystems.get(dep);
            if (ecosystem != null && !ecosystem.isBlank()) {
                return ecosystem;
            }
        }

        // Try to extract from the key itself (PURL format or groupId pattern)
        if (dep != null) {
            String lowerDep = dep.toLowerCase(Locale.ROOT);

            // PURL prefix detection
            if (lowerDep.startsWith("pkg:maven")) return "maven";
            if (lowerDep.startsWith("pkg:npm")) return "npm";
            if (lowerDep.startsWith("pkg:pypi")) return "pypi";
            if (lowerDep.startsWith("pkg:nuget")) return "nuget";
            if (lowerDep.startsWith("pkg:gem")) return "gem";
            if (lowerDep.startsWith("pkg:golang")) return "golang";
            if (lowerDep.startsWith("pkg:deb") || lowerDep.startsWith("pkg:rpm") || lowerDep.startsWith("pkg:apk")) return "native";
            if (lowerDep.startsWith("pkg:composer")) return "composer";
            if (lowerDep.startsWith("pkg:cargo")) return "cargo";
            if (lowerDep.startsWith("pkg:pub")) return "dart";

            // Heuristic: Maven groupId patterns (dot notation)
            if (dep.contains(":")) {
                String[] parts = dep.split(":");
                String groupId = parts[0].trim();
                // Maven groupIds typically follow domain reversal pattern
                if (isMavenGroupIdPattern(groupId)) {
                    return "maven";
                }
            }

            // Heuristic: Node modules pattern
            if (lowerDep.contains("node_modules") || lowerDep.startsWith("@")) {
                return "npm";
            }

            // Heuristic: Python patterns
            if (lowerDep.contains("__pycache__") || lowerDep.contains(".egg-info")) {
                return "pypi";
            }

            // Heuristic: OS packages
            if (lowerDep.contains("/bin/") || lowerDep.contains("/usr/") ||
                lowerDep.contains(".apk") || lowerDep.contains(".deb") || lowerDep.contains(".rpm")) {
                return "native";
            }
        }

        return null; // Unknown
    }

    /**
     * Check if a groupId follows Maven naming conventions
     */
    private boolean isMavenGroupIdPattern(String groupId) {
        if (groupId == null || groupId.isBlank()) {
            return false;
        }
        // Maven groupIds typically follow domain reversal:
        // - com.example
        // - org.springframework
        // - io.netty
        // - com.google.code
        // - apache.commons

        // Common prefixes that indicate Maven packages
        String[] mavenPrefixes = {
            "com.", "org.", "io.", "net.", "de.", "fr.", "uk.", "cn.",
            "gov.", "edu.", "mil.", "se.", "ru.", "jp.", "kr.", "br."
        };

        String lower = groupId.toLowerCase(Locale.ROOT);
        for (String prefix : mavenPrefixes) {
            if (lower.startsWith(prefix)) {
                return true;
            }
        }

        // Check for known framework/library groupIds
        String[] knownGroups = {
            "junit", "spring", "hibernate", "apache", "google", "slf4j",
            "log4j", "commons", "jackson", "guava", "lombok", "mockito"
        };
        for (String known : knownGroups) {
            if (lower.contains(known)) {
                return true;
            }
        }

        return false;
    }

    /**
     * Normalize ecosystem label - convert null/unknown to appropriate fallback
     * and ensure consistent casing
     */
    private String normalizeEcosystem(String ecosystem) {
        if (ecosystem == null || ecosystem.isBlank()) {
            return "other";
        }

        String normalized = ecosystem.toLowerCase(Locale.ROOT).trim();

        // Map common variations
        switch (normalized) {
            case "maven":
            case "java":
            case "jar":
                return "maven";
            case "npm":
            case "nodejs":
            case "node.js":
                return "npm";
            case "pypi":
            case "python":
            case "pip":
                return "pypi";
            case "nuget":
            case "dotnet":
            case "csharp":
                return "nuget";
            case "gem":
            case "ruby":
                return "gem";
            case "golang":
            case "go":
                return "golang";
            case "native":
            case "os":
            case "linux":
            case "debian":
            case "alpine":
            case "rpm":
            case "apk":
            case "deb":
                return "native";
            case "cargo":
            case "rust":
                return "cargo";
            case "composer":
            case "php":
                return "composer";
            case "pub":
            case "dart":
                return "dart";
            case "unknown":
            case "":
                return "other";
            default:
                return normalized;
        }
    }

    /**
     * Check if ecosystem is unknown or empty
     */
    private boolean isUnknownOrEmpty(String ecosystem) {
        return ecosystem == null || ecosystem.isBlank() || "unknown".equalsIgnoreCase(ecosystem) || "other".equalsIgnoreCase(ecosystem);
    }

    /**
     * Filter dependencies by ecosystem
     */
    private Set<String> filterByEcosystem(Set<String> deps, Map<String, String> componentEcosystems, String targetEcosystem) {
        if (deps == null || deps.isEmpty()) {
            return Collections.emptySet();
        }

        Set<String> filtered = new HashSet<>();
        for (String dep : deps) {
            String ecosystem = extractEcosystem(dep, componentEcosystems);
            if (targetEcosystem.equalsIgnoreCase(normalizeEcosystem(ecosystem))) {
                filtered.add(dep);
            }
        }
        return filtered;
    }

    // ==================== HELPER METHODS ====================

    private String normalizeRepoName(String repoUrl, String repoName) {
        String normalized = repoName;
        if ((normalized == null || normalized.isBlank()) && repoUrl != null && !repoUrl.isBlank()) {
            normalized = repoUrl.substring(repoUrl.lastIndexOf('/') + 1).replace(".git", "");
        }
        if (normalized == null) return null;
        normalized = normalized.trim();
        if (normalized.contains("/")) {
            String[] parts = normalized.split("/");
            normalized = parts[parts.length - 1];
        }
        normalized = normalized.replaceAll("\\.git$", "");
        return normalized.isBlank() ? null : normalized;
    }

    private Map<String, String> buildLatestVersionMap(List<PackageEntity> packages) {
        Map<String, String> map = new HashMap<>();
        if (packages == null) return map;
        for (PackageEntity pkg : packages) {
            if (pkg.getName() == null) continue;
            String existing = map.get(pkg.getName());
            if (existing == null || compareVersions(pkg.getVersion(), existing) > 0) {
                map.put(pkg.getName(), pkg.getVersion());
            }
        }
        return map;
    }

    private Set<String> extractGraphDeps(GraphResultDTO graph) {
        if (graph == null || graph.getNodes() == null) return Collections.emptySet();
        Set<String> deps = new HashSet<>();
        for (Node node : graph.getNodes()) {
            if (node.getName() != null && !node.getName().isBlank()) {
                deps.add(node.getName());
            }
        }
        return deps;
    }

    private String pickVersion(String dep,
                               Map<String, String> sbomDeps,
                               Map<String, String> declaredDeps,
                               Map<String, String> resolvedRuntimeDeps,
                               Map<String, String> scannerDeps) {
        if (scannerDeps.containsKey(dep)) return scannerDeps.get(dep);
        if (resolvedRuntimeDeps.containsKey(dep)) return resolvedRuntimeDeps.get(dep);
        if (declaredDeps.containsKey(dep)) return declaredDeps.get(dep);
        return sbomDeps.get(dep);
    }

    private List<ValidationIssueDTO> buildIssues(Map<String, String> declaredDeps,
                                                 Map<String, String> resolvedRuntimeDeps,
                                                 Map<String, String> scannerDeps,
                                                 Set<String> graphDeps,
                                                 boolean mavenDetected) {
        List<ValidationIssueDTO> issues = new ArrayList<>();

        if (!mavenDetected && !declaredDeps.isEmpty()) {
            issues.add(issue("MAVEN_RUNTIME_MISMATCH", null, "MEDIUM",
                    "pom.xml declares Maven dependencies but scanner runtime output does not contain pkg:maven components.",
                    "DECLARED|SCANNER"));
        }

        Set<String> all = new HashSet<>();
        all.addAll(declaredDeps.keySet());
        all.addAll(resolvedRuntimeDeps.keySet());
        all.addAll(scannerDeps.keySet());
        all.addAll(graphDeps);

        for (String dep : all) {
            Set<String> versions = new HashSet<>();
            if (declaredDeps.get(dep) != null && !declaredDeps.get(dep).isBlank()) versions.add(declaredDeps.get(dep));
            if (resolvedRuntimeDeps.get(dep) != null && !resolvedRuntimeDeps.get(dep).isBlank()) versions.add(resolvedRuntimeDeps.get(dep));
            if (scannerDeps.get(dep) != null && !scannerDeps.get(dep).isBlank()) versions.add(scannerDeps.get(dep));
            if (versions.size() > 1) {
                issues.add(issue("VERSION_MISMATCH", dep, "MEDIUM",
                        "The same dependency is reported with different versions across sources.",
                        "DECLARED|RESOLVED|SCANNER"));
            }
        }

        return issues;
    }

    private String scoreToQuality(double score) {
        if (score >= 0.75) return "HIGH";
        if (score >= 0.40) return "MEDIUM";
        return "LOW";
    }

    private ValidationIssueDTO issue(String type, String packageName, String severity, String description, String comparisonScope) {
        ValidationIssueDTO dto = new ValidationIssueDTO();
        dto.setType(type);
        dto.setPackageName(packageName);
        dto.setSeverity(severity);
        dto.setDescription(description);
        dto.setComparisonScope(comparisonScope);
        return dto;
    }

    private String buildInterpretation() {
        return "Scanner components may exceed declared Maven dependencies because runtime dependency resolution includes transitive and ecosystem-level packages not explicitly declared in pom.xml. "
                + "Runtime SBOMs commonly contain transitive dependencies not directly declared, and multi-module Maven projects frequently introduce runtime packages outside direct dependency declarations. "
                + "Scanner/runtime alignment should be interpreted separately from direct build validation. "
                + "Dependency Graph Consistency measures alignment between the generated dependency graph and independently scanned runtime components. "
                + "Build Dependency Coverage measures whether direct build dependencies are preserved in runtime SBOM generation.";
    }

    private String classifyConfidence(boolean inGraph,
                                      boolean inScanner,
                                      boolean inResolved,
                                      boolean isMavenEcosystem,
                                      String ecosystem) {
        // HIGH confidence: present in multiple high-value sources
        if ((inGraph && inScanner && inResolved) || (inGraph && inScanner && isMavenEcosystem)) {
            return "HIGH";
        }
        // MEDIUM confidence: present in at least two sources
        if ((inGraph && inScanner) || (inScanner && inResolved) || (inGraph && inResolved)) {
            return "MEDIUM";
        }
        // LOW confidence: only one source or unknown ecosystem
        if (isUnknownOrEmpty(ecosystem)) {
            return "LOW";
        }
        return "LOW";
    }

    private double weightScore(boolean inGraph, boolean inScanner, boolean inResolved, boolean isMavenEcosystem) {
        // Weights: Scanner (0.40) > Graph (0.30) = Resolved (0.30)
        // - Scanner: nguồn độc lập từ bên thứ 3 (Trivy) - QUAN TRỌNG NHẤT
        // - Graph: dependency structure trong project
        // - Resolved: Maven transitive resolution
        double score = 0.0;
        if (inGraph) score += 0.30;
        if (inScanner) score += 0.40;  // Scanner ưu tiên cao nhất!
        if (inResolved) score += 0.30;
        // Bonus for Maven ecosystem confirmation
        if (isMavenEcosystem && inResolved) {
            score += 0.1; // Small bonus for confirmed ecosystem match
        }
        return Math.min(score, 1.0); // Cap at 1.0
    }

    private Set<String> intersection(Set<String> left, Set<String> right) {
        if (left == null || right == null) return Collections.emptySet();
        Set<String> result = new HashSet<>(left);
        result.retainAll(right);
        return result;
    }

    private double computeBaseScore(Double buildCoverage,
                                    double graphConsistency,
                                    double scannerAlignment,
                                    double securityMetadataAvailability,
                                    boolean buildValidationAvailable) {
        double buildWeight = buildValidationAvailable && buildCoverage != null ? 0.35 : 0.0;
        double graphWeight = 0.35;
        double scannerWeight = 0.20;
        double securityWeight = 0.10;
        double total = buildWeight + graphWeight + scannerWeight + securityWeight;
        if (total <= 0.0) return 0.0;
        double buildScore = buildCoverage != null ? buildCoverage : 0.0;
        double raw = (buildScore * buildWeight)
                + (graphConsistency * graphWeight)
                + (scannerAlignment * scannerWeight)
                + (securityMetadataAvailability * securityWeight);
        return raw / total;
    }

    private double ratio(int numerator, int denominator) {
        if (denominator <= 0) return 0.0;
        return (double) numerator / (double) denominator;
    }

    private double clamp(double value, double min, double max) {
        return Math.max(min, Math.min(max, value));
    }

    /**
     * Build a name → ecosystem map from {@link PackageEntity} rows that
     * were persisted from a previous Trivy scan. Used as a fallback when
     * the current {@code validate()} call skipped Trivy because the DB
     * already had packages for the repo. Mirrors
     * {@code trivyScanService} → {@code componentEcosystems} shape.
     */
    private Map<String, String> buildEcosystemMapFromSbom(List<PackageEntity> sbomPackages) {
        Map<String, String> result = new HashMap<>();
        if (sbomPackages == null) return result;
        for (PackageEntity pkg : sbomPackages) {
            if (pkg == null) continue;
            String name = pkg.getName();
            if (name == null || name.isBlank()) continue;
            String ecosystem = extractEcosystemFromPurl(pkg.getPurl());
            if (ecosystem != null) {
                result.put(name, ecosystem);
            }
        }
        return result;
    }

    /**
     * Mirror of {@code TrivyScanService.extractEcosystem}, but reading
     * from a stored purl on a {@link PackageEntity} instead of a
     * freshly-scanned SBOM. Unknown / blank purls return {@code null} so
     * the caller can skip the row entirely.
     */
    private String extractEcosystemFromPurl(String purl) {
        if (purl == null || purl.isBlank()) return null;
        String v = purl.toLowerCase(Locale.ROOT);
        if (v.startsWith("pkg:maven")) return "maven";
        if (v.startsWith("pkg:npm")) return "npm";
        if (v.startsWith("pkg:pypi")) return "pypi";
        if (v.startsWith("pkg:nuget")) return "nuget";
        if (v.startsWith("pkg:gem")) return "gem";
        if (v.startsWith("pkg:golang")) return "golang";
        if (v.startsWith("pkg:deb") || v.startsWith("pkg:rpm") || v.startsWith("pkg:apk")) return "native";
        if (v.startsWith("pkg:composer")) return "composer";
        if (v.startsWith("pkg:cargo")) return "cargo";
        if (v.startsWith("pkg:pub")) return "dart";
        return null;
    }

    /**
     * Count how many packages belong to each ecosystem. Used as a
     * fallback for {@code runtimeSupplyChainVisibility} when the call
     * path is the SBOM-cached branch (no Trivy scan this turn).
     */
    private Map<String, Integer> countEcosystems(Map<String, String> componentEcosystems) {
        Map<String, Integer> counts = new LinkedHashMap<>();
        if (componentEcosystems == null) return counts;
        for (String ecosystem : componentEcosystems.values()) {
            if (ecosystem == null) continue;
            counts.merge(ecosystem, 1, Integer::sum);
        }
        return counts;
    }

    private int countPackagesWithVulns(Set<String> scannerDeps, List<PackageEntity> sbomPackages) {
        if (scannerDeps == null || scannerDeps.isEmpty() || sbomPackages == null) return 0;
        int count = 0;
        for (PackageEntity pkg : sbomPackages) {
            if (pkg.getName() == null) continue;
            if (!scannerDeps.contains(pkg.getName())) continue;
            if (pkg.getVulnerabilities() != null && !pkg.getVulnerabilities().isEmpty()) {
                count++;
            }
        }
        return count;
    }

    private double safeRatio(int numerator, int denominator) {
        if (denominator <= 0) return 0.0;
        return (double) numerator / (double) denominator;
    }

    private double rounded(double score) {
        return Math.round(score * 100.0) / 100.0;
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