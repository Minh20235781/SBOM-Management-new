package com.example.sbom.provenance;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.*;
import org.springframework.stereotype.Service;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.*;
import java.util.concurrent.*;

@Service
public class SbomProvenanceService {
    private final ObjectMapper json = new ObjectMapper();
    private final ExecutorService pool = Executors.newFixedThreadPool(8);
    private final java.util.function.BiFunction<String, String, RegistryEvidence> lookup;

    public SbomProvenanceService() { this(RegistryEvidence::lookup); }

    SbomProvenanceService(java.util.function.BiFunction<String, String, RegistryEvidence> lookup) { this.lookup = lookup; }

    @jakarta.annotation.PreDestroy
    public void close() { pool.shutdown(); }

    public ProvenanceResultDTO processProvenance(String content) throws Exception {
        return processProvenance(content.getBytes(StandardCharsets.UTF_8));
    }

    public ProvenanceResultDTO processProvenance(byte[] bytes) throws Exception {
        JsonNode input = json.readTree(bytes);
        if (!(input instanceof ObjectNode root) || !"CycloneDX".equals(root.path("bomFormat").asText()) || !root.path("components").isArray())
            throw new IllegalArgumentException("Cần SBOM CycloneDX JSON có danh sách components.");
        String digest = HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(bytes));
        var result = ProvenanceResultDTO.builder().format("CycloneDX").specVersion(root.path("specVersion").asText())
                .fileSha256(digest).sha256Engine("Java MessageDigest SHA-256").totalComponents(root.path("components").size());
        ObjectNode metadata = root.withObject("/metadata");
        for (JsonNode prop : metadata.path("properties"))
            if ("devops.provenance.normalized".equals(prop.path("name").asText()) && "true".equals(prop.path("value").asText()))
                return result.alreadyNormalized(true).message("Tệp đã đánh dấu chuẩn hóa. Dùng bản gốc để kiểm tra lại.").build();

        if ("1.6".equals(root.path("specVersion").asText())) normalizeLegacyFields(root, metadata);
        var components = inspectComponents(root.path("components"));
        prop(metadata, "devops.provenance.file_sha256", digest);
        prop(metadata, "devops.provenance.normalized", "true");
        int found = (int) components.stream().filter(c -> "RELEASE_FOUND".equals(c.getStatus())).count();
        int absent = (int) components.stream().filter(c -> "NOT_FOUND".equals(c.getStatus())).count();
        return result.components(components).verifiedComponents(found).suspiciousComponents(absent)
                .unverifiedComponents(components.size() - found - absent).enrichedSbomJson(json.convertValue(root, Map.class))
                .message("Đã đối chiếu bản phát hành và ghi nguồn checksum tham chiếu.").build();
    }

    private List<ComponentProvenanceDTO> inspectComponents(JsonNode nodes) {
        Map<List<String>, CompletableFuture<RegistryEvidence>> lookups = new HashMap<>();
        List<CompletableFuture<ComponentProvenanceDTO>> jobs = new ArrayList<>();
        for (JsonNode node : nodes) {
            if (!(node instanceof ObjectNode component)) throw new IllegalArgumentException("Component không hợp lệ.");
            String purl = purl(component);
            String resolved = version(component, purl);
            var evidence = lookups.computeIfAbsent(List.of(purl, resolved), key ->
                CompletableFuture.supplyAsync(() -> lookup.apply(purl, resolved), pool));
            jobs.add(evidence.thenApply(e -> enrich(component, purl, resolved, e)));
        }
        return jobs.stream().map(CompletableFuture::join).toList();
    }

    private static String purl(ObjectNode component) {
        String existing = component.path("purl").asText("");
        if (!existing.isBlank()) return existing;
        String name = component.path("name").asText("");
        for (JsonNode property : component.path("properties")) {
            if ("syft:package:type".equals(property.path("name").asText()) && "npm".equals(property.path("value").asText())
                    && name.matches("(?:@[a-zA-Z0-9._-]+/)?[a-zA-Z0-9._-]+")) {
                String version = component.path("version").asText("");
                String purl = "pkg:npm/" + name.replace("@", "%40");
                if (!version.isBlank() && !version.equalsIgnoreCase("unknown"))
                    purl += "@" + java.net.URLEncoder.encode(version, StandardCharsets.UTF_8);
                component.put("purl", purl);
                return purl;
            }
        }
        return "";
    }

    private static String version(JsonNode component, String purl) {
        String declared = component.path("version").asText("");
        if (!declared.isBlank()) return declared;
        String coordinate = purl.split("[?#]", 2)[0];
        int at = coordinate.lastIndexOf('@');
        if (at <= coordinate.lastIndexOf('/')) return "";
        try {
            return java.net.URLDecoder.decode(coordinate.substring(at + 1).replace("+", "%2B"), StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) { return ""; }
    }

    private static void normalizeLegacyFields(ObjectNode root, ObjectNode metadata) {
        for (ObjectNode node : List.of(root, metadata)) {
            JsonNode legacy = node.get("lifecycle_phase");
            if (legacy != null && legacy.isTextual()) {
                prop(metadata, node == root ? "legacy.document.lifecycle_phase" : "legacy.metadata.lifecycle_phase", legacy.asText());
                node.remove("lifecycle_phase");
            }
        }
        for (JsonNode vuln : root.path("vulnerabilities")) for (JsonNode rating : vuln.path("ratings")) {
            String severity = rating.path("severity").asText().toLowerCase(Locale.ROOT);
            if (rating instanceof ObjectNode item && Set.of("critical","high","medium","low","info","none","unknown").contains(severity))
                item.put("severity", severity);
        }
    }

    private static void prop(ObjectNode node, String key, String value) {
        if (value == null) return;
        ArrayNode properties = node.withArray("properties");
        if (key.equals("devops.provenance.file_sha256") || key.equals("devops.provenance.normalized")) {
            for (int i = properties.size() - 1; i >= 0; i--)
                if (key.equals(properties.get(i).path("name").asText())) properties.remove(i);
        }
        properties.addObject().put("name", key).put("value", value);
    }

    private static List<String> manifestPaths(JsonNode node) {
        Set<String> paths = new LinkedHashSet<>();
        for (JsonNode p : node.path("properties")) {
            String name = p.path("name").asText();
            if (name.startsWith("syft:location:") && name.endsWith(":path") && p.path("value").isTextual())
                paths.add(p.get("value").asText());
        }
        return List.copyOf(paths);
    }

    private ComponentProvenanceDTO enrich(ObjectNode node, String purl, String version, RegistryEvidence e) {
        prop(node, "devops.provenance.status", e.status());
        prop(node, "devops.provenance.source", e.source());
        prop(node, "devops.provenance.artifact", e.artifact());
        prop(node, "devops.provenance.gitHead", e.commit());
        if (e.hash() != null) {
            ObjectNode hash = json.createObjectNode().put("alg", e.algorithm()).put("content", e.hash());
            ArrayNode hashes = node.withArray("hashes");
            boolean existingAlgorithm = false;
            for (JsonNode entry : hashes) if (e.algorithm().equals(entry.path("alg").asText())) {
                existingAlgorithm = true;
                if (!e.hash().equalsIgnoreCase(entry.path("content").asText()))
                    prop(node, "devops.provenance.checksumConflict", e.algorithm() + " " + e.hash());
            }
            if (!existingAlgorithm) hashes.add(hash);
        }
        String ecosystem = purl.startsWith("pkg:") ? purl.substring(4).split("/", 2)[0] : "";
        return ComponentProvenanceDTO.builder().name(node.path("name").asText()).version(version).purl(purl)
                .normalizedPurl(purl).ecosystem(ecosystem).status(e.status()).officialRegistry(e.source()).manifestPaths(manifestPaths(node))
                .officialHashAlgorithm(e.algorithm()).officialHash(e.hash()).artifactUrl(e.artifact()).commitSha(e.commit())
                .pedigree(node.has("pedigree") ? json.convertValue(node.get("pedigree"), Map.class) : null).build();
    }
}
