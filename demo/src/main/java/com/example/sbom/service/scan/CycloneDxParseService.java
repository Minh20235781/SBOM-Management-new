package com.example.sbom.service.scan;

import com.example.sbom.entity.DependencyEntity;
import com.example.sbom.entity.PackageEntity;
import com.example.sbom.model.Edge;
import com.example.sbom.model.Node;
import com.example.sbom.repository.DependencyRepository;
import com.example.sbom.repository.PackageRepository;
import com.example.sbom.service.graph.ModuleRankService;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.io.File;
import java.io.IOException;
import java.util.*;

@Service
@RequiredArgsConstructor
public class CycloneDxParseService {
    private static final Logger log = LoggerFactory.getLogger(CycloneDxParseService.class);

    private final PackageRepository packageRepository;
    private final ModuleRankService moduleRankService;
    private final DependencyRepository dependencyRepository;
    private final ObjectMapper objectMapper = new ObjectMapper();

    @Transactional
    public void parseAndRank(File sbomFile) throws IOException {
        JsonNode root = objectMapper.readTree(sbomFile);

        Map<String, PackageEntity> purlToPkg = new HashMap<>();
        List<Node> nodes = new ArrayList<>();
        List<Edge> edges = new ArrayList<>();

        // 1️⃣ Load/create packages
        JsonNode components = root.path("components");
        if (components.isArray()) {
            for (JsonNode c : components) {
                String purl = c.path("purl").asText(null);
                if (purl == null) continue;

                PackageEntity pkg = packageRepository.findByPurl(purl)
                        .orElseGet(() -> {
                            PackageEntity ph = new PackageEntity();
                            ph.setPurl(purl);
                            ph.setName(c.path("name").asText(purl));
                            ph.setVersion(c.path("version").asText(null));
                            ph.setType(c.path("type").asText(null));
                            ph.setRankScore(0.0);
                            return packageRepository.save(ph);
                        });
                purlToPkg.put(purl, pkg);
                nodes.add(new Node(pkg.getId().toString(), pkg.getName(), pkg.getRankScore()));
            }
        }

        // 2️⃣ Build dependencies
        JsonNode deps = root.path("dependencies");
        if (deps.isArray()) {
            for (JsonNode dep : deps) {
                String ref = dep.path("ref").asText(null);
                if (ref == null) continue;
                JsonNode dependsOn = dep.path("dependsOn");
                if (!dependsOn.isArray()) continue;

                String rawScope = dep.path("scope").asText(null);
                String type = mapCycloneScopeToEdgeType(rawScope);

                for (JsonNode d : dependsOn) {
                    String targetRef = d.asText(null);
                    if (targetRef == null) continue;

                    PackageEntity fromPkg = purlToPkg.get(ref);
                    PackageEntity toPkg = purlToPkg.get(targetRef);

                    if (fromPkg != null && toPkg != null) {
                        if (!dependencyRepository.existsByFromAndToAndType(fromPkg, toPkg, type)) {
                            DependencyEntity depEntity = new DependencyEntity();
                            depEntity.setFrom(fromPkg);
                            depEntity.setTo(toPkg);
                            depEntity.setType(type);
                            dependencyRepository.save(depEntity);
                        }

                        // Edge cho graph
                        edges.add(new Edge(
                                fromPkg.getId().toString(),
                                toPkg.getId().toString(),
                                type
                        ));
                    }
                }
            }
        }

        log.info("Parsed graph — nodes: {}, edges: {}", nodes.size(), edges.size());

        // 3️⃣ Tính module rank
        Map<String, Double> rankMap = moduleRankService.calculateRank(nodes, edges);

        // 4️⃣ Lưu rank về DB
        for (Map.Entry<String, Double> e : rankMap.entrySet()) {
            Long id = Long.parseLong(e.getKey());
            packageRepository.findById(id).ifPresent(pkg -> {
                pkg.setRankScore(e.getValue());
                packageRepository.save(pkg);
            });
        }
        log.info("Updated rank_score for {} packages", rankMap.size());
    }

    private String mapCycloneScopeToEdgeType(String rawScope) {
        if (rawScope == null) return "runtime";
        String s = rawScope.toLowerCase(Locale.ROOT);
        return switch (s) {
            case "optional" -> "optional";
            case "development", "provided", "test" -> "dev";
            case "peer", "build", "system" -> "third-party";
            default -> "runtime";
        };
    }
}
