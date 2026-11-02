package com.example.sbom.service;

import com.example.sbom.dto.*;
import com.example.sbom.entity.*;
import com.example.sbom.repository.*;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.*;

@Service
@RequiredArgsConstructor
public class PackageQueryService {

    private final PackageRepository packageRepo;
    private final DependencyRepository dependencyRepo;
    private final AnomalyService anomalyService;

    /* ================= API 1 ================= */
    public PackageDetailsResponse getPackageDetails(String name, String repoName) {

        List<PackageEntity> pkgs;
        String normalizedRepo = null;
        if (repoName != null && !repoName.isBlank()) {
            normalizedRepo = repoName.trim();
            if (normalizedRepo.contains("/")) {
                String[] parts = normalizedRepo.split("/");
                normalizedRepo = parts[parts.length - 1];
            }
            normalizedRepo = normalizedRepo.replaceAll("\\.git$", "");
            pkgs = packageRepo.findByNameAndRepoWithVulnerabilities(name, normalizedRepo);
            if (pkgs == null || pkgs.isEmpty()) {
                // fallback to global if not found for the repo
                pkgs = packageRepo.findByNameWithVulnerabilities(name);
            }
        } else {
            pkgs = packageRepo.findByNameWithVulnerabilities(name);
        }
        if (pkgs == null || pkgs.isEmpty()) {
            throw new RuntimeException("Package not found");
        }

        // If multiple versions exist, pick the latest by version string
        PackageEntity pkg;
        if (pkgs.size() == 1) {
            pkg = pkgs.get(0);
        } else {
            pkgs.sort((a, b) -> compareVersions(b.getVersion(), a.getVersion()));
            pkg = pkgs.get(0);
        }

        String anomalyRepo = normalizedRepo != null ? normalizedRepo : pkg.getRepoName();
        var risky = anomalyService
            .getAnomalyOfPackage(name, anomalyRepo)
            .orElse(null);

        PackageDTO dto = new PackageDTO();
        dto.setName(pkg.getName());
        dto.setVersion(pkg.getVersion());
        dto.setRepoName(pkg.getRepoName());
        dto.setRankScore(Optional.ofNullable(pkg.getRankScore()).orElse(0.0));
        dto.setDependencyDepth(pkg.getDependencyDepth());
        dto.setRepoCount(pkg.getRepoCount());

        if (risky != null) {
            dto.setVulnAnomaly(risky.getVulnAnomaly());
            dto.setHubAnomaly(risky.getHubAnomaly());
        }

        List<VulnerabilityDTO> vulns = pkg.getVulnerabilities().stream().map(v -> {
            VulnerabilityDTO vd = new VulnerabilityDTO();
            vd.setName(v.getVulnId());
            vd.setSeverity(v.getSeverity());
            vd.setCvssScore(v.getCvssScore());
            vd.setReferences(
                    v.getUrl() != null ? List.of(v.getUrl()) : List.of()
            );
            return vd;
        }).toList();

        PackageDetailsResponse res = new PackageDetailsResponse();
        res.setPackageInfo(dto);
        res.setVulnerabilities(vulns);
        return res;
    }

    /* ================= API 2 ================= */
    public DependencyGraphResponse getLocalGraph(String name) {

        List<DependencyEntity> deps = dependencyRepo.findLocalGraph(name);

        Map<String, GraphNodeDTO> nodes = new HashMap<>();
        List<GraphEdgeDTO> edges = new ArrayList<>();

        for (DependencyEntity d : deps) {

            PackageEntity from = d.getFrom();
            PackageEntity to = d.getTo();

            nodes.computeIfAbsent(from.getName(), k -> buildNode(from));
            nodes.computeIfAbsent(to.getName(), k -> buildNode(to));

            GraphEdgeDTO e = new GraphEdgeDTO();
            e.setSource(from.getName());
            e.setTarget(to.getName());
            edges.add(e);
        }

        DependencyGraphResponse res = new DependencyGraphResponse();
        res.setNodes(new ArrayList<>(nodes.values()));
        res.setEdges(edges);
        return res;
    }

    private GraphNodeDTO buildNode(PackageEntity p) {
        GraphNodeDTO n = new GraphNodeDTO();
        n.setId(p.getName());
        n.setRankScore(Optional.ofNullable(p.getRankScore()).orElse(0.0));
        n.setVulnCount(p.getVulnerabilities().size());
        n.setDependencyDepth(p.getDependencyDepth());
        return n;
    }

    /**
     * Compare two version strings in a best-effort numeric way.
     * Returns negative if v1 < v2, zero if equal, positive if v1 > v2.
     */
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
