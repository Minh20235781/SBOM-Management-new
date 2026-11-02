package com.example.sbom.gnn.dataset.service;

import com.example.sbom.entity.DependencyEntity;
import com.example.sbom.entity.PackageEntity;
import com.example.sbom.gnn.dataset.builder.DatasetGraphBuilder;
import com.example.sbom.gnn.dataset.dto.DatasetBuildRequestDTO;
import com.example.sbom.gnn.dataset.dto.DatasetBuildResponseDTO;
import com.example.sbom.gnn.dataset.dto.DatasetNodeFeatureDTO;
import com.example.sbom.gnn.dto.GraphEdgeDTO;
import com.example.sbom.gnn.dto.GraphExportDTO;
import com.example.sbom.gnn.dto.GraphExportMetadataDTO;
import com.example.sbom.gnn.dto.GraphNodeFeatureDTO;
import com.example.sbom.gnn.exporter.JsonGraphExporter;
import com.example.sbom.gnn.service.GraphExportService;
import com.example.sbom.model.Edge;
import com.example.sbom.model.Node;
import com.example.sbom.repository.DependencyRepository;
import com.example.sbom.repository.PackageRepository;
import com.example.sbom.service.graph.ModuleRankService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

/** Experimental dataset build pipeline: DB -> threat intel -> feature engineering -> graph DTO -> JSON export. */
@Service
public class DatasetBuildService {

    private static final Logger log = LoggerFactory.getLogger(DatasetBuildService.class);

    private final PackageRepository packageRepository;
    private final DependencyRepository dependencyRepository;
    private final ModuleRankService moduleRankService;
    private final DatasetFeatureEngineeringService featureEngineeringService;
    private final GraphExportService graphExportService;
    private final JsonGraphExporter jsonGraphExporter;
    private final DatasetGraphBuilder graphBuilder = new DatasetGraphBuilder();

    public DatasetBuildService(PackageRepository packageRepository,
                               DependencyRepository dependencyRepository,
                               ModuleRankService moduleRankService,
                               DatasetFeatureEngineeringService featureEngineeringService,
                               GraphExportService graphExportService,
                               JsonGraphExporter jsonGraphExporter) {
        this.packageRepository = packageRepository;
        this.dependencyRepository = dependencyRepository;
        this.moduleRankService = moduleRankService;
        this.featureEngineeringService = featureEngineeringService;
        this.graphExportService = graphExportService;
        this.jsonGraphExporter = jsonGraphExporter;
    }

    @Transactional(readOnly = true)
    public DatasetBuildResponseDTO build(DatasetBuildRequestDTO request) {
        DatasetBuildRequestDTO safe = request != null ? request : new DatasetBuildRequestDTO();
        List<String> repoNames = normalizeRepoNames(safe.getRepoNames());
        boolean includeAll = safe.isIncludeAllRepos() && repoNames.isEmpty();

        List<PackageEntity> packages;
        if (includeAll) {
            packages = packageRepository.findAllWithVulnerabilities();
        } else {
            packages = loadPackagesByRepo(repoNames);
        }

        if (packages.isEmpty()) {
            throw new IllegalArgumentException("no packages found for dataset build");
        }

        Map<Long, PackageEntity> packageIndex = packages.stream()
                .filter(pkg -> pkg.getId() != null)
                .collect(Collectors.toMap(PackageEntity::getId, pkg -> pkg, (a, b) -> a));

        List<DependencyEntity> dependencies = includeAll
                ? dependencyRepository.findAll()
                : loadDependenciesByRepo(repoNames);

        List<DependencyEntity> filteredDeps = dependencies.stream()
                .filter(dep -> dep != null
                        && dep.getFrom() != null
                        && dep.getTo() != null
                        && packageIndex.containsKey(dep.getFrom().getId())
                        && packageIndex.containsKey(dep.getTo().getId()))
                .toList();

        Map<String, Double> moduleRank = computeModuleRank(packages, filteredDeps);

        Map<Long, Integer> nodeIdByPackage = new HashMap<>();
        List<GraphNodeFeatureDTO> graphNodes = new ArrayList<>();
        int nextId = 1;

        for (PackageEntity pkg : packages) {
            if (pkg == null || pkg.getId() == null) {
                continue;
            }
            int nodeId = nextId++;
            nodeIdByPackage.put(pkg.getId(), nodeId);

            double rankScore = moduleRank.getOrDefault(pkg.getId().toString(),
                    pkg.getRankScore() != null ? pkg.getRankScore() : 0.0);

            DatasetNodeFeatureDTO datasetNode = featureEngineeringService.buildFeatures(pkg, rankScore);
            datasetNode.setNodeId(nodeId);

            GraphNodeFeatureDTO graphNode = toGraphNode(datasetNode);
            graphNodes.add(graphNode);
        }

        List<GraphEdgeDTO> graphEdges = new ArrayList<>();
        for (DependencyEntity dep : filteredDeps) {
            Integer source = nodeIdByPackage.get(dep.getFrom().getId());
            Integer target = nodeIdByPackage.get(dep.getTo().getId());
            if (source == null || target == null) {
                continue;
            }
            GraphEdgeDTO edge = new GraphEdgeDTO();
            edge.setSource(source);
            edge.setTarget(target);
            graphEdges.add(edge);
        }

        GraphExportDTO exportDTO = graphBuilder.build(graphNodes, graphEdges);
        GraphExportDTO prepared = graphExportService.prepareExport(exportDTO);
        GraphExportMetadataDTO meta = jsonGraphExporter.export(prepared);

        long uniquePackageCount = packages.stream()
                .filter(p -> p != null && p.getName() != null)
                .map(p -> p.getName())
                .distinct()
                .count();

        DatasetBuildResponseDTO response = new DatasetBuildResponseDTO();
        response.setExportPath(meta.getExportPath());
        response.setExportTimestamp(meta.getExportTimestamp());
        response.setNodeCount(meta.getNodeCount());
        response.setEdgeCount(meta.getEdgeCount());
        response.setPackageCount((int) uniquePackageCount);
        response.setRepoNames(includeAll ? extractRepoNames(packages) : repoNames);
        response.setRepoCount(response.getRepoNames().size());

        log.info("Experimental dataset export completed: path={}, nodes={}, edges={}, uniquePackages={}",
                meta.getExportPath(), meta.getNodeCount(), meta.getEdgeCount(), uniquePackageCount);
        return response;
    }

    private List<PackageEntity> loadPackagesByRepo(List<String> repoNames) {
        List<PackageEntity> packages = new ArrayList<>();
        for (String repoName : repoNames) {
            packages.addAll(packageRepository.findAllByRepoWithVulnerabilities(repoName));
        }
        return packages;
    }

    private List<DependencyEntity> loadDependenciesByRepo(List<String> repoNames) {
        List<DependencyEntity> dependencies = new ArrayList<>();
        for (String repoName : repoNames) {
            dependencies.addAll(dependencyRepository.findByFrom_RepoName(repoName));
        }
        return dependencies;
    }

    private Map<String, Double> computeModuleRank(List<PackageEntity> packages, List<DependencyEntity> dependencies) {
        List<Node> nodes = new ArrayList<>();
        for (PackageEntity pkg : packages) {
            if (pkg == null || pkg.getId() == null) {
                continue;
            }
            nodes.add(new Node(pkg.getId().toString(), pkg.getName(), 0.0));
        }

        List<Edge> edges = new ArrayList<>();
        for (DependencyEntity dep : dependencies) {
            if (dep == null || dep.getFrom() == null || dep.getTo() == null) {
                continue;
            }
            String type = dep.getType() != null ? dep.getType() : "runtime";
            edges.add(new Edge(dep.getFrom().getId().toString(), dep.getTo().getId().toString(), type));
        }

        return moduleRankService.calculateRank(nodes, edges);
    }

    private GraphNodeFeatureDTO toGraphNode(DatasetNodeFeatureDTO datasetNode) {
        GraphNodeFeatureDTO node = new GraphNodeFeatureDTO();
        node.setNodeId(datasetNode.getNodeId());
        node.setPackageName(datasetNode.getPackageName());
        node.setModuleRank(datasetNode.getModuleRank());
        node.setMaxCvss(datasetNode.getMaxCvss());
        node.setAvgCvss(datasetNode.getAvgCvss());
        node.setMaxEpss(datasetNode.getMaxEpss());
        node.setAvgEpss(datasetNode.getAvgEpss());
        node.setKevCount(datasetNode.getKevCount());
        node.setVulnerabilityCount(datasetNode.getVulnerabilityCount());
        node.setSeverityWeight(datasetNode.getSeverityWeight());
        return node;
    }

    private List<String> normalizeRepoNames(List<String> repoNames) {
        if (repoNames == null) {
            return Collections.emptyList();
        }
        return repoNames.stream()
                .filter(Objects::nonNull)
                .map(String::trim)
                .filter(name -> !name.isBlank())
                .distinct()
                .toList();
    }

    private List<String> extractRepoNames(List<PackageEntity> packages) {
        Set<String> names = new HashSet<>();
        for (PackageEntity pkg : packages) {
            if (pkg != null && pkg.getRepoName() != null && !pkg.getRepoName().isBlank()) {
                names.add(pkg.getRepoName());
            }
        }
        return names.stream().sorted().toList();
    }
}
