package com.example.sbom.gnn.dataset.service;

import com.example.sbom.entity.PackageEntity;
import com.example.sbom.gnn.dataset.dto.DatasetFeatureResultDTO;
import com.example.sbom.gnn.dataset.dto.DatasetGraphEnrichRequestDTO;
import com.example.sbom.gnn.dto.GraphExportDTO;
import com.example.sbom.gnn.dto.GraphExportMetadataDTO;
import com.example.sbom.gnn.dto.GraphNodeFeatureDTO;
import com.example.sbom.gnn.exporter.JsonGraphExporter;
import com.example.sbom.gnn.service.GraphExportService;
import com.example.sbom.repository.PackageRepository;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;

/**
 * Enrich a raw graph export with threat-intel features from the SBOM database.
 */
@Service
public class GraphThreatEnrichmentService {

    private static final Logger log = LoggerFactory.getLogger(GraphThreatEnrichmentService.class);

    private final PackageRepository packageRepository;
    private final DatasetFeatureEngineeringService featureEngineeringService;
    private final GraphExportService graphExportService;
    private final JsonGraphExporter jsonGraphExporter;

    public GraphThreatEnrichmentService(PackageRepository packageRepository,
                                        DatasetFeatureEngineeringService featureEngineeringService,
                                        GraphExportService graphExportService,
                                        JsonGraphExporter jsonGraphExporter) {
        this.packageRepository = packageRepository;
        this.featureEngineeringService = featureEngineeringService;
        this.graphExportService = graphExportService;
        this.jsonGraphExporter = jsonGraphExporter;
    }

    @Transactional(readOnly = true)
    public GraphExportMetadataDTO enrichAndExport(DatasetGraphEnrichRequestDTO request) {
        if (request == null || request.getGraph() == null) {
            throw new IllegalArgumentException("graph payload is required");
        }

        GraphExportDTO graph = request.getGraph();
        List<GraphNodeFeatureDTO> nodes = graph.getNodes();
        if (nodes == null || nodes.isEmpty()) {
            throw new IllegalArgumentException("graph nodes are required");
        }

        String repoName = request.getRepoName() != null ? request.getRepoName().trim() : "";

        int enrichedCount = 0;
        int missingCount = 0;
        int totalKev = 0;
        int totalVulnerabilities = 0;
        int epssCovered = 0;

        for (GraphNodeFeatureDTO node : nodes) {
            if (node == null || node.getPackageName() == null || node.getPackageName().isBlank()) {
                missingCount++;
                continue;
            }

            PackageEntity pkg = resolvePackage(node.getPackageName(), repoName);
            if (pkg == null) {
                missingCount++;
                continue;
            }

            double moduleRank = pkg.getRankScore() != null ? pkg.getRankScore() : node.getModuleRank();
            DatasetFeatureResultDTO result = featureEngineeringService.buildFeaturesWithStats(pkg, moduleRank);
            applyFeatures(node, result);

            enrichedCount++;
            totalKev += result.getKevCount();
            totalVulnerabilities += result.getVulnerabilityCount();
            epssCovered += result.getEpssCoveredCount();

            if (result.getVulnerabilityCount() > 0
                    && result.getKevCount() == 0
                    && result.getNode().getMaxEpss() == 0.0) {
                log.warn("Threat-intel missing for package with CVEs: {}", node.getPackageName());
            }
        }

        log.info("Threat enrichment summary: nodes={}, enriched={}, missing={}, kevMatches={}, epssCovered={}, totalVulns={}",
                nodes.size(), enrichedCount, missingCount, totalKev, epssCovered, totalVulnerabilities);

        GraphExportDTO prepared = graphExportService.prepareExport(graph);
        return jsonGraphExporter.export(prepared);
    }

    private PackageEntity resolvePackage(String packageName, String repoName) {
        if (packageName == null || packageName.isBlank()) {
            return null;
        }

        List<PackageEntity> matches;
        if (repoName != null && !repoName.isBlank()) {
            matches = packageRepository.findByNameAndRepoWithVulnerabilities(packageName, repoName);
            if (matches == null || matches.isEmpty()) {
                matches = packageRepository.findByNameWithVulnerabilities(packageName);
            }
        } else {
            matches = packageRepository.findByNameWithVulnerabilities(packageName);
        }

        if (matches == null || matches.isEmpty()) {
            log.warn("Package not found for enrichment: {}", packageName);
            return null;
        }

        return matches.get(0);
    }

    private void applyFeatures(GraphNodeFeatureDTO node, DatasetFeatureResultDTO result) {
        node.setModuleRank(result.getNode().getModuleRank());
        node.setMaxCvss(result.getNode().getMaxCvss());
        node.setAvgCvss(result.getNode().getAvgCvss());
        node.setMaxEpss(result.getNode().getMaxEpss());
        node.setAvgEpss(result.getNode().getAvgEpss());
        node.setKevCount(result.getKevCount());
        node.setVulnerabilityCount(result.getVulnerabilityCount());
        node.setSeverityWeight(result.getNode().getSeverityWeight());
    }
}
