package com.example.sbom.gnn.exporter;

import com.example.sbom.gnn.dto.GraphEdgeDTO;
import com.example.sbom.gnn.dto.GraphExportDTO;
import com.example.sbom.gnn.dto.GraphExportMetadataDTO;
import com.example.sbom.gnn.dto.GraphNodeFeatureDTO;
import com.example.sbom.gnn.util.GraphExportUtil;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Component;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/** JSON exporter for experimental GNN datasets. */
@Component
public class JsonGraphExporter {

    private static final Logger log = LoggerFactory.getLogger(JsonGraphExporter.class);

    private final ObjectMapper objectMapper;

    public JsonGraphExporter(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    public GraphExportMetadataDTO export(GraphExportDTO exportDTO) {
        if (exportDTO == null) {
            throw new IllegalArgumentException("export payload is required");
        }

        try {
            String timestamp = GraphExportUtil.nowTimestamp();
            Path exportDir = Paths.get("exports", "gnn");
            Files.createDirectories(exportDir);

            Path exportFile = exportDir.resolve("gnn-export-" + timestamp + ".json");
            Map<String, Object> payload = buildPayload(exportDTO);

            objectMapper.writerWithDefaultPrettyPrinter().writeValue(exportFile.toFile(), payload);

            GraphExportMetadataDTO meta = new GraphExportMetadataDTO();
            meta.setExportPath(exportFile.toString());
            meta.setNodeCount(exportDTO.getNodes() != null ? exportDTO.getNodes().size() : 0);
            meta.setEdgeCount(exportDTO.getEdges() != null ? exportDTO.getEdges().size() : 0);
            meta.setExportTimestamp(timestamp);

            log.info("GNN export written: path={}, nodes={}, edges={}",
                    meta.getExportPath(), meta.getNodeCount(), meta.getEdgeCount());
            return meta;
        } catch (Exception ex) {
            log.error("GNN export failed: {}", ex.getMessage(), ex);
            throw new IllegalStateException("GNN export failed", ex);
        }
    }

    private Map<String, Object> buildPayload(GraphExportDTO exportDTO) {
        List<Map<String, Object>> nodes = new ArrayList<>();
        List<Map<String, Object>> edges = new ArrayList<>();

        if (exportDTO.getNodes() != null) {
            for (GraphNodeFeatureDTO node : exportDTO.getNodes()) {
                if (node == null) {
                    continue;
                }
                Map<String, Object> nodeMap = new HashMap<>();
                nodeMap.put("nodeId", node.getNodeId());
                nodeMap.put("packageName", node.getPackageName());

                Map<String, Object> features = new HashMap<>();
                features.put("moduleRank", node.getModuleRank());
                features.put("maxCvss", node.getMaxCvss());
                features.put("avgCvss", node.getAvgCvss());
                features.put("maxEpss", node.getMaxEpss());
                features.put("avgEpss", node.getAvgEpss());
                features.put("kevCount", node.getKevCount());
                features.put("vulnerabilityCount", node.getVulnerabilityCount());
                features.put("severityWeight", node.getSeverityWeight());

                nodeMap.put("features", features);
                nodes.add(nodeMap);
            }
        }

        if (exportDTO.getEdges() != null) {
            for (GraphEdgeDTO edge : exportDTO.getEdges()) {
                if (edge == null) {
                    continue;
                }
                Map<String, Object> edgeMap = new HashMap<>();
                edgeMap.put("source", edge.getSource());
                edgeMap.put("target", edge.getTarget());
                edges.add(edgeMap);
            }
        }

        Map<String, Object> payload = new HashMap<>();
        payload.put("nodes", nodes);
        payload.put("edges", edges);
        return payload;
    }
}
