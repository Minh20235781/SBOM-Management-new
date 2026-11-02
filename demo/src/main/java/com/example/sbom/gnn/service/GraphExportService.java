package com.example.sbom.gnn.service;

import com.example.sbom.gnn.dto.GraphEdgeDTO;
import com.example.sbom.gnn.dto.GraphExportDTO;
import com.example.sbom.gnn.dto.GraphNodeFeatureDTO;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/** Experimental graph export service for GNN research. */
@Service
public class GraphExportService {

    private static final Logger log = LoggerFactory.getLogger(GraphExportService.class);

    public GraphExportDTO prepareExport(GraphExportDTO raw) {
        if (raw == null) {
            throw new IllegalArgumentException("export payload is required");
        }

        List<GraphNodeFeatureDTO> nodes = raw.getNodes() != null ? raw.getNodes() : List.of();
        List<GraphEdgeDTO> edges = raw.getEdges() != null ? raw.getEdges() : List.of();

        List<GraphNodeFeatureDTO> normalizedNodes = normalizeNodes(nodes);
        List<GraphEdgeDTO> normalizedEdges = normalizeEdges(edges, normalizedNodes);

        GraphExportDTO exportDTO = new GraphExportDTO();
        exportDTO.setNodes(normalizedNodes);
        exportDTO.setEdges(normalizedEdges);

        log.info("GNN export prepared: nodes={}, edges={}",
                normalizedNodes.size(), normalizedEdges.size());
        return exportDTO;
    }

    private List<GraphNodeFeatureDTO> normalizeNodes(List<GraphNodeFeatureDTO> nodes) {
        List<GraphNodeFeatureDTO> normalized = new ArrayList<>();
        int nextId = 1;
        for (GraphNodeFeatureDTO node : nodes) {
            if (node == null) {
                continue;
            }
            if (node.getNodeId() == null) {
                node.setNodeId(nextId++);
            } else {
                nextId = Math.max(nextId, node.getNodeId() + 1);
            }
            normalized.add(node);
        }
        return normalized;
    }

    private List<GraphEdgeDTO> normalizeEdges(List<GraphEdgeDTO> edges, List<GraphNodeFeatureDTO> nodes) {
        Map<Integer, Boolean> nodeIndex = new HashMap<>();
        for (GraphNodeFeatureDTO node : nodes) {
            if (node != null && node.getNodeId() != null) {
                nodeIndex.put(node.getNodeId(), true);
            }
        }

        List<GraphEdgeDTO> normalized = new ArrayList<>();
        for (GraphEdgeDTO edge : edges) {
            if (edge == null || edge.getSource() == null || edge.getTarget() == null) {
                continue;
            }
            if (!nodeIndex.containsKey(edge.getSource()) || !nodeIndex.containsKey(edge.getTarget())) {
                log.warn("Skipping edge with unknown node: {} -> {}", edge.getSource(), edge.getTarget());
                continue;
            }
            normalized.add(edge);
        }
        return normalized;
    }
}
