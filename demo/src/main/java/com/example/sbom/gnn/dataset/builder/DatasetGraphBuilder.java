package com.example.sbom.gnn.dataset.builder;

import com.example.sbom.gnn.dto.GraphEdgeDTO;
import com.example.sbom.gnn.dto.GraphExportDTO;
import com.example.sbom.gnn.dto.GraphNodeFeatureDTO;

import java.util.List;

/**
 * Builds GraphExportDTO objects compatible with the existing GNN pipeline.
 */
public class DatasetGraphBuilder {

    public GraphExportDTO build(List<GraphNodeFeatureDTO> nodes, List<GraphEdgeDTO> edges) {
        GraphExportDTO exportDTO = new GraphExportDTO();
        exportDTO.setNodes(nodes);
        exportDTO.setEdges(edges);
        return exportDTO;
    }
}
