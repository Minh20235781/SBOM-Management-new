package com.example.sbom.gnn.dto;

import lombok.Data;

import java.util.List;

/**
 * Graph export payload for experimental GNN processing.
 */
@Data
public class GraphExportDTO {
    private List<GraphNodeFeatureDTO> nodes;
    private List<GraphEdgeDTO> edges;
    private String model;
}
