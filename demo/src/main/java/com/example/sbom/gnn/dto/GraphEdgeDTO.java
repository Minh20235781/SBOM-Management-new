package com.example.sbom.gnn.dto;

import lombok.Data;

/**
 * Directed edge between two dependency nodes.
 */
@Data
public class GraphEdgeDTO {
    private Integer source;
    private Integer target;
}
