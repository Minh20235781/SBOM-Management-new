package com.example.sbom.gnn.dto;

import lombok.Data;

/**
 * Metadata for GNN graph export results.
 */
@Data
public class GraphExportMetadataDTO {
    private String exportPath;
    private int nodeCount;
    private int edgeCount;
    private String exportTimestamp;
}
