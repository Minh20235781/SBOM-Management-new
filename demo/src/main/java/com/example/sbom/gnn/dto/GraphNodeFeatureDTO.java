package com.example.sbom.gnn.dto;

import lombok.Data;

/**
 * GNN node feature representation for experimental graph intelligence research.
 */
@Data
public class GraphNodeFeatureDTO {
    private Integer nodeId;
    private String packageName;
    private double moduleRank;
    private double maxCvss;
    private double avgCvss;
    private double maxEpss;
    private double avgEpss;
    private int kevCount;
    private int vulnerabilityCount;
    private double severityWeight;
}
