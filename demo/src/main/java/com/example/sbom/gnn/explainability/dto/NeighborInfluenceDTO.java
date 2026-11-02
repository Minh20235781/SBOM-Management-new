package com.example.sbom.gnn.explainability.dto;

import lombok.Data;

/**
 * Influence contribution from a neighboring dependency.
 */
@Data
public class NeighborInfluenceDTO {
    private String packageName;
    private double influenceScore;
    private String riskLevel;
}
