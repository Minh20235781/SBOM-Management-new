package com.example.sbom.gnn.dataset.dto;

import lombok.Data;

/**
 * Result wrapper for feature engineering with enrichment stats.
 */
@Data
public class DatasetFeatureResultDTO {
    private DatasetNodeFeatureDTO node;
    private int vulnerabilityCount;
    private int kevCount;
    private int epssCoveredCount;
}
