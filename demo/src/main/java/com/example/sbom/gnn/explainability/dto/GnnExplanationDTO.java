package com.example.sbom.gnn.explainability.dto;

import lombok.Data;

import java.util.List;
import java.util.Map;

/**
 * Explainability summary for a single package node.
 */
@Data
public class GnnExplanationDTO {
    private String packageName;
    private String predictedRisk;
    private List<NeighborInfluenceDTO> influentialNeighbors;
    private Map<String, Double> attentionScores;
    private String explanationText;
    // Percentile rank cho moduleRank (0-100, cao hơn bao nhiêu % packages khác)
    private Double percentileRank;
}
