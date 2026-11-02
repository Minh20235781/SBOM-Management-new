package com.example.sbom.gnn.dataset.dto;

import lombok.Data;

/**
 * Feature vector used during dataset assembly before exporting to GraphExportDTO.
 */
@Data
public class DatasetNodeFeatureDTO {
    private String packageName;
    private Integer nodeId;
    private double moduleRank;
    private double maxCvss;
    private double avgCvss;
    private double maxEpss;
    private double avgEpss;
    private int kevCount;
    private int vulnerabilityCount;
    private double severityWeight;
}
