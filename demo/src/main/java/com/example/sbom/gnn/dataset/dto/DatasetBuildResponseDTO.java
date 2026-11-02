package com.example.sbom.gnn.dataset.dto;

import lombok.Data;

import java.util.List;

/**
 * Response metadata for dataset export results.
 */
@Data
public class DatasetBuildResponseDTO {
    private String exportPath;
    private String exportTimestamp;
    private int nodeCount;
    private int edgeCount;
    private int packageCount;
    private int repoCount;
    private List<String> repoNames;
}
