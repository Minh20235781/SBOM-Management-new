package com.example.sbom.gnn.dataset.dto;

import com.example.sbom.gnn.dto.GraphExportDTO;
import lombok.Data;

/**
 * Request payload for enriching a raw graph export with threat-intel features.
 */
@Data
public class DatasetGraphEnrichRequestDTO {
    private String repoName;
    private GraphExportDTO graph;
}
