package com.example.sbom.gnn.dataset.dto;

import lombok.Data;

import java.util.List;

/**
 * Request options for building an experimental GNN dataset.
 */
@Data
public class DatasetBuildRequestDTO {
    private List<String> repoNames;
    private boolean includeAllRepos = false;
}
