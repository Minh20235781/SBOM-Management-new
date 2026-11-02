package com.example.sbom.dto;

import lombok.Data;
import java.util.List;

@Data
public class DependencyGraphResponse {
    private List<GraphNodeDTO> nodes;
    private List<GraphEdgeDTO> edges;
}
