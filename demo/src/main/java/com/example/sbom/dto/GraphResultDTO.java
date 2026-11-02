package com.example.sbom.dto;

import com.example.sbom.model.Node;
import com.example.sbom.model.Edge;
import lombok.AllArgsConstructor;
import lombok.Data;

import java.util.List;

@Data
@AllArgsConstructor
public class GraphResultDTO {
    private List<Node> nodes;
    private List<Edge> edges;
}
