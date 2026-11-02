package com.example.sbom.dto;

import lombok.Data;

@Data
public class GraphNodeDTO {
    private String id;
    private double rankScore;
    private int vulnCount;
    private int dependencyDepth;
}
