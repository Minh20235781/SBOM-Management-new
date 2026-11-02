package com.example.sbom.threatintel.dto;

import lombok.Data;

@Data
public class ThreatIntelDTO {
    private String cveId;
    private double epssScore;
    private boolean kevExploited;
}
