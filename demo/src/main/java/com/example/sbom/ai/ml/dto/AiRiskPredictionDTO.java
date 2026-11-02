package com.example.sbom.ai.ml.dto;

import lombok.Data;

@Data
public class AiRiskPredictionDTO {
    private String packageName;
    private String version;
    private String predictedRisk;
    private double confidence;
    private double probabilityLow;
    private double probabilityMedium;
    private double probabilityHigh;
}
