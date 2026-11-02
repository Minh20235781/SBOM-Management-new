package com.example.sbom.ai.ml.dto;

import java.util.List;

import lombok.Data;

/**
 * Response envelope for RF prediction.
 * Mirrors {@code gnn-training/api/rf_server.py::PredictionResponse}.
 */
@Data
public class RfPredictionResponse {
    private List<AiRiskPredictionDTO> items;
}