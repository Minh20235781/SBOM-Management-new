package com.example.sbom.gnn.dto;

import lombok.Data;

/**
 * Health response for experimental GNN export APIs.
 */
@Data
public class GnnHealthResponse {
    private String status;
    private String message;
}
