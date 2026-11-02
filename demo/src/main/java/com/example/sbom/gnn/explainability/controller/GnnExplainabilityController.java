package com.example.sbom.gnn.explainability.controller;

import com.example.sbom.gnn.dto.GnnHealthResponse;
import com.example.sbom.gnn.dto.GraphExportDTO;
import com.example.sbom.gnn.explainability.dto.GnnExplanationDTO;
import com.example.sbom.gnn.explainability.service.GnnExplainabilityService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/**
 * Experimental explainability controller for GNN predictions.
 * This API is isolated from production ML flows and used for research only.
 */
@RestController
@RequestMapping("/api/v2/gnn/explainability")
public class GnnExplainabilityController {

    private static final Logger log = LoggerFactory.getLogger(GnnExplainabilityController.class);

    private final GnnExplainabilityService explainabilityService;

    public GnnExplainabilityController(GnnExplainabilityService explainabilityService) {
        this.explainabilityService = explainabilityService;
    }

    @PostMapping("/analyze")
    public ResponseEntity<List<GnnExplanationDTO>> analyze(@RequestBody GraphExportDTO request) {
        try {
            if (request == null) {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).build();
            }
            log.info("GNN explainability request received");
            return ResponseEntity.ok(explainabilityService.analyze(request));
        } catch (IllegalArgumentException ex) {
            log.warn("GNN explainability input error: {}", ex.getMessage());
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).build();
        } catch (Exception ex) {
            log.error("GNN explainability failed: {}", ex.getMessage(), ex);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    @GetMapping("/health")
    public ResponseEntity<GnnHealthResponse> health() {
        GnnHealthResponse response = new GnnHealthResponse();
        response.setStatus("ok");
        response.setMessage("gnn explainability ready");
        return ResponseEntity.ok(response);
    }
}
