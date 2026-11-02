package com.example.sbom.gnn.dataset.controller;

import com.example.sbom.gnn.dataset.dto.DatasetBuildRequestDTO;
import com.example.sbom.gnn.dataset.dto.DatasetBuildResponseDTO;
import com.example.sbom.gnn.dataset.service.DatasetBuildService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Experimental dataset builder endpoint for GNN research.
 *
 * This endpoint is isolated from production SBOM flows and only generates
 * GNN-ready JSON exports for model training and research.
 */
@RestController
@RequestMapping("/api/v2/gnn/dataset")
public class DatasetBuildController {

    private static final Logger log = LoggerFactory.getLogger(DatasetBuildController.class);

    private final DatasetBuildService datasetBuildService;

    public DatasetBuildController(DatasetBuildService datasetBuildService) {
        this.datasetBuildService = datasetBuildService;
    }

    @PostMapping("/build")
    public ResponseEntity<DatasetBuildResponseDTO> build(@RequestBody(required = false) DatasetBuildRequestDTO request) {
        try {
            log.info("GNN dataset build request received");
            return ResponseEntity.ok(datasetBuildService.build(request));
        } catch (IllegalArgumentException ex) {
            log.warn("GNN dataset build input error: {}", ex.getMessage());
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).build();
        } catch (Exception ex) {
            log.error("GNN dataset build failed: {}", ex.getMessage(), ex);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }
}
