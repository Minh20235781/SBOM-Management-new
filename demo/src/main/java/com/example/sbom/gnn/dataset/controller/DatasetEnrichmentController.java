package com.example.sbom.gnn.dataset.controller;

import com.example.sbom.gnn.dataset.dto.DatasetGraphEnrichRequestDTO;
import com.example.sbom.gnn.dataset.service.GraphThreatEnrichmentService;
import com.example.sbom.gnn.dto.GraphExportMetadataDTO;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Experimental threat-intel enrichment endpoint for raw graph exports.
 */
@RestController
@RequestMapping("/api/v2/gnn/dataset")
public class DatasetEnrichmentController {

    private static final Logger log = LoggerFactory.getLogger(DatasetEnrichmentController.class);

    private final GraphThreatEnrichmentService enrichmentService;

    public DatasetEnrichmentController(GraphThreatEnrichmentService enrichmentService) {
        this.enrichmentService = enrichmentService;
    }

    @PostMapping("/enrich")
    public ResponseEntity<GraphExportMetadataDTO> enrich(@RequestBody DatasetGraphEnrichRequestDTO request) {
        try {
            log.info("GNN graph enrichment request received");
            return ResponseEntity.ok(enrichmentService.enrichAndExport(request));
        } catch (IllegalArgumentException ex) {
            log.warn("GNN graph enrichment input error: {}", ex.getMessage());
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).build();
        } catch (Exception ex) {
            log.error("GNN graph enrichment failed: {}", ex.getMessage(), ex);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }
}
