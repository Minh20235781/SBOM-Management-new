package com.example.sbom.gnn.controller;

import com.example.sbom.gnn.dto.GnnHealthResponse;
import com.example.sbom.gnn.dto.GraphExportDTO;
import com.example.sbom.gnn.dto.GraphExportMetadataDTO;
import com.example.sbom.gnn.exporter.JsonGraphExporter;
import com.example.sbom.gnn.service.GraphExportService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Experimental GNN graph export controller.
 * This API is isolated from production graph flows and intended for research only.
 */
@RestController
@RequestMapping("/api/v2/gnn")
public class GraphExportController {

    private static final Logger log = LoggerFactory.getLogger(GraphExportController.class);

    private final GraphExportService graphExportService;
    private final JsonGraphExporter jsonGraphExporter;

    public GraphExportController(GraphExportService graphExportService,
                                 JsonGraphExporter jsonGraphExporter) {
        this.graphExportService = graphExportService;
        this.jsonGraphExporter = jsonGraphExporter;
    }

    /**
     * Export a GNN-ready graph dataset as a JSON file.
     */
    @PostMapping("/export")
    public ResponseEntity<GraphExportMetadataDTO> export(@RequestBody GraphExportDTO request) {
        try {
            if (request == null) {
                return ResponseEntity.status(HttpStatus.BAD_REQUEST).build();
            }
            log.info("GNN export request received");

            GraphExportDTO prepared = graphExportService.prepareExport(request);
            GraphExportMetadataDTO meta = jsonGraphExporter.export(prepared);
            return ResponseEntity.ok(meta);
        } catch (IllegalArgumentException ex) {
            log.warn("GNN export input error: {}", ex.getMessage());
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).build();
        } catch (Exception ex) {
            log.error("GNN export failed: {}", ex.getMessage(), ex);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    /**
     * Health check endpoint for GNN export APIs.
     */
    @GetMapping("/health")
    public ResponseEntity<GnnHealthResponse> health() {
        GnnHealthResponse response = new GnnHealthResponse();
        response.setStatus("ok");
        response.setMessage("gnn export ready");
        return ResponseEntity.ok(response);
    }
}
