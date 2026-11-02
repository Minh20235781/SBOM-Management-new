package com.example.sbom.ai.ml.controller;

import com.example.sbom.ai.ml.dto.AiRiskPredictionDTO;
import com.example.sbom.ai.ml.dto.RfPredictionResponse;
import com.example.sbom.ai.ml.service.ZenodoRfPredictionService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

/**
 * AI-RF Score endpoint using the 13-feature Zenodo RF model.
 * Exposed at /api/ai/rf-new/predict/{repoName}.
 */
@RestController
@RequestMapping("/api/ai")
public class RfNewPredictionController {

    private static final Logger log = LoggerFactory.getLogger(RfNewPredictionController.class);

    private final ZenodoRfPredictionService zenodoRfService;

    public RfNewPredictionController(ZenodoRfPredictionService zenodoRfService) {
        this.zenodoRfService = zenodoRfService;
    }

    @GetMapping("/rf-new/predict/{repoName}")
    public ResponseEntity<RfPredictionResponse> predict(@PathVariable String repoName) {
        try {
            log.info("AI request start: endpoint=/api/ai/rf-new/predict, repoName={}", repoName);
            List<AiRiskPredictionDTO> predictions = zenodoRfService.predictForRepo(repoName);

            RfPredictionResponse response = new RfPredictionResponse();
            response.setItems(predictions);
            return ResponseEntity.ok(response);
        } catch (IllegalArgumentException ex) {
            log.warn("Zenodo RF prediction input error: {}", ex.getMessage());
            return ResponseEntity.status(HttpStatus.BAD_REQUEST).build();
        } catch (Exception ex) {
            log.error("Zenodo RF prediction failed: {}", ex.getMessage(), ex);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }
}