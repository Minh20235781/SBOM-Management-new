package com.example.sbom.ai.ml.controller;

import com.example.sbom.ai.dto.AiAnalysisResponse;
import com.example.sbom.ai.service.AiAnalysisService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

@RestController
@RequestMapping("/api/ai")
@CrossOrigin(origins = "*")
public class AiRiskAnalysisController {

    private static final Logger log = LoggerFactory.getLogger(AiRiskAnalysisController.class);

    private final AiAnalysisService aiAnalysisService;

    public AiRiskAnalysisController(AiAnalysisService aiAnalysisService) {
        this.aiAnalysisService = aiAnalysisService;
    }

    /**
     * AI Risk Analysis on an uploaded SBOM JSON file.
     *
     * This is the Gemini-backed analysis path: parse the SBOM,
     * compute features, then call Gemini (or fall back to a
     * mock when {@code GEMINI_API_KEY} isn't configured) for
     * score/grade/recommendations. The frontend "Risk Analysis"
     * tab on the AI page is wired to this endpoint.
     *
     * Transport note: switched from {@code @RequestBody} JSON to
     * {@code multipart/form-data} so the frontend can upload the
     * raw SBOM file the user picked, mirroring the
     * {@code /api/ai/analyze-upload} contract (field name
     * {@code file}, optional {@code repoName} used only for
     * logging / response context).
     */
    @PostMapping(value = "/risk-analysis", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<AiAnalysisResponse> analyzeRisk(
            @RequestParam("file") MultipartFile file,
            @RequestParam(value = "repoName", required = false) String repoName) {
        try {
            log.info("AI request start: endpoint=/api/ai/risk-analysis, repoName={}, uploadedFile={}",
                    repoName, file.getOriginalFilename());
            AiAnalysisResponse response = aiAnalysisService.analyzeUploadedJson(file);
            if (response == null) {
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
            }
            return ResponseEntity.ok(response);
        } catch (Exception ex) {
            log.error("AI risk analysis failed: {}", ex.getMessage(), ex);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }
}
