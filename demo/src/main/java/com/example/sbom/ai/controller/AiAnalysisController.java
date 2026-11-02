package com.example.sbom.ai.controller;

import com.example.sbom.ai.dto.AiAnalysisResponse;
import com.example.sbom.ai.service.AiAnalysisService;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

@RestController
@RequestMapping("/api/ai")
@CrossOrigin(origins = "*")
public class AiAnalysisController {

    private static final Logger log = LoggerFactory.getLogger(AiAnalysisController.class);

    private final AiAnalysisService aiAnalysisService;
    // Xóa OpenAiService vì không dùng nữa

    public AiAnalysisController(AiAnalysisService aiAnalysisService) {
        // Chỉ inject AiAnalysisService
        this.aiAnalysisService = aiAnalysisService;
    }

    @PostMapping(value = "/analyze-upload", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<AiAnalysisResponse> analyzeUpload(
            @RequestParam("file") MultipartFile file,
            @RequestParam(value = "repoName", required = false) String repoName) {

        try {
            log.info("Starting AI analysis for file: {} (repoName: {})",
                    file.getOriginalFilename(), repoName);

            AiAnalysisResponse resp = aiAnalysisService.analyzeUploadedJson(file);

            // Set repo name if provided (you may want to add this field to response)
            if (repoName != null && resp.getScoreData() != null) {
                // If you want to store repoName somewhere, add it to RepoScoreDTO
                log.info("Analysis completed for repo: {}", repoName);
            }

            return ResponseEntity.ok(resp);

        } catch (Exception e) {
            log.error("Error during AI analysis: {}", e.getMessage(), e);

            AiAnalysisResponse errorResp = new AiAnalysisResponse();
            errorResp.setSuccess(false);
            errorResp.setAiRawResponse("Controller error: " + e.getMessage());

            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(errorResp);
        }
    }

    @GetMapping("/test")
    public ResponseEntity<String> testAi() {
        try {
            return ResponseEntity.ok("Gemini AI service is configured");
        } catch (Exception e) {
            log.error("AI test failed: {}", e.getMessage(), e);
            return ResponseEntity.status(HttpStatus.BAD_GATEWAY)
                    .body("AI test failed: " + e.getMessage());
        }
    }

    @GetMapping("/test-service")
    public ResponseEntity<String> testService() {
        try {
            String result = aiAnalysisService.test();
            return ResponseEntity.ok("Service test: " + result);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("Service test failed: " + e.getMessage());
        }
    }
}