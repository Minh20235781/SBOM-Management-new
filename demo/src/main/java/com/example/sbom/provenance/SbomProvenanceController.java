package com.example.sbom.provenance;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.nio.charset.StandardCharsets;
import java.util.Map;

@RestController
@RequestMapping("/api/provenance")
@CrossOrigin(origins = "*")
@RequiredArgsConstructor
@Slf4j
public class SbomProvenanceController {

    private final SbomProvenanceService provenanceService;
    private final ObjectMapper objectMapper = new ObjectMapper();

    /**
     * Tải file SBOM tĩnh lên để kiểm tra và chuẩn hóa nguồn gốc
     */
    @PostMapping(value = "/validate-and-normalize", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<?> validateAndNormalizeSbom(@RequestParam("file") MultipartFile file) {
        if (file.isEmpty()) {
            return ResponseEntity.badRequest().body(Map.of("error", "Vui lòng chọn tệp SBOM cần chuẩn hóa."));
        }

        try {
            String content = new String(file.getBytes(), StandardCharsets.UTF_8);
            ProvenanceResultDTO result = provenanceService.processProvenance(content);
            return ResponseEntity.ok(result);
        } catch (Exception e) {
            log.error("Lỗi xử lý xác thực nguồn gốc SBOM: {}", e.getMessage(), e);
            return ResponseEntity.internalServerError().body(Map.of("error", "Lỗi xử lý SBOM: " + e.getMessage()));
        }
    }

    /**
     * Tải trực tiếp nội dung JSON dạng chuỗi
     */
    @PostMapping(value = "/validate-and-normalize-json", consumes = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<?> validateAndNormalizeJson(@RequestBody String rawJson) {
        try {
            ProvenanceResultDTO result = provenanceService.processProvenance(rawJson);
            return ResponseEntity.ok(result);
        } catch (Exception e) {
            log.error("Lỗi xử lý xác thực nguồn gốc SBOM JSON: {}", e.getMessage(), e);
            return ResponseEntity.internalServerError().body(Map.of("error", "Lỗi xử lý SBOM: " + e.getMessage()));
        }
    }

    /**
     * Tải xuống file SBOM JSON đã được làm giàu thông tin pedigree
     */
    @PostMapping("/export-enriched")
    public ResponseEntity<byte[]> exportEnrichedSbom(@RequestBody Map<String, Object> enrichedSbomJson) {
        try {
            byte[] bytes = objectMapper.writerWithDefaultPrettyPrinter().writeValueAsBytes(enrichedSbomJson);
            return ResponseEntity.ok()
                    .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"normalized-provenance-sbom.json\"")
                    .contentType(MediaType.APPLICATION_JSON)
                    .body(bytes);
        } catch (Exception e) {
            return ResponseEntity.internalServerError().build();
        }
    }
}

