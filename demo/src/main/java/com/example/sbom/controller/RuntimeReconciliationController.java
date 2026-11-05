package com.example.sbom.controller;

import com.example.sbom.dto.reconciliation.AiDiffEvaluationRequest;
import com.example.sbom.dto.reconciliation.AiDiffEvaluationResponse;
import com.example.sbom.dto.reconciliation.CompareSbomsRequest;
import com.example.sbom.dto.reconciliation.RuntimeReconciliationRequest;
import com.example.sbom.dto.reconciliation.RuntimeReconciliationResponse;
import com.example.sbom.poc.MatchReport;
import com.example.sbom.poc.PocMatchRequest;
import com.example.sbom.poc.PocReconciliationService;
import com.example.sbom.service.reconciliation.RuntimeReconciliationService;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

/**
 * Controller phục vụ API Đối sánh SBOM theo phong cách Track Changes (MS Word)
 * giữa 2 nguồn đầu vào: Build-time SBOM vs Runtime SBOM (hoặc 2 file SBOM bất kỳ).
 * Tích hợp AI Engine phân tích động chi tiết cho từng điểm khác biệt.
 */
@RestController
@RequestMapping("/api/reconciliation")
@RequiredArgsConstructor
@CrossOrigin(origins = "*")
public class RuntimeReconciliationController {

    private final RuntimeReconciliationService reconciliationService;
    private final PocReconciliationService pocService;

    /**
     * API đối sánh giữa 2 nguồn SBOM (Base SBOM vs Target SBOM / 2 nguồn đầu vào)
     */
    @PostMapping("/compare-sboms")
    public ResponseEntity<RuntimeReconciliationResponse> compareSboms(
            @RequestBody CompareSbomsRequest request) {
        return ResponseEntity.ok(reconciliationService.compareSboms(request));
    }

    /**
     * API đối sánh trực tiếp 2 tệp SBOM được tải lên (CycloneDX / SPDX JSON)
     */
    @PostMapping(value = "/compare-files", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<RuntimeReconciliationResponse> compareFiles(
            @RequestParam("file1") MultipartFile file1,
            @RequestParam("file2") MultipartFile file2) {
        return ResponseEntity.ok(reconciliationService.compareSbomFiles(file1, file2));
    }

    /**
     * API đánh giá AI động theo yêu cầu cho một điểm khác biệt cụ thể
     */
    @PostMapping("/ai-evaluate-diff")
    public ResponseEntity<AiDiffEvaluationResponse> aiEvaluateDiff(
            @RequestBody AiDiffEvaluationRequest request) {
        return ResponseEntity.ok(reconciliationService.evaluateDiff(request));
    }

    /**
     * API đối sánh động dựa trên payload runtime gửi lên
     */
    @PostMapping("/reconcile")
    public ResponseEntity<RuntimeReconciliationResponse> reconcile(
            @RequestBody RuntimeReconciliationRequest request) {
        return ResponseEntity.ok(reconciliationService.reconcile(request));
    }

    /**
     * API demo các kịch bản đối sánh
     */
    @GetMapping("/demo-iteration")
    public ResponseEntity<RuntimeReconciliationResponse> getDemoIteration(
            @RequestParam(required = false, defaultValue = "1") Long projectId,
            @RequestParam(defaultValue = "1") int iteration) {
        return ResponseEntity.ok(reconciliationService.getDemoIteration(projectId, iteration));
    }

    /**
     * API quét trực tiếp toàn bộ thư viện đang nạp trong RAM JVM bằng Java Reflection
     */
    @GetMapping("/inspect-jvm")
    public ResponseEntity<?> inspectJvm() {
        return ResponseEntity.ok(reconciliationService.inspectLiveJvm());
    }

    /**
     * API kết hợp: Dùng Java Reflection quét JVM thật và tự động đối sánh với SBOM tĩnh của dự án
     */
    @GetMapping("/live-reconcile")
    public ResponseEntity<RuntimeReconciliationResponse> liveReconcile(
            @RequestParam(required = false, defaultValue = "1") Long projectId,
            @RequestParam(required = false) String repoName) {
        return ResponseEntity.ok(reconciliationService.reconcileLiveJvm(projectId, repoName));
    }

    /**
     * API chạy web trên browser / F12 và sinh tệp SBOM Runtime chuẩn CycloneDX JSON
     */
    @PostMapping("/generate-runtime-sbom")
    public ResponseEntity<?> generateRuntimeSbom(@RequestBody java.util.Map<String, Object> request) {
        return ResponseEntity.ok(reconciliationService.generateRuntimeSbom(request));
    }

    /**
     * API tiếp nhận dữ liệu F12 Network stream từ trang web mục tiêu (Đồng bộ 2 màn hình)
     */
    @PostMapping("/live-f12-stream")
    public ResponseEntity<?> receiveLiveF12Stream(@RequestBody java.util.Map<String, Object> payload) {
        return ResponseEntity.ok(reconciliationService.receiveLiveF12Stream(payload));
    }

    /**
     * API SSE: Đẩy luồng sự kiện F12 Network theo thời gian thực (Real-time Server-Sent Events)
     */
    @GetMapping(value = "/live-f12-stream/sse", produces = org.springframework.http.MediaType.TEXT_EVENT_STREAM_VALUE)
    public org.springframework.web.servlet.mvc.method.annotation.SseEmitter subscribeLiveF12Stream() {
        return reconciliationService.subscribeLiveF12Stream();
    }

    /**
     * API lấy dữ liệu Live F12 stream mới nhất được gửi từ trang web mục tiêu
     */
    @GetMapping("/live-f12-stream")
    public ResponseEntity<?> getLatestLiveF12Stream() {
        java.util.Map<String, Object> stream = reconciliationService.getLatestLiveF12Stream();
        if (stream == null) {
            return ResponseEntity.ok(java.util.Map.of("connected", false, "message", "Chưa có tab web nào kết nối Live F12"));
        }
        return ResponseEntity.ok(java.util.Map.of("connected", true, "data", stream));
    }

    /**
     * API tiếp nhận dữ liệu Runtime SBOM từ Node.js / Express / NestJS Agent
     */
    @PostMapping("/node-agent-collector")
    public ResponseEntity<?> receiveNodeAgentReport(
            @RequestBody com.example.sbom.dto.reconciliation.NodeAgentReportRequest request) {
        return ResponseEntity.ok(reconciliationService.receiveNodeAgentReport(request));
    }

    /**
     * API lấy thông tin snapshot mới nhất do Node.js Agent gửi lên
     */
    @GetMapping("/latest-node-agent")
    public ResponseEntity<?> getLatestNodeAgentReport() {
        com.example.sbom.dto.reconciliation.NodeAgentReportRequest report = reconciliationService.getLatestNodeAgentReport();
        if (report == null) {
            return ResponseEntity.ok(java.util.Map.of("connected", false, "message", "Chưa có Agent Node.js nào kết nối"));
        }
        return ResponseEntity.ok(java.util.Map.of(
                "connected", true,
                "appName", report.getAppName() != null ? report.getAppName() : "NodeApp",
                "pid", report.getPid() != null ? report.getPid() : "unknown",
                "timestamp", report.getTimestamp() != null ? report.getTimestamp() : "",
                "packageCount", report.getPackages() != null ? report.getPackages().size() : 0,
                "packages", report.getPackages() != null ? report.getPackages() : java.util.Collections.emptyList(),
                "memorySnapshot", report.getMemorySnapshot() != null ? report.getMemorySnapshot() : java.util.Map.of()
        ));
    }

    /**
     * API đối sánh chuẩn POC: CycloneDX/SPDX static SBOM vs Runtime HAR / Network JSON
     */
    @PostMapping("/poc/match")
    public ResponseEntity<MatchReport> matchPoc(@RequestBody PocMatchRequest request) {
        return ResponseEntity.ok(pocService.match(request.getSbomContentAsString(), request.getHarContentAsString()));
    }

    /**
     * API đối sánh chuẩn POC từ 2 file tải lên trực tiếp (Static SBOM JSON và HAR/Runtime JSON)
     */
    @PostMapping(value = "/poc/match-files", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<MatchReport> matchPocFiles(
            @RequestParam(value = "sbomFile", required = false) MultipartFile sbomFile,
            @RequestParam(value = "harFile", required = false) MultipartFile harFile) {
        return ResponseEntity.ok(pocService.matchFiles(sbomFile, harFile));
    }

    /**
     * API xuất báo cáo đối sánh ra định dạng CSV (UTF-8 có BOM cho Excel)
     */
    @PostMapping("/poc/export-csv")
    public ResponseEntity<byte[]> exportPocCsv(@RequestBody MatchReport report) {
        byte[] csvBytes = pocService.exportCsvBytes(report);
        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\"matching-results.csv\"")
                .contentType(MediaType.parseMediaType("text/csv; charset=UTF-8"))
                .body(csvBytes);
    }
}
