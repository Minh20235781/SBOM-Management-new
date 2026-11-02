package com.example.sbom.controller;

import com.example.sbom.entity.VulnStatusHistory;
import com.example.sbom.service.VulnDiffService;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

/**
 * Phase 4 endpoints for inspecting per-vulnerability status changes.
 * The actual writes happen inside {@code RiskAssessmentAspect} — these
 * routes are read-only.
 */
@RestController
@RequestMapping("/api/projects/{projectId}/vuln-history")
public class VulnStatusHistoryController {

 private final VulnDiffService vulnDiffService;

 public VulnStatusHistoryController(VulnDiffService vulnDiffService) {
 this.vulnDiffService = vulnDiffService;
 }

 /**
 * List status history rows for a project, newest first.
 * Optional {@code status} filter accepts: NEW, STILL_OPEN, FIXED, REOPENED.
 * Optional {@code limit} caps the number of rows.
 */
 @GetMapping
 public List<VulnStatusHistory> list(@PathVariable Long projectId,
 @RequestParam(value = "status", required = false) String status,
 @RequestParam(value = "limit", defaultValue = "0") int limit) {
 return vulnDiffService.getHistory(projectId, status, limit);
 }

 /** Aggregate counts per status for the project. */
 @GetMapping("/stats")
 public Map<String, Long> stats(@PathVariable Long projectId) {
 VulnDiffService.Stats s = vulnDiffService.stats(projectId);
 return Map.of(
 "new", s.newCount(),
 "stillOpen", s.stillOpenCount(),
 "fixed", s.fixedCount(),
 "reopened", s.reopenedCount()
 );
 }
}
