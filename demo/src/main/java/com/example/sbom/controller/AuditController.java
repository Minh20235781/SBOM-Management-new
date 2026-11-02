package com.example.sbom.controller;

import com.example.sbom.dto.AuditEventDTO;
import com.example.sbom.service.TimelineAggregatorService;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.server.ResponseStatusException;

import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.List;

/**
 * Phase 5: cross-entity audit timeline. Returns a unified, time-sorted
 * list of events for one project, drawn from the six history sources.
 *
 * Example:
 * <pre>
 * GET /api/audit?projectId=1&amp;type=VULN&amp;from=2025-06-01T00:00:00Z&amp;limit=50
 * </pre>
 */
@RestController
@RequestMapping("/api/audit")
public class AuditController {

 private final TimelineAggregatorService aggregator;

 public AuditController(TimelineAggregatorService aggregator) {
 this.aggregator = aggregator;
 }

 @GetMapping
 public List<AuditEventDTO> timeline(@RequestParam("projectId") Long projectId,
 @RequestParam(value = "type", required = false) String type,
 @RequestParam(value = "from", required = false) String from,
 @RequestParam(value = "to", required = false) String to,
 @RequestParam(value = "limit", required = false) Integer limit) {
 if (projectId == null) {
 throw new ResponseStatusException(HttpStatus.BAD_REQUEST, "projectId is required");
 }
 AuditEventDTO.Type typeFilter = parseType(type);
 Instant fromTs = parseInstant(from, "from");
 Instant toTs = parseInstant(to, "to");
 return aggregator.getTimeline(projectId, typeFilter, fromTs, toTs, limit);
 }

 private static AuditEventDTO.Type parseType(String raw) {
 if (raw == null || raw.isBlank()) return null;
 try {
 return AuditEventDTO.Type.valueOf(raw.toUpperCase());
 } catch (IllegalArgumentException e) {
 throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
 "Unknown type: " + raw + ". Allowed: PROJECT, MODULE, REPO_CONFIG, SBOM_FILE, RISK_ASSESSMENT, VULN");
 }
 }

 private static Instant parseInstant(String raw, String paramName) {
 if (raw == null || raw.isBlank()) return null;
 try {
 return Instant.parse(raw);
 } catch (DateTimeParseException e) {
 throw new ResponseStatusException(HttpStatus.BAD_REQUEST,
 paramName + " must be ISO-8601 instant (e.g. 2025-06-01T00:00:00Z). Got: " + raw);
 }
 }
}
