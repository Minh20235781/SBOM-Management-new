package com.example.sbom.dto;

import lombok.Data;

import java.time.Instant;
import java.util.Map;

/**
 * Single entry in the cross-entity audit timeline.
 */
@Data
public class AuditEventDTO {

 public enum Type {
 PROJECT,
 MODULE,
 REPO_CONFIG,
 SBOM_FILE,
 RISK_ASSESSMENT,
 VULN
 }

 private Instant timestamp;
 private Type type;
 private String action;
 private String entityId;
 private String entityName;
 private String summary;
 private Map<String, Object> details;
}
