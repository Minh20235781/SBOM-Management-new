package com.example.sbom.entity;

import jakarta.persistence.*;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;

/**
 * Per-project vulnerability lifecycle tracking (NEW, STILL_OPEN, FIXED, REOPENED).
 */
@Entity
@Table(name = "vuln_status_history",
 indexes = {
 @Index(name = "idx_vsh_project_vuln", columnList = "project_id, vuln_id"),
 @Index(name = "idx_vsh_project_last_seen", columnList = "project_id, last_seen_at"),
 @Index(name = "idx_vsh_status", columnList = "status")
 })
@Data
@NoArgsConstructor
public class VulnStatusHistory {

 public enum Status {
 NEW,
 STILL_OPEN,
 FIXED,
 REOPENED
 }

 @Id
 @GeneratedValue(strategy = GenerationType.IDENTITY)
 private Long id;

 @Column(name = "project_id", nullable = false)
 private Long projectId;

 @Column(name = "vuln_id", nullable = false, length = 100)
 private String vulnId;

 @Column(name = "package_purl", length = 500)
 private String packagePurl;

 @Enumerated(EnumType.STRING)
 @Column(name = "status", nullable = false, length = 16)
 private Status status;

 @Column(name = "severity", length = 32)
 private String severity;

 @Column(name = "cvss_score")
 private Double cvssScore;

 @Column(name = "first_seen_at", nullable = false)
 private Instant firstSeenAt;

 @Column(name = "last_seen_at", nullable = false)
 private Instant lastSeenAt;

 @Column(name = "resolved_at")
 private Instant resolvedAt;

 @Column(name = "fixed_in_version", length = 100)
 private String fixedInVersion;

 @Column(name = "scan_id")
 private Long scanId;

 @PrePersist
 public void prePersist() {
 Instant now = Instant.now();
 if (firstSeenAt == null) firstSeenAt = now;
 if (lastSeenAt == null) lastSeenAt = now;
 }
}
