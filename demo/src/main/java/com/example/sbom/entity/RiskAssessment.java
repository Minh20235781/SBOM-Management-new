package com.example.sbom.entity;

import jakarta.persistence.*;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;

/**
 * Point-in-time risk snapshot for trend tracking.
 */
@Entity
@Table(name = "risk_assessment",
        indexes = {
                @Index(name = "idx_risk_assessment_project", columnList = "project_id"),
                @Index(name = "idx_risk_assessment_module", columnList = "module_id"),
                @Index(name = "idx_risk_assessment_sbom", columnList = "sbom_file_id"),
                @Index(name = "idx_risk_assessment_assessed_at", columnList = "assessed_at")
        })
@Data
@NoArgsConstructor
public class RiskAssessment {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "project_id", nullable = false)
    private Long projectId;

    @Column(name = "module_id")
    private Long moduleId;

    @Column(name = "sbom_file_id")
    private Long sbomFileId;

    @Column(name = "score", nullable = false)
    private Double score;

    @Column(name = "grade", nullable = false, length = 4)
    private String grade;

    @Column(name = "total_packages", nullable = false)
    private Integer totalPackages = 0;

    @Column(name = "total_vulnerabilities", nullable = false)
    private Integer totalVulnerabilities = 0;

    @Column(name = "critical_count", nullable = false)
    private Integer criticalCount = 0;

    @Column(name = "high_count", nullable = false)
    private Integer highCount = 0;

    @Column(name = "medium_count", nullable = false)
    private Integer mediumCount = 0;

    @Column(name = "low_count", nullable = false)
    private Integer lowCount = 0;

    @Column(name = "summary_json", columnDefinition = "LONGTEXT")
    private String summaryJson;

    @Column(name = "assessed_at", nullable = false)
    private Instant assessedAt;

    @PrePersist
    public void prePersist() {
        if (assessedAt == null) assessedAt = Instant.now();
    }
}
