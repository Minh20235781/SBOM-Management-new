package com.example.sbom.entity;

import jakarta.persistence.*;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;

/**
 * Per-project repository configuration with scan schedule and tool settings.
 */
@Entity
@Table(name = "repo_config",
        uniqueConstraints = {
                @UniqueConstraint(name = "uk_repo_config_project_url",
                        columnNames = {"project_id", "repo_url"})
        },
        indexes = {
                @Index(name = "idx_repo_config_project", columnList = "project_id")
        })
@Data
@NoArgsConstructor
public class RepoConfig {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "project_id", nullable = false)
    private Long projectId;

    @Column(name = "repo_url", nullable = false, length = 500)
    private String repoUrl;

    @Column(nullable = false, length = 200)
    private String branch = "main";

    @Column(name = "scan_schedule", length = 100)
    private String scanSchedule;

    @Column(name = "scan_tool", length = 50)
    private String scanTool = "TRIVY";

    @Column(name = "last_scan_at")
    private Instant lastScanAt;

    @Column(name = "version", nullable = false)
    private Integer version = 1;

    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;

    @Column(name = "updated_at", nullable = false)
    private Instant updatedAt;

    @PrePersist
    public void prePersist() {
        Instant now = Instant.now();
        if (createdAt == null) createdAt = now;
        updatedAt = now;
    }

    @PreUpdate
    public void preUpdate() {
        updatedAt = Instant.now();
    }
}
