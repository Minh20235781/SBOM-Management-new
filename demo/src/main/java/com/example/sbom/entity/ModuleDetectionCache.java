package com.example.sbom.entity;

import jakarta.persistence.*;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;

/**
 * Cached module detection results keyed by project and repo signature.
 */
@Entity
@Table(name = "module_detection_cache",
        uniqueConstraints = {
                @UniqueConstraint(name = "uk_module_cache_project_repo",
                        columnNames = {"project_id", "repo_signature"})
        },
        indexes = {
                @Index(name = "idx_module_cache_project", columnList = "project_id")
        })
@Data
@NoArgsConstructor
public class ModuleDetectionCache {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "project_id", nullable = false)
    private Long projectId;

    @Column(name = "repo_signature", nullable = false, length = 400)
    private String repoSignature;

    @Column(name = "owner", length = 200)
    private String owner;

    @Column(name = "repo", length = 200)
    private String repo;

    @Column(name = "default_branch", length = 200)
    private String defaultBranch;

    @Column(name = "build_system", length = 64)
    private String buildSystem;

    @Column(name = "modules_json", columnDefinition = "LONGTEXT")
    private String modulesJson;

    @Column(name = "error_message", length = 500)
    private String errorMessage;

    @Column(name = "fetched_at", nullable = false)
    private Instant fetchedAt;
}
