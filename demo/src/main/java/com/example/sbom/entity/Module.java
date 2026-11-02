package com.example.sbom.entity;

import jakarta.persistence.*;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;

/**
 * Logical module inside a project, mapped to a path within a repo.
 */
@Entity
@Table(name = "module",
        uniqueConstraints = {
                @UniqueConstraint(name = "uk_module_project_name",
                        columnNames = {"project_id", "name"})
        },
        indexes = {
                @Index(name = "idx_module_project", columnList = "project_id"),
                @Index(name = "idx_module_repo", columnList = "repo_config_id")
        })
@Data
@NoArgsConstructor
public class Module {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "project_id", nullable = false)
    private Long projectId;

    @Column(name = "repo_config_id")
    private Long repoConfigId;

    @Column(nullable = false, length = 200)
    private String name;

    @Column(name = "path_in_repo", length = 500)
    private String pathInRepo;

    @Column(name = "sbom_pattern", length = 500)
    private String sbomPattern;

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
