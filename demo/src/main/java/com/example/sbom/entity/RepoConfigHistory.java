package com.example.sbom.entity;

import jakarta.persistence.*;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;

/**
 * Per-mutation snapshot of a {@link RepoConfig}. See {@link ProjectHistory}
 * for rationale on the "one history table per entity" model.
 */
@Entity
@Table(name = "repo_config_history",
        indexes = {
                @Index(name = "idx_repo_config_history_repo", columnList = "repo_config_id"),
                @Index(name = "idx_repo_config_history_changed_at", columnList = "changed_at")
        })
@Data
@NoArgsConstructor
public class RepoConfigHistory {

    public enum ChangeType {
        CREATED,
        UPDATED,
        DELETED
    }

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "repo_config_id", nullable = false)
    private Long repoConfigId;

    @Column(name = "project_id", nullable = false)
    private Long projectId;

    @Column(name = "version", nullable = false)
    private Integer version;

    @Enumerated(EnumType.STRING)
    @Column(name = "change_type", nullable = false, length = 32)
    private ChangeType changeType;

    @Column(name = "snapshot_json", columnDefinition = "LONGTEXT", nullable = false)
    private String snapshotJson;

    @Column(name = "changed_at", nullable = false)
    private Instant changedAt;

    @PrePersist
    public void prePersist() {
        if (changedAt == null) changedAt = Instant.now();
    }
}
