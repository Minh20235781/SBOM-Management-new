package com.example.sbom.entity;

import jakarta.persistence.*;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;

/**
 * Project mutation history with full snapshot for diffs.
 */
@Entity
@Table(name = "project_history",
        indexes = {
                @Index(name = "idx_project_history_project", columnList = "project_id"),
                @Index(name = "idx_project_history_changed_at", columnList = "changed_at")
        })
@Data
@NoArgsConstructor
public class ProjectHistory {

    public enum ChangeType {
        CREATED,
        UPDATED,
        DELETED,
        RESTORED
    }

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

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
        if (changedAt == null) {
            changedAt = Instant.now();
        }
    }
}
