package com.example.sbom.entity;

import jakarta.persistence.*;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;

@Entity
@Table(name = "sbom_file_history",
        indexes = {
                @Index(name = "idx_sbom_file_history_file", columnList = "sbom_file_id"),
                @Index(name = "idx_sbom_file_history_changed_at", columnList = "changed_at")
        })
@Data
@NoArgsConstructor
public class SbomFileHistory {

    public enum ChangeType {
        UPLOADED,
        SCAN_STARTED,
        SCAN_COMPLETED,
        SCAN_FAILED,
        DELETED
    }

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "sbom_file_id", nullable = false)
    private Long sbomFileId;

    @Column(name = "module_id", nullable = false)
    private Long moduleId;

    @Column(name = "project_id", nullable = false)
    private Long projectId;

    @Enumerated(EnumType.STRING)
    @Column(name = "change_type", nullable = false, length = 32)
    private ChangeType changeType;

    @Column(name = "scan_status", length = 32)
    private String scanStatus;

    @Column(name = "note", length = 1000)
    private String note;

    @Column(name = "snapshot_json", columnDefinition = "LONGTEXT")
    private String snapshotJson;

    @Column(name = "changed_at", nullable = false)
    private Instant changedAt;

    @PrePersist
    public void prePersist() {
        if (changedAt == null) changedAt = Instant.now();
    }
}
