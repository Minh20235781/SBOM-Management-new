package com.example.sbom.entity;

import jakarta.persistence.*;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;

/**
 * SBOM file record with upload metadata and scan status.
 */
@Entity
@Table(name = "sbom_file",
        indexes = {
                @Index(name = "idx_sbom_file_module", columnList = "module_id"),
                @Index(name = "idx_sbom_file_uploaded_at", columnList = "uploaded_at")
        })
@Data
@NoArgsConstructor
public class SbomFile {

    public enum ScanStatus {
        PENDING,
        SCANNING,
        COMPLETED,
        FAILED
    }

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "module_id", nullable = false)
    private Long moduleId;

    @Column(name = "file_name", nullable = false, length = 500)
    private String fileName;

    @Column(name = "sha256", length = 64)
    private String sha256;

    @Column(name = "size_bytes")
    private Long sizeBytes;

    @Column(name = "source", length = 50)
    private String source = "UPLOAD";

    @Enumerated(EnumType.STRING)
    @Column(name = "scan_status", length = 32, nullable = false)
    private ScanStatus scanStatus = ScanStatus.PENDING;

    @Column(name = "uploaded_at", nullable = false, updatable = false)
    private Instant uploadedAt;

    @PrePersist
    public void prePersist() {
        if (uploadedAt == null) uploadedAt = Instant.now();
    }
}
