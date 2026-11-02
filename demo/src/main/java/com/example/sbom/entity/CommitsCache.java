package com.example.sbom.entity;

import jakarta.persistence.*;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.Instant;

/** Cached GitHub commits for a project. */
@Entity
@Table(name = "commits_cache",
        uniqueConstraints = {
                @UniqueConstraint(name = "uk_commits_cache_project_repo",
                        columnNames = {"project_id", "repo_signature"})
        },
        indexes = {
                @Index(name = "idx_commits_cache_project", columnList = "project_id")
        })
@Data
@NoArgsConstructor
public class CommitsCache {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "project_id", nullable = false)
    private Long projectId;

    @Column(name = "repo_signature", nullable = false, length = 400)
    private String repoSignature;

    @Column(name = "commits_json", columnDefinition = "LONGTEXT")
    private String commitsJson;

    @Column(name = "fetched_at", nullable = false)
    private Instant fetchedAt;
}
