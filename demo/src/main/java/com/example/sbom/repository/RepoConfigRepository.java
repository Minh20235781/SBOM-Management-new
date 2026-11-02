package com.example.sbom.repository;

import com.example.sbom.entity.RepoConfig;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface RepoConfigRepository extends JpaRepository<RepoConfig, Long> {
    List<RepoConfig> findByProjectIdOrderByCreatedAtAsc(Long projectId);

    Optional<RepoConfig> findByProjectIdAndRepoUrl(Long projectId, String repoUrl);
}
