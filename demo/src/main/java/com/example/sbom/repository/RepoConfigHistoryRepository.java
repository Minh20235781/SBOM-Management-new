package com.example.sbom.repository;

import com.example.sbom.entity.RepoConfigHistory;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface RepoConfigHistoryRepository extends JpaRepository<RepoConfigHistory, Long> {
 List<RepoConfigHistory> findByRepoConfigIdOrderByChangedAtDesc(Long repoConfigId);

 /** Phase 5: feed the cross-entity audit timeline. */
 List<RepoConfigHistory> findByProjectIdOrderByChangedAtDesc(Long projectId);
}
