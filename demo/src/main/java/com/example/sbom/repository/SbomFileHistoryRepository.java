package com.example.sbom.repository;

import com.example.sbom.entity.SbomFileHistory;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface SbomFileHistoryRepository extends JpaRepository<SbomFileHistory, Long> {
 List<SbomFileHistory> findBySbomFileIdOrderByChangedAtDesc(Long sbomFileId);

 /** Phase 5: feed the cross-entity audit timeline. */
 List<SbomFileHistory> findByProjectIdOrderByChangedAtDesc(Long projectId);
}
