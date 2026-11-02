package com.example.sbom.repository;

import com.example.sbom.entity.ModuleHistory;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface ModuleHistoryRepository extends JpaRepository<ModuleHistory, Long> {
 List<ModuleHistory> findByModuleIdOrderByChangedAtDesc(Long moduleId);

 /** Phase 5: feed the cross-entity audit timeline. */
 List<ModuleHistory> findByProjectIdOrderByChangedAtDesc(Long projectId);
}
