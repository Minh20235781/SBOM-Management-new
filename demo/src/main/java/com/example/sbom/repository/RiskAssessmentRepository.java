package com.example.sbom.repository;

import com.example.sbom.entity.RiskAssessment;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface RiskAssessmentRepository extends JpaRepository<RiskAssessment, Long> {
    List<RiskAssessment> findByProjectIdOrderByAssessedAtDesc(Long projectId);

    Optional<RiskAssessment> findFirstByProjectIdOrderByAssessedAtDesc(Long projectId);

    long countByProjectId(Long projectId);

    /**
     * Wipe all risk-snapshot rows for a project. Used by the
     * "Reset project" flow in Settings.
     */
    @org.springframework.data.jpa.repository.Modifying
    @org.springframework.data.jpa.repository.Query(
        "DELETE FROM RiskAssessment r WHERE r.projectId = :projectId")
    int deleteByProjectId(Long projectId);
}
