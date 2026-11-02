package com.example.sbom.repository;

import com.example.sbom.entity.ProjectHistory;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface ProjectHistoryRepository extends JpaRepository<ProjectHistory, Long> {
    List<ProjectHistory> findByProjectIdOrderByChangedAtDesc(Long projectId);
}
