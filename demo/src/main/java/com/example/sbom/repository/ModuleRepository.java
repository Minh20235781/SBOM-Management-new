package com.example.sbom.repository;

import com.example.sbom.entity.Module;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface ModuleRepository extends JpaRepository<Module, Long> {
    List<Module> findByProjectIdOrderByCreatedAtAsc(Long projectId);

    Optional<Module> findByProjectIdAndName(Long projectId, String name);

    long countByRepoConfigId(Long repoConfigId);
}
