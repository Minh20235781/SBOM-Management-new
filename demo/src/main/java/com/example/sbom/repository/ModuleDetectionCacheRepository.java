package com.example.sbom.repository;

import com.example.sbom.entity.ModuleDetectionCache;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface ModuleDetectionCacheRepository extends JpaRepository<ModuleDetectionCache, Long> {
    Optional<ModuleDetectionCache> findByProjectIdAndRepoSignature(Long projectId, String repoSignature);
}
