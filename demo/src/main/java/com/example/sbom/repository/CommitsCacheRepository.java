package com.example.sbom.repository;

import com.example.sbom.entity.CommitsCache;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface CommitsCacheRepository extends JpaRepository<CommitsCache, Long> {
    Optional<CommitsCache> findByProjectIdAndRepoSignature(Long projectId, String repoSignature);
}
