package com.example.sbom.repository;

import com.example.sbom.entity.SbomFile;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface SbomFileRepository extends JpaRepository<SbomFile, Long> {
    List<SbomFile> findByModuleIdOrderByUploadedAtDesc(Long moduleId);

    long countByModuleId(Long moduleId);
}
