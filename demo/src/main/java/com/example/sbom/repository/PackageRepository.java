package com.example.sbom.repository;

import com.example.sbom.entity.PackageEntity;
import com.example.sbom.entity.Project;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Modifying;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface PackageRepository extends JpaRepository<PackageEntity, Long> {
    Optional<PackageEntity> findByPurl(String purl);

    List<PackageEntity> findByRepoName(String repoName);

    @Query("SELECT DISTINCT p FROM PackageEntity p LEFT JOIN FETCH p.vulnerabilities")
    List<PackageEntity> findAllWithVulnerabilities();

    @Query("SELECT DISTINCT p FROM PackageEntity p LEFT JOIN FETCH p.vulnerabilities WHERE p.repoName = :repoName")
    List<PackageEntity> findAllByRepoWithVulnerabilities(@Param("repoName") String repoName);

    @Query("SELECT p FROM PackageEntity p LEFT JOIN FETCH p.vulnerabilities WHERE p.name = :name AND p.repoName = :repoName")
    List<PackageEntity> findByNameAndRepoWithVulnerabilities(@Param("name") String name, @Param("repoName") String repoName);

    @Query("""
    select distinct p from PackageEntity p
    left join fetch p.vulnerabilities
    where p.name = :name
    order by p.version desc
""")
    List<PackageEntity> findByNameWithVulnerabilities(@Param("name") String name);

    /**
     * Bulk-update all packages with project_id = NULL to point at the given
     * project. Used by ProjectAssigner to keep the data layer consistent
     * after the introduction of the Project entity.
     */
    @Modifying
    @Query("UPDATE PackageEntity p SET p.project = :project WHERE p.project IS NULL")
    int assignUnassignedToProject(@Param("project") Project project);

    /**
     * Count packages that belong to the given project. Used by project
     * management to render package counts and to refuse deletion of a
     * non-empty project.
     */
    long countByProjectId(Long projectId);

    List<PackageEntity> findByProjectId(Long projectId);
}
