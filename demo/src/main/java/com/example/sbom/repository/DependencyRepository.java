package com.example.sbom.repository;

import com.example.sbom.entity.DependencyEntity;
import com.example.sbom.entity.PackageEntity;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;

import java.util.List;

public interface DependencyRepository extends JpaRepository<DependencyEntity, Long> {
    List<DependencyEntity> findByFrom_RepoName(String repoName);

    boolean existsByFromAndToAndType(PackageEntity from, PackageEntity to, String type);

    @Query("""
    select d from DependencyEntity d
    join fetch d.from
    join fetch d.to
    where d.from.name = :name or d.to.name = :name
""")
    List<DependencyEntity> findLocalGraph(@Param("name") String name);
}