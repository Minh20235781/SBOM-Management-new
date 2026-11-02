package com.example.sbom.entity;

import jakarta.persistence.*;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.ArrayList;
import java.util.List;

@Entity
@Table(name = "package")
@Data
@NoArgsConstructor
public class PackageEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable = false)
    private String name;

    private String version;

    private String purl;

    private String type;

    @Column(name = "rank_score")
    private Double rankScore = 0.0;

    @Column(name = "repo_name")
    private String repoName;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "project_id")
    private Project project;

    @OneToMany(mappedBy = "pkg", cascade = CascadeType.ALL, fetch = FetchType.LAZY)
    private List<VulnerabilityEntity> vulnerabilities = new ArrayList<>();

    @OneToMany(mappedBy = "from", cascade = CascadeType.ALL, fetch = FetchType.LAZY)
    private List<DependencyEntity> dependencies = new ArrayList<>();

    @Transient
    private int dependencyDepth = 0;

    @Transient
    private int repoCount = 1;

}