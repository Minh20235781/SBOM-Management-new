package com.example.sbom.entity;

import jakarta.persistence.*;
import lombok.Data;
import lombok.NoArgsConstructor;

@Entity
@Table(name = "dependency")
@Data
@NoArgsConstructor
public class DependencyEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "from_package_id")
    private PackageEntity from;

    @ManyToOne(fetch = FetchType.LAZY)
    @JoinColumn(name = "to_package_id")
    private PackageEntity to;

    private String type; // runtime | dev | optional | third-party
}

