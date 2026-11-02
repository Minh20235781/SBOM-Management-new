package com.example.sbom.service.graph;

import com.example.sbom.dto.GraphResultDTO;
import com.example.sbom.entity.DependencyEntity;
import com.example.sbom.entity.PackageEntity;
import com.example.sbom.model.Edge;
import com.example.sbom.model.Node;
import com.example.sbom.repository.DependencyRepository;
import com.example.sbom.repository.PackageRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

import java.util.*;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class GraphBuilderService {

    private final PackageRepository packageRepository;
    private final DependencyRepository dependencyRepository;

    public GraphResultDTO buildGraphByRepo(String repoName) {

        List<PackageEntity> packages = packageRepository.findByRepoName(repoName);
        List<DependencyEntity> deps = dependencyRepository.findByFrom_RepoName(repoName);

        List<Node> nodes = packages.stream()
                .map(p -> new Node(
                        p.getId().toString(),
                        p.getName(),
                        p.getRankScore()
                ))
                .collect(Collectors.toList());

        List<Edge> edges = deps.stream()
                .map(d -> new Edge(
                        d.getFrom().getId().toString(),
                        d.getTo().getId().toString(),
                        d.getType()
                ))
                .collect(Collectors.toList());

        return new GraphResultDTO(nodes, edges);
    }
}
