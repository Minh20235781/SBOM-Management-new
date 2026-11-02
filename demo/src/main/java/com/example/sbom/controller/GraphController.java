package com.example.sbom.controller;

import com.example.sbom.dto.GraphResultDTO;
import com.example.sbom.service.graph.GraphBuilderService;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/graph")
@RequiredArgsConstructor
public class GraphController {

    private final GraphBuilderService graphBuilderService;

    @GetMapping("/rank")
    public GraphResultDTO getGraph(
            @RequestParam String repoName
    ) {
        return graphBuilderService.buildGraphByRepo(repoName);
    }
}


