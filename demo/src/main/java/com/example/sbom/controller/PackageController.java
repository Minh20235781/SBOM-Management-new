package com.example.sbom.controller;

import com.example.sbom.dto.*;
import com.example.sbom.service.PackageQueryService;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/packages")
@RequiredArgsConstructor
public class PackageController {

    private final PackageQueryService service;

    @GetMapping("/{name}")
    public PackageDetailsResponse getDetails(@PathVariable String name,
                                             @RequestParam(required = false) String repoName) {
        return service.getPackageDetails(name, repoName);
    }

        @GetMapping("/{name}/dependency-graph")
    public DependencyGraphResponse getGraph(@PathVariable String name) {
        return service.getLocalGraph(name);
    }
}
