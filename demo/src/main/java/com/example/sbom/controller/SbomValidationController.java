package com.example.sbom.controller;

import com.example.sbom.dto.SbomValidationResponse;
import com.example.sbom.service.validation.SbomValidationService;
import lombok.RequiredArgsConstructor;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/sbom")
@RequiredArgsConstructor
public class SbomValidationController {

    private final SbomValidationService sbomValidationService;

    @PostMapping("/validate")
    public SbomValidationResponse validate(
            @RequestParam(required = false) String repoUrl,
            @RequestParam(required = false) String repoName,
            @RequestParam(required = false) String repoPath
    ) {
        return sbomValidationService.validate(repoUrl, repoName, repoPath);
    }

    /**
     * Project-scoped entry point: look up the project by id,
     * derive a best-effort repoUrl from its description, and
     * run the full validation. Used by the TrustScore page
     * where the only thing the user picked is a project — no
     * Git URL to copy around.
     */
    @PostMapping("/validate-by-project")
    public SbomValidationResponse validateByProject(@RequestParam Long projectId) {
        return sbomValidationService.validateByProject(projectId);
    }
}
