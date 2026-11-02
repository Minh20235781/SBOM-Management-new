package com.example.sbom.controller;

import com.example.sbom.dto.RepoConfigRequest;
import com.example.sbom.entity.RepoConfig;
import com.example.sbom.entity.RepoConfigHistory;
import com.example.sbom.service.RepoConfigService;
import jakarta.validation.Valid;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/projects/{projectId}/repo-configs")
public class RepoConfigController {

    private final RepoConfigService service;

    public RepoConfigController(RepoConfigService service) {
        this.service = service;
    }

    @GetMapping
    public List<RepoConfig> list(@PathVariable Long projectId) {
        return service.listByProject(projectId);
    }

    @GetMapping("/{id}")
    public RepoConfig get(@PathVariable Long projectId, @PathVariable Long id) {
        return service.get(projectId, id);
    }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    public RepoConfig create(@PathVariable Long projectId,
                             @Valid @RequestBody RepoConfigRequest req) {
        return service.create(projectId, req);
    }

    @PutMapping("/{id}")
    public RepoConfig update(@PathVariable Long projectId,
                             @PathVariable Long id,
                             @Valid @RequestBody RepoConfigRequest req) {
        return service.update(projectId, id, req);
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> delete(@PathVariable Long projectId, @PathVariable Long id) {
        service.delete(projectId, id);
        return ResponseEntity.noContent().build();
    }

    @GetMapping("/{id}/history")
    public List<RepoConfigHistory> history(@PathVariable Long projectId, @PathVariable Long id) {
        return service.getHistory(projectId, id);
    }
}
