package com.example.sbom.controller;

import com.example.sbom.entity.SbomFile;
import com.example.sbom.entity.SbomFileHistory;
import com.example.sbom.service.SbomFileService;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.util.List;

@RestController
@RequestMapping("/api/projects/{projectId}/modules/{moduleId}/sbom-files")
public class SbomFileController {

    private final SbomFileService service;

    public SbomFileController(SbomFileService service) {
        this.service = service;
    }

    @GetMapping
    public List<SbomFile> list(@PathVariable Long projectId, @PathVariable Long moduleId) {
        return service.listByModule(projectId, moduleId);
    }

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    public SbomFile upload(@PathVariable Long projectId,
                           @PathVariable Long moduleId,
                           @RequestParam("file") MultipartFile file) {
        return service.recordUpload(projectId, moduleId, file);
    }

    @DeleteMapping("/{sbomFileId}")
    public ResponseEntity<Void> delete(@PathVariable Long projectId,
                                       @PathVariable Long moduleId,
                                       @PathVariable Long sbomFileId) {
        service.delete(projectId, moduleId, sbomFileId);
        return ResponseEntity.noContent().build();
    }

    @GetMapping("/{sbomFileId}/history")
    public List<SbomFileHistory> history(@PathVariable Long projectId,
                                          @PathVariable Long moduleId,
                                          @PathVariable Long sbomFileId) {
        return service.getHistory(projectId, moduleId, sbomFileId);
    }
}
