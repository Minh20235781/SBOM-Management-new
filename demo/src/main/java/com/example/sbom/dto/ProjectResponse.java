package com.example.sbom.dto;

import com.example.sbom.entity.Project;
import lombok.Data;

import java.time.Instant;

@Data
public class ProjectResponse {
    private Long id;
    private String name;
    private String description;
    private String status;
    private Integer version;
    private Instant createdAt;
    private Instant updatedAt;
    private long packageCount;

    public static ProjectResponse from(Project project, long packageCount) {
        ProjectResponse r = new ProjectResponse();
        r.id = project.getId();
        r.name = project.getName();
        r.description = project.getDescription();
        r.status = project.getStatus();
        r.version = project.getVersion();
        r.createdAt = project.getCreatedAt();
        r.updatedAt = project.getUpdatedAt();
        r.packageCount = packageCount;
        return r;
    }
}
