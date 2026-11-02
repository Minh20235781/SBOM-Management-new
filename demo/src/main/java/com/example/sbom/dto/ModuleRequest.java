package com.example.sbom.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Data;

@Data
public class ModuleRequest {

    @NotBlank(message = "name is required")
    @Size(max = 200)
    private String name;

    /** Optional - module may not be tied to a specific repo config. */
    private Long repoConfigId;

    @Size(max = 500)
    private String pathInRepo;

    @Size(max = 500)
    private String sbomPattern;
}
