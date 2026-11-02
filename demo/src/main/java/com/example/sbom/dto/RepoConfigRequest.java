package com.example.sbom.dto;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.Data;

@Data
public class RepoConfigRequest {

    @NotBlank(message = "repoUrl is required")
    @Size(max = 500)
    private String repoUrl;

    @Size(max = 200)
    private String branch = "main";

    /** Cron expression; null/blank means manual scanning only. */
    @Size(max = 100)
    private String scanSchedule;

    @Size(max = 50)
    private String scanTool = "TRIVY";
}
