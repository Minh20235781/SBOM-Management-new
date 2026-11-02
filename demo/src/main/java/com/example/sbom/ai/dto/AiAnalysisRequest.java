package com.example.sbom.ai.dto;

import lombok.Data;

@Data
public class AiAnalysisRequest {
    private String repoName; // optional
    // file sẽ dùng @RequestParam riêng
}