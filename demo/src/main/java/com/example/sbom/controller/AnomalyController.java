package com.example.sbom.controller;

import com.example.sbom.dto.RiskyPackageDTO;
import com.example.sbom.service.AnomalyService;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/sbom")
public class AnomalyController {

    private final AnomalyService anomalyService;

    public AnomalyController(AnomalyService anomalyService) {
        this.anomalyService = anomalyService;
    }

    @GetMapping("/anomalies/vulnerable")
    public List<RiskyPackageDTO> topVuln(@RequestParam int topN,
                                         @RequestParam(required = false) String repoName) {
        return anomalyService.getTopVulnerablePackages(topN, repoName);
    }

    @GetMapping("/anomalies/hub")
    public List<RiskyPackageDTO> topHub(@RequestParam int topN,
                                        @RequestParam(required = false) String repoName) {
        return anomalyService.getTopHubPackages(topN, repoName);
    }

    @GetMapping("/anomalies/risky")
    public List<RiskyPackageDTO> topRisky(@RequestParam int topN,
                                          @RequestParam(required = false) String repoName) {
        return anomalyService.getTopRiskyPackages(topN, repoName);
    }

    @GetMapping("/debug/stats")
    public Map<String, Object> getStats(@RequestParam(required = false) String repoName) {
        return anomalyService.getPackageStats(repoName);
    }
}
