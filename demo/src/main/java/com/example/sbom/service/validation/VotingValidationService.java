package com.example.sbom.service.validation;

import com.example.sbom.dto.DependencyConfidenceDTO;
import com.example.sbom.dto.ValidationSummaryDTO;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class VotingValidationService {

    public String getConfidence(int sourceCount) {
        if (sourceCount >= 3) return "HIGH";
        if (sourceCount == 2) return "MEDIUM";
        return "LOW";
    }

    public ValidationSummaryDTO summarize(List<DependencyConfidenceDTO> dependencies) {
        ValidationSummaryDTO summary = new ValidationSummaryDTO();
        if (dependencies == null || dependencies.isEmpty()) {
            return summary;
        }
        int high = 0;
        int medium = 0;
        int low = 0;
        for (DependencyConfidenceDTO dep : dependencies) {
            String confidence = dep.getConfidence();
            if ("HIGH".equalsIgnoreCase(confidence)) {
                high++;
            } else if ("MEDIUM".equalsIgnoreCase(confidence)) {
                medium++;
            } else {
                low++;
            }
        }
        summary.setHighConfidence(high);
        summary.setMediumConfidence(medium);
        summary.setLowConfidence(low);
        return summary;
    }
}
