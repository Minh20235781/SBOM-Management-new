package com.example.sbom.service.validation;

import org.springframework.stereotype.Service;

@Service
public class WeightedValidationService {

    private static final double SOURCE_WEIGHT = 0.3;
    private static final double SCANNER_WEIGHT = 0.4;
    private static final double BUILD_WEIGHT = 0.3;

    public double getWeightedScore(boolean inSourceGraph, boolean inScanner, boolean inBuild) {
        double score = 0.0;
        if (inSourceGraph) score += SOURCE_WEIGHT;
        if (inScanner) score += SCANNER_WEIGHT;
        if (inBuild) score += BUILD_WEIGHT;
        return score;
    }
}
