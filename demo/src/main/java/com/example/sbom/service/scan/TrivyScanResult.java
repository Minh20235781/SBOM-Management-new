package com.example.sbom.service.scan;

import java.io.File;
import java.util.Map;
import java.util.Set;

public class TrivyScanResult {
    private final Map<String, String> components;
    private final Map<String, Integer> ecosystemCounts;
    private final Set<String> purlEcosystems;
    private final Map<String, String> componentEcosystems;
    private final File sbomFile;

    public TrivyScanResult(Map<String, String> components,
                           Map<String, Integer> ecosystemCounts,
                           Set<String> purlEcosystems,
                           Map<String, String> componentEcosystems,
                           File sbomFile) {
        this.components = components;
        this.ecosystemCounts = ecosystemCounts;
        this.purlEcosystems = purlEcosystems;
        this.componentEcosystems = componentEcosystems;
        this.sbomFile = sbomFile;
    }

    public Map<String, String> getComponents() {
        return components;
    }

    public Map<String, Integer> getEcosystemCounts() {
        return ecosystemCounts;
    }

    public Set<String> getPurlEcosystems() {
        return purlEcosystems;
    }

    public Map<String, String> getComponentEcosystems() {
        return componentEcosystems;
    }

    public File getSbomFile() {
        return sbomFile;
    }
}