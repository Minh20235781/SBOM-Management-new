package com.example.sbom.poc;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;

class ComponentMatcherTest {

    private static StaticComponent component(String name, String version) {
        return new StaticComponent(name, name, version,
                "pkg:npm/" + name + "@" + version,
                "CycloneDX", null, "library", "static_sbom");
    }

    private static RuntimeResource resource(String id, String url) {
        return new RuntimeResource(id, url, null, null, "GET", 200,
                "application/javascript", "javascript", null, "browser_har");
    }

    @Test
    void matchSamePackageAndVersion() {
        MatchReport report = ComponentMatcher.match(
                List.of(component("example-lib", "1.2.3")),
                List.of(resource("RT-0001",
                        "https://cdn.example.test/npm/example-lib@1.2.3/index.js")));

        assertEquals(1, report.summary().statusCounts().get("MATCHED"));
    }

    @Test
    void staticOnlyWhenNoRuntimeEvidence() {
        MatchReport report = ComponentMatcher.match(
                List.of(component("example-lib", "1.2.3")),
                List.of());

        assertEquals(1, report.summary().statusCounts().get("STATIC_ONLY"));
    }

    @Test
    void unresolvedForGenericBundle() {
        MatchReport report = ComponentMatcher.match(
                List.of(),
                List.of(resource("RT-0001", "http://localhost:5173/assets/index-a1b2.js")));

        assertEquals(1, report.summary().statusCounts().get("UNRESOLVED"));
    }

    @Test
    void runtimeOnlyWhenPackageIdentifiedButNotInSbom() {
        MatchReport report = ComponentMatcher.match(
                List.of(),
                List.of(resource("RT-0001",
                        "https://cdn.example.test/npm/other-lib@2.0.0/index.js")));

        assertEquals(1, report.summary().statusCounts().get("RUNTIME_ONLY"));
    }

    @Test
    void versionMismatchIsUnresolved() {
        MatchReport report = ComponentMatcher.match(
                List.of(component("example-lib", "1.2.3")),
                List.of(resource("RT-0001",
                        "https://cdn.example.test/npm/example-lib@9.9.9/index.js")));

        assertEquals(1, report.summary().statusCounts().get("UNRESOLVED"));
    }
}

