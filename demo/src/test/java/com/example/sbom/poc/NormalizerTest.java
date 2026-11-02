package com.example.sbom.poc;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;

class NormalizerTest {

    @Test
    void packageNameFromPlainPurl() {
        assertEquals("react", Normalizer.packageNameFromPurl("pkg:npm/react@18.3.1"));
    }

    @Test
    void packageNameFromScopedPurl() {
        assertEquals("@scope/package",
                Normalizer.packageNameFromPurl("pkg:npm/%40scope%2Fpackage@1.0.0"));
        assertEquals("@scope/package",
                Normalizer.packageNameFromPurl("pkg:npm/%40scope/package@1.0.0"));
    }

    @Test
    void identifyPackageFromCdnUrl() {
        PackageIdentification id = Normalizer.inferPackageFromUrl(
                "https://cdn.example.test/npm/example-lib@1.2.3/index.js");

        assertEquals("example-lib", id.packageName());
        assertEquals("1.2.3", id.packageVersion());
    }

    @Test
    void doNotIdentifyGenericBundle() {
        PackageIdentification id = Normalizer.inferPackageFromUrl(
                "http://localhost:5173/assets/index-a1b2.js");

        assertNull(id.packageName());
        assertEquals("none", id.identificationConfidence());
    }
}

