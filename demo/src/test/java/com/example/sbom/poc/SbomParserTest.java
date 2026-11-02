package com.example.sbom.poc;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class SbomParserTest {

    @Test
    void parseCycloneDx(@TempDir Path tmp) throws IOException {
        Path file = tmp.resolve("sbom.json");
        Files.writeString(file, """
                {
                  "bomFormat": "CycloneDX",
                  "specVersion": "1.5",
                  "components": [
                    {
                      "type": "library",
                      "name": "react",
                      "version": "18.3.1",
                      "purl": "pkg:npm/react@18.3.1"
                    }
                  ]
                }
                """);

        List<StaticComponent> components = SbomParser.parse(file);

        assertEquals(1, components.size());
        assertEquals("react", components.get(0).name());
        assertEquals("18.3.1", components.get(0).version());
        assertEquals("react", components.get(0).normalizedName());
    }

    @Test
    void parseEmptyCycloneDx(@TempDir Path tmp) throws IOException {
        Path file = tmp.resolve("empty.json");
        Files.writeString(file, """
                {"bomFormat": "CycloneDX", "specVersion": "1.5", "components": []}
                """);

        assertTrue(SbomParser.parse(file).isEmpty());
    }
}

