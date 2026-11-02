package com.example.sbom.poc;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class HarParserTest {

    @Test
    void parseJavascriptResource(@TempDir Path tmp) throws IOException {
        Path file = tmp.resolve("runtime.har");
        Files.writeString(file, """
                {
                  "log": {
                    "entries": [
                      {
                        "startedDateTime": "2026-11-03T10:00:00.000Z",
                        "request": {
                          "method": "GET",
                          "url": "http://localhost:5173/assets/app.js"
                        },
                        "response": {
                          "status": 200,
                          "content": { "mimeType": "application/javascript" }
                        }
                      }
                    ]
                  }
                }
                """);

        List<RuntimeResource> resources = HarParser.parse(file);

        assertEquals(1, resources.size());
        assertEquals("GET", resources.get(0).method());
        assertEquals(200, resources.get(0).status());
        assertEquals("javascript", resources.get(0).resourceType());
        assertEquals("localhost", resources.get(0).host());
    }

    @Test
    void parseEmptyHar(@TempDir Path tmp) throws IOException {
        Path file = tmp.resolve("empty.har");
        Files.writeString(file, "{\"log\": {\"entries\": []}}");

        assertTrue(HarParser.parse(file).isEmpty());
    }
}

