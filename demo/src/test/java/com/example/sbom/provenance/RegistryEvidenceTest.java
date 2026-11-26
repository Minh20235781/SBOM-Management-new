package com.example.sbom.provenance;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;
import java.util.HexFormat;
import static org.junit.jupiter.api.Assertions.*;

class RegistryEvidenceTest {
    private final ObjectMapper json = new ObjectMapper();

    @Test
    void exactBytesAndTarballReferenceHaveDistinctDigests() throws Exception {
        byte[] tarball = "test archive bytes".getBytes(StandardCharsets.UTF_8);
        byte[] checksum = MessageDigest.getInstance("SHA-512").digest(tarball);
        var release = json.createObjectNode();
        release.putObject("dist").put("tarball", "https://registry.npmjs.org/test/-/test-1.0.0.tgz")
                .put("integrity", "sha512-" + Base64.getEncoder().encodeToString(checksum));
        var evidence = RegistryEvidence.npmRelease("https://registry.npmjs.org/test/1.0.0", release);
        assertEquals(HexFormat.of().formatHex(checksum), evidence.hash());
        var service = new SbomProvenanceService((purl, version) -> evidence);
        try {
            byte[] sbom = """
                    {"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"components":[
                    {"type":"library","name":"test","purl":"pkg:npm/test@1.0.0"}]}
                    """.getBytes(StandardCharsets.UTF_8);
            var result = service.processProvenance(sbom);
            assertEquals(HexFormat.of().formatHex(MessageDigest.getInstance("SHA-256").digest(sbom)), result.getFileSha256());
            var node = json.valueToTree(result.getEnrichedSbomJson()).at("/components/0");
            assertFalse(node.has("pedigree"));
            assertEquals(evidence.hash(), node.at("/hashes/0/content").asText());
            assertEquals("RELEASE_FOUND", result.getComponents().getFirst().getStatus());
        } finally { service.close(); }
    }

    @Test
    void distinguishesSourcesWithoutFabricatingEvidence() {
        assertEquals("MISSING_VERSION", RegistryEvidence.lookup("pkg:npm/example", "UNKNOWN").status());
        assertEquals("UNSUPPORTED_SOURCE", RegistryEvidence.lookup("pkg:github/actions/checkout@v4", "v4").status());
        assertEquals("INVALID_COORDINATES", RegistryEvidence.lookup("pkg:npm/example@1", "2").status());
        assertNull(RegistryEvidence.npmRelease("registry", json.createObjectNode()).hash());
    }
}
