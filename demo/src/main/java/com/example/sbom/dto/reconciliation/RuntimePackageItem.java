package com.example.sbom.dto.reconciliation;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class RuntimePackageItem {
    private String name;
    private String version;
    private Integer loadedClassesCount;
    private String loadedAt;
    private String source; // JVM_CLASSLOADER, NODE_REQUIRE_CACHE, PROCESS_INSPECT
}
