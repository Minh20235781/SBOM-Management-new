package com.example.sbom.poc;

/** Kết quả nhận diện package từ URL runtime. */
public record PackageIdentification(
        String packageName,
        String packageVersion,
        String identificationMethod,
        String identificationConfidence
) {

    public static PackageIdentification notIdentified() {
        return new PackageIdentification(null, null, "not_identified", "none");
    }
}

