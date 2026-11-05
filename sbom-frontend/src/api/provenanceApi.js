const BASE_URL = "http://localhost:8080";

/**
 * Tải file SBOM (CycloneDX / SPDX) lên để kiểm tra và chuẩn hóa nguồn gốc
 */
export async function validateAndNormalizeSbomFile(file) {
  const formData = new FormData();
  formData.append("file", file);

  const res = await fetch(`${BASE_URL}/api/provenance/validate-and-normalize`, {
    method: "POST",
    body: formData,
  });

  if (!res.ok) {
    const errorData = await res.json().catch(() => ({}));
    throw new Error(errorData.error || "Không thể xác thực nguồn gốc SBOM");
  }

  return res.json();
}

/**
 * Tải trực tiếp nội dung JSON string
 */
export async function validateAndNormalizeSbomJson(jsonString) {
  const res = await fetch(`${BASE_URL}/api/provenance/validate-and-normalize-json`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: jsonString,
  });

  if (!res.ok) {
    const errorData = await res.json().catch(() => ({}));
    throw new Error(errorData.error || "Không thể xác thực nguồn gốc SBOM");
  }

  return res.json();
}

/**
 * Xuất và tải file SBOM đã chuẩn hóa
 */
export async function downloadEnrichedSbom(enrichedSbomJson, filename = "normalized-provenance-sbom.json") {
  const res = await fetch(`${BASE_URL}/api/provenance/export-enriched`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(enrichedSbomJson),
  });

  if (!res.ok) {
    throw new Error("Không thể tải xuống tệp SBOM đã chuẩn hóa");
  }

  const blob = await res.blob();
  const url = window.URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  window.URL.revokeObjectURL(url);
  document.body.removeChild(a);
}

