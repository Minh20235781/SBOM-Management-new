const BASE_URL = "http://localhost:8080";

export async function fetchDemoIteration(projectId = 1, iteration = 1) {
  const res = await fetch(`${BASE_URL}/api/reconciliation/demo-iteration?projectId=${projectId}&iteration=${iteration}`);
  if (!res.ok) {
    const text = await res.text();
    throw new Error(text || "Failed to fetch demo iteration");
  }
  return res.json();
}

export async function fetchLiveReconciliation(projectId = 1) {
  const res = await fetch(`${BASE_URL}/api/reconciliation/live-reconcile?projectId=${projectId}`);
  if (!res.ok) {
    const text = await res.text();
    throw new Error(text || "Failed to run live JVM reconciliation");
  }
  return res.json();
}

export async function fetchInspectJvm() {
  const res = await fetch(`${BASE_URL}/api/reconciliation/inspect-jvm`);
  if (!res.ok) {
    const text = await res.text();
    throw new Error(text || "Failed to inspect JVM via reflection");
  }
  return res.json();
}

export async function submitReconciliation(request) {
  const res = await fetch(`${BASE_URL}/api/reconciliation/reconcile`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(request),
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(text || "Failed to reconcile runtime data");
  }
  return res.json();
}

/**
 * Đối sánh giữa 2 nguồn SBOM (Base vs Target)
 */
export async function compareSboms(compareRequest) {
  const res = await fetch(`${BASE_URL}/api/reconciliation/compare-sboms`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(compareRequest),
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(text || "Failed to compare 2 SBOM sources");
  }
  return res.json();
}

/**
 * Tải lên và đối sánh trực tiếp 2 tệp SBOM (CycloneDX / SPDX JSON)
 */
export async function compareSbomFiles(file1, file2) {
  const formData = new FormData();
  formData.append("file1", file1);
  formData.append("file2", file2);

  const res = await fetch(`${BASE_URL}/api/reconciliation/compare-files`, {
    method: "POST",
    body: formData,
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(text || "Failed to upload and compare SBOM files");
  }
  return res.json();
}

/**
 * Đánh giá AI theo yêu cầu cho một điểm khác biệt cụ thể
 */
export async function evaluateDiffWithAi(diffRequest) {
  const res = await fetch(`${BASE_URL}/api/reconciliation/ai-evaluate-diff`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(diffRequest),
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(text || "Failed to evaluate diff with AI");
  }
  return res.json();
}

/**
 * Chạy web trên browser / F12 và sinh tệp SBOM Runtime chuẩn CycloneDX JSON
 */
export async function generateRuntimeSbom(requestPayload) {
  const res = await fetch(`${BASE_URL}/api/reconciliation/generate-runtime-sbom`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(requestPayload),
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(text || "Failed to generate runtime SBOM");
  }
  return res.json();
}

/**
 * Lấy dữ liệu Live F12 Network stream mới nhất từ trang web mục tiêu (đồng bộ 2 màn hình)
 */
export async function fetchLatestLiveF12Stream() {
  const res = await fetch(`${BASE_URL}/api/reconciliation/live-f12-stream`);
  if (!res.ok) {
    const text = await res.text();
    throw new Error(text || "Failed to fetch latest live F12 stream");
  }
  return res.json();
}

/**
 * Lấy trạng thái kết nối và snapshot mới nhất của Node.js Agent
 */
export async function fetchLatestNodeAgent() {
  const res = await fetch(`${BASE_URL}/api/reconciliation/latest-node-agent`);
  if (!res.ok) {
    const text = await res.text();
    throw new Error(text || "Failed to fetch latest node agent status");
  }
  return res.json();
}

/**
 * Thực hiện đối sánh chuẩn POC: Static SBOM vs Runtime HAR JSON
 */
export async function matchPoc(payload) {
  const res = await fetch(`${BASE_URL}/api/reconciliation/poc/match`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload),
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(text || "Lỗi khi đối sánh POC");
  }
  return res.json();
}

/**
 * Thực hiện đối sánh chuẩn POC từ 2 file tải lên trực tiếp
 */
export async function matchPocFiles(sbomFile, harFile) {
  const formData = new FormData();
  if (sbomFile) formData.append("sbomFile", sbomFile);
  if (harFile) formData.append("harFile", harFile);

  const res = await fetch(`${BASE_URL}/api/reconciliation/poc/match-files`, {
    method: "POST",
    body: formData,
  });
  if (!res.ok) {
    const text = await res.text();
    throw new Error(text || "Lỗi khi đối sánh tệp POC");
  }
  return res.json();
}

/**
 * Xuất báo cáo CSV đối sánh từ server có UTF-8 BOM cho Excel
 */
export async function exportPocCsv(report) {
  const res = await fetch(`${BASE_URL}/api/reconciliation/poc/export-csv`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(report),
  });
  if (!res.ok) {
    throw new Error("Lỗi khi tải file CSV");
  }
  return res.blob();
}

