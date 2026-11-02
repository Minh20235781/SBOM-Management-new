const BASE_URL = "http://localhost:8080";

// SBOM Scan
export async function scanAndSaveRepo(repoUrl) {
  const res = await fetch(
    `${BASE_URL}/api/sbom/scan-and-save?repoUrl=${encodeURIComponent(repoUrl)}`,
    { method: "POST" }
  );
  if (!res.ok) {
    const text = await res.text();
    throw new Error(text);
  }
  return res.text();
}

// Graph
export async function fetchGraphByRepo(repoName) {
  const res = await fetch(
    `${BASE_URL}/api/graph/rank?repoName=${encodeURIComponent(repoName)}`
  );
  if (!res.ok) throw new Error("Failed to fetch graph");
  return res.json();
}

// Anomaly / Risk
export async function fetchTopRisky(topN = 10, repoName = "") {
  const repoParam = repoName ? `&repoName=${encodeURIComponent(repoName)}` : '';
  const res = await fetch(
    `${BASE_URL}/api/sbom/anomalies/risky?topN=${topN}${repoParam}`
  );
  if (!res.ok) throw new Error("Failed to fetch risky packages");
  return res.json();
}

export async function fetchTopVulnerable(topN = 10, repoName = "") {
  const repoParam = repoName ? `&repoName=${encodeURIComponent(repoName)}` : '';
  const res = await fetch(
    `${BASE_URL}/api/sbom/anomalies/vulnerable?topN=${topN}${repoParam}`
  );
  if (!res.ok) throw new Error("Failed to fetch vulnerable packages");
  return res.json();
}

export async function fetchTopHub(topN = 10, repoName = "") {
  const repoParam = repoName ? `&repoName=${encodeURIComponent(repoName)}` : '';
  const res = await fetch(
    `${BASE_URL}/api/sbom/anomalies/hub?topN=${topN}${repoParam}`
  );
  if (!res.ok) throw new Error("Failed to fetch hub packages");
  return res.json();
}

// Package Detail
export async function fetchPackageDetails(packageName, repoName = "") {
  const repoParam = repoName ? `?repoName=${encodeURIComponent(repoName)}` : '';
  const res = await fetch(
    `${BASE_URL}/api/packages/${encodeURIComponent(packageName)}${repoParam}`
  );
  if (!res.ok) throw new Error("Failed to fetch package details");
  return res.json();
}

export async function fetchLocalDependencyGraph(packageName) {
  const res = await fetch(
    `${BASE_URL}/api/packages/${encodeURIComponent(packageName)}/dependency-graph`
  );
  if (!res.ok) throw new Error("Failed to fetch local dependency graph");
  return res.json();
}

// SBOM Table
export async function fetchSbomTable(repoName = '') {
  const repoParam = repoName ? `?repoName=${encodeURIComponent(repoName)}` : '';
  const res = await fetch(`${BASE_URL}/api/sbom-table${repoParam}`);
  if (!res.ok) throw new Error('Failed to fetch SBOM table');
  return res.json();
}

// SBOM Validation
export async function fetchSbomValidation(repoUrl, repoName = '', repoPath = '') {
  const params = new URLSearchParams();
  if (repoUrl) params.append('repoUrl', repoUrl);
  if (repoName) params.append('repoName', repoName);
  if (repoPath) params.append('repoPath', repoPath);

  const query = params.toString();
  const res = await fetch(
    `${BASE_URL}/api/sbom/validate${query ? `?${query}` : ''}`,
    { method: 'POST' }
  );
  if (!res.ok) {
    const text = await res.text();
    throw new Error(text || 'Failed to validate SBOM');
  }
  return res.json();
}

export async function fetchSbomValidationByProject(projectId) {
  const res = await fetch(
    `${BASE_URL}/api/sbom/validate-by-project?projectId=${encodeURIComponent(projectId)}`,
    { method: 'POST' }
  );
  if (!res.ok) {
    const text = await res.text();
    throw new Error(text || 'Failed to validate SBOM by project');
  }
  return res.json();
}
