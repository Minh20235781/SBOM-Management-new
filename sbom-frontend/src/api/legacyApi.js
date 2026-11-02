import axios from "axios";

/**
 * Wrapper for the legacy/non-project endpoints. These pre-date the
 * project management work (Phase 0-3) so they don't take a
 * projectId — most of them scope by repoName or operate globally.
 *
 * The HTTP client is shared with the rest of the app (baseURL=/api)
 * so the Vite dev proxy forwards everything to the Spring backend.
 */
const http = axios.create({ baseURL: "/api", timeout: 120000 });

export const legacyApi = {
 // ---------- Scan trigger ----------
 /**
 * Triggers a Trivy scan of the given repo URL and persists the
 * result. Returns a plain String from the backend; we wrap it so
 * the UI can show a friendlier confirmation.
 */
 scanAndSave: async (repoUrl) => {
 const { data } = await http.post(`/sbom/scan-and-save`, null, {
 params: { repoUrl },
 });
 return data;
 },

 // ---------- SBOM Table ----------
 /**
 * Flat table: each row is a (package, vulnerability) pair.
 * Pass {@code repoName} (or null) to filter.
 */
 sbomTable: (repoName) => {
 const params = {};
 if (repoName) params.repoName = repoName;
 return http.get("/sbom-table", { params }).then((r) => r.data);
 },

 /** Triggers a CSV download. The browser handles the file save. */
 exportCsv: (repoName) => {
 const params = {};
 if (repoName) params.repoName = repoName;
 return http
 .get("/sbom-table/export/csv", { params, responseType: "blob" })
 .then((r) => r.data);
 },

 exportJson: (repoName) => {
 const params = {};
 if (repoName) params.repoName = repoName;
 return http
 .get("/sbom-table/export/json", { params, responseType: "blob" })
 .then((r) => r.data);
 },

 // ---------- Anomaly rankings ----------
 topVulnerable: (topN = 10, repoName) => {
 const params = { topN };
 if (repoName) params.repoName = repoName;
 return http.get("/sbom/anomalies/vulnerable", { params }).then((r) => r.data);
 },
 topHub: (topN = 10, repoName) => {
 const params = { topN };
 if (repoName) params.repoName = repoName;
 return http.get("/sbom/anomalies/hub", { params }).then((r) => r.data);
 },
 topRisky: (topN = 10, repoName) => {
 const params = { topN };
 if (repoName) params.repoName = repoName;
 return http.get("/sbom/anomalies/risky", { params }).then((r) => r.data);
 },
 debugStats: (repoName) => {
 const params = {};
 if (repoName) params.repoName = repoName;
 return http.get("/sbom/debug/stats", { params }).then((r) => r.data);
 },

 // ---------- SBOM Validation ----------
 validate: ({ repoUrl, repoName, repoPath } = {}) => {
 const params = {};
 if (repoUrl) params.repoUrl = repoUrl;
 if (repoName) params.repoName = repoName;
 if (repoPath) params.repoPath = repoPath;
 return http.post("/sbom/validate", null, { params }).then((r) => r.data);
 },

 // ---------- Graph ----------
 graphRank: (repoName) =>
 http.get("/graph/rank", { params: { repoName } }).then((r) => r.data),

 // ---------- Package detail ----------
 packageDetails: (name, repoName) => {
 const params = {};
 if (repoName) params.repoName = repoName;
 return http.get(`/packages/${encodeURIComponent(name)}`, { params }).then((r) => r.data);
 },
 packageGraph: (name) =>
 http.get(`/packages/${encodeURIComponent(name)}/dependency-graph`).then((r) => r.data),
};

export default legacyApi;
