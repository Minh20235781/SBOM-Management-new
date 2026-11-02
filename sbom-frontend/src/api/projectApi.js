import axios from "axios";

/**
 * Tiny client for the project-management endpoints.
 *
 * The Spring controllers live under /api/projects, so the base URL
 * here is the same host as the rest of the SBOM app — Vite's dev
 * server proxies /api to the backend (see vite.config.js).
 */
const http = axios.create({
 baseURL: "/api",
 timeout: 30000,
});

export const projectApi = {
 list: () => http.get("/projects").then((r) => r.data),
 get: (id) => http.get(`/projects/${id}`).then((r) => r.data),
 create: (payload) => http.post("/projects", payload).then((r) => r.data),
 update: (id, payload) => http.put(`/projects/${id}`, payload).then((r) => r.data),
 reset: (id) => http.post(`/projects/${id}/reset`).then((r) => r.data),
 history: (id) => http.get(`/projects/${id}/history`).then((r) => r.data),
 riskAssessments: (id, limit = 50) =>
 http.get(`/projects/${id}/risk-assessments`, { params: { limit } }).then((r) => r.data),
 latestRisk: (id) => http.get(`/projects/${id}/risk-assessments/latest`).then((r) => r.data),
 recomputeRisk: (id) => http.post(`/projects/${id}/risk-assessments/recompute`).then((r) => r.data),
 commits: (id, limit = 5, refresh = false) => http.get(`/projects/${id}/commits`, { params: { limit, refresh } }).then((r) => r.data),
 vulnHistory: (id, status, limit = 100) => {
 const params = {};
 if (status) params.status = status;
 if (limit) params.limit = limit;
 return http.get(`/projects/${id}/vuln-history`, { params }).then((r) => r.data);
 },
 vulnStats: (id) => http.get(`/projects/${id}/vuln-history/stats`).then((r) => r.data),
};

export default projectApi;
