import axios from "axios";

const http = axios.create({ baseURL: "/api", timeout: 30000 });

/**
 * Endpoints nested under a project: modules, repo configs, and the
 * sbom files inside each module. The shape mirrors the Spring
 * controllers: /api/projects/{projectId}/...
 */
export const projectDetailApi = {
 listModules: (projectId) => http.get(`/projects/${projectId}/modules`).then((r) => r.data),
 createModule: (projectId, payload) => http.post(`/projects/${projectId}/modules`, payload).then((r) => r.data),
 deleteModule: (projectId, moduleId) => http.delete(`/projects/${projectId}/modules/${moduleId}`).then((r) => r.data),
 moduleHistory: (projectId, moduleId) => http.get(`/projects/${projectId}/modules/${moduleId}/history`).then((r) => r.data),
 autoDetectModules: (projectId) => http.get(`/projects/${projectId}/modules/auto-detect`).then((r) => r.data),
 scanModule: (projectId, moduleId) => http.post(`/projects/${projectId}/modules/${moduleId}/scan`).then((r) => r.data),
 scanModuleFs: (projectId, moduleId) => http.post(`/projects/${projectId}/modules/${moduleId}/scan-fs`).then((r) => r.data),

 listRepoConfigs: (projectId) => http.get(`/projects/${projectId}/repo-configs`).then((r) => r.data),
 createRepoConfig: (projectId, payload) => http.post(`/projects/${projectId}/repo-configs`, payload).then((r) => r.data),
 updateRepoConfig: (projectId, id, payload) => http.put(`/projects/${projectId}/repo-configs/${id}`, payload).then((r) => r.data),
 deleteRepoConfig: (projectId, id) => http.delete(`/projects/${projectId}/repo-configs/${id}`).then((r) => r.data),
 repoConfigHistory: (projectId, id) => http.get(`/projects/${projectId}/repo-configs/${id}/history`).then((r) => r.data),

 listSbomFiles: (projectId, moduleId) =>
 http.get(`/projects/${projectId}/modules/${moduleId}/sbom-files`).then((r) => r.data),
 uploadSbomFile: (projectId, moduleId, file) => {
 const fd = new FormData();
 fd.append("file", file);
 return http
 .post(`/projects/${projectId}/modules/${moduleId}/sbom-files`, fd, {
 headers: { "Content-Type": "multipart/form-data" },
 })
 .then((r) => r.data);
 },
 deleteSbomFile: (projectId, moduleId, sbomFileId) =>
 http.delete(`/projects/${projectId}/modules/${moduleId}/sbom-files/${sbomFileId}`).then((r) => r.data),
 sbomFileHistory: (projectId, moduleId, sbomFileId) =>
 http.get(`/projects/${projectId}/modules/${moduleId}/sbom-files/${sbomFileId}/history`).then((r) => r.data),
};

export default projectDetailApi;
