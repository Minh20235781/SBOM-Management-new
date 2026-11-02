import axios from "axios";

const http = axios.create({ baseURL: "/api", timeout: 30000 });

/**
 * Wrapper for the cross-entity audit timeline endpoint. The backend
 * accepts a projectId plus optional type/from/to/limit filters; we
 * pass them through verbatim.
 */
export const auditApi = {
 timeline: ({ projectId, type, from, to, limit } = {}) => {
 const params = { projectId };
 if (type) params.type = type;
 if (from) params.from = from;
 if (to) params.to = to;
 if (limit != null) params.limit = limit;
 return http.get("/audit", { params }).then((r) => r.data);
 },
};

export default auditApi;
