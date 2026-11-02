import axios from "axios";

const http = axios.create({ baseURL: "/api", timeout: 120000 });
const httpV2 = axios.create({ baseURL: "/api", timeout: 120000 });

/** AI + ML endpoints for risk analysis and RF prediction. */
export const aiApi = {
 rfNewPredict: (repoName) =>
  http.get(`/ai/rf-new/predict/${encodeURIComponent(repoName)}`).then((r) => r.data),

 riskAnalysis: (file, repoName) => {
 const fd = new FormData();
 fd.append("file", file);
 if (repoName) fd.append("repoName", repoName);
 return http.post("/ai/risk-analysis", fd).then((r) => r.data);
 },
};

export default aiApi;
