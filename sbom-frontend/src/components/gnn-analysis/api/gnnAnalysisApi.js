import axios from "axios";

const api = axios.create({
  baseURL: "http://localhost:8080",
  timeout: 20000
});

const DEFAULT_RETRY_MAX = 2;
const DEFAULT_RETRY_DELAY_MS = 750;

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function requestWithRetry(requestFn, retryMax = DEFAULT_RETRY_MAX) {
  let lastError = null;
  for (let attempt = 0; attempt <= retryMax; attempt += 1) {
    try {
      return await requestFn();
    } catch (error) {
      lastError = error;
      const status = error?.response?.status;
      if (status && status >= 400 && status < 500) {
        throw error;
      }
      if (attempt >= retryMax) break;
      console.warn("GNN explainability retry", { attempt: attempt + 1, status });
      await sleep(DEFAULT_RETRY_DELAY_MS * (attempt + 1));
    }
  }
  throw lastError;
}

export async function fetchGnnExplainability(payload) {
  if (!payload) {
    throw new Error("Explainability payload is required");
  }

  try {
    const res = await requestWithRetry(() =>
      api.post("/api/v2/gnn/explainability/analyze", payload)
    );
    return res.data;
  } catch (error) {
    console.error("GNN explainability request failed", error);
    handleTimeout(error, "GNN explainability request timed out");
  }
}
