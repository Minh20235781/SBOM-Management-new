import { useEffect, useState, useCallback } from "react";
import projectApi from "../api/projectApi";
import projectDetailApi from "../api/projectDetailApi";
import { safeArray } from "../utils/safe";

/**
 * Centralised fetcher for the Project Workspace. Loads the
 * project record plus a few pieces of cross-cutting data (latest
 * risk, vuln stats, module/repo counts) in parallel and exposes
 * a single {@code reload} for use after mutations.
 *
 * Tab-specific data (e.g. the audit timeline, vuln history list)
 * stays inside the tab components themselves — those are cheap to
 * fetch and only relevant when their tab is active.
 */
export default function useProjectData(projectId) {
 const [data, setData] = useState({
 project: null,
 modules: [],
 riskRows: [],
 latestRisk: null,
 vulnStats: { new: 0, stillOpen: 0, fixed: 0, reopened: 0 },
 });
 const [loading, setLoading] = useState(true);
 const [error, setError] = useState(null);

 const load = useCallback(async () => {
 if (projectId == null) return;
 setLoading(true);
 setError(null);
 try {
 const [project, modules, riskRows, latestRisk, vulnStats] =
 await Promise.all([
 projectApi.get(projectId),
 projectDetailApi.listModules(projectId).catch(() => []),
 projectApi.riskAssessments(projectId, 200).catch(() => []),
 projectApi.latestRisk(projectId).catch(() => null),
 projectApi.vulnStats(projectId).catch(() => ({ new: 0, stillOpen: 0, fixed: 0, reopened: 0 })),
 ]);
 setData({
 project: project || null,
 modules: safeArray(modules),
 riskRows: safeArray(riskRows),
 latestRisk: latestRisk || null,
 vulnStats: vulnStats || { new: 0, stillOpen: 0, fixed: 0, reopened: 0 },
 });
 } catch (e) {
 setError(e?.response?.data?.message || e?.message || "Failed to load project");
 } finally {
 setLoading(false);
 }
 }, [projectId]);

 useEffect(() => {
 load();
 }, [load]);

 return { ...data, loading, error, reload: load };
}
