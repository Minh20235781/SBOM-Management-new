import { useEffect, useRef, useState } from "react";
import PageHeader from "../../components/shared/PageHeader";
import StatCard from "../../components/shared/StatCard";
import Button from "../../components/shared/Button";
import ErrorBanner from "../../components/shared/ErrorBanner";
import Spinner from "../../components/shared/Spinner";
import EmptyState from "../../components/shared/EmptyState";
import legacyApi from "../../api/legacyApi";
import projectApi from "../../api/projectApi";
import { toGnnGraphExport } from "../../components/gnn-analysis/utils/graphRiskUtils";
import { renderDependencyGraph } from "../../components/dependency-graph/DependencyGraphD3";
import "../../components/dependency-graph/DependencyGraph.css";
import { safeArray, safeObject } from "../../utils/safe";

/**
 * Graph page: D3 force-directed graph for the picked project.
 *
 * Pick a project from the dropdown at the top. The page fetches
 * two payloads in parallel:
 * - /api/graph/rank → dependency graph (nodes + edges) used to
 * render the D3 visualisation.
 * - /api/sbom/anomalies/risky → per-package anomaly scores used
 * to colour the D3 nodes (red = high anomaly).
 *
 * The D3 renderer reuses the legacy components in
 * components/dependency-graph (drag, zoom, tooltip, highlight,
 * legend, reset). Use the buttons next to the dropdown to
 * re-run a Trivy scan for the project or to download the
 * graph as a d3.json file.
 */
export default function GraphPage() {
 const [projects, setProjects] = useState([]);
 const [projectId, setProjectId] = useState("");
 const [selectedProject, setSelectedProject] = useState(null);
 const [graph, setGraph] = useState(null);
 const [riskData, setRiskData] = useState([]);
 const [loading, setLoading] = useState(false);
 const [error, setError] = useState(null);
 const [rescanning, setRescanning] = useState(false);
 const [rescanMessage, setRescanMessage] = useState(null);
 const graphContainerRef = useRef(null);

 // Load the project list once and auto-pick the richest one.
 useEffect(() => {
 let cancelled = false;
 (async () => {
 try {
 const list = safeArray(await projectApi.list());
 if (cancelled) return;
 setProjects(list);
 if (list.length > 0 && !projectId) {
 const richest = [...list].sort((a, b) => (b.packageCount || 0) - (a.packageCount || 0))[0];
 setProjectId(richest.id);
 setSelectedProject(richest);
 }
 } catch (e) {
 if (!cancelled) setError(e?.message || "Failed to load projects");
 }
 })();
 return () => { cancelled = true; };
 // eslint-disable-next-line react-hooks/exhaustive-deps
 }, []);

 const handleProjectChange = (id) => {
 setProjectId(id);
 const next = projects.find((p) => p.id === Number(id));
 setSelectedProject(next || null);
 setError(null);
 setRescanMessage(null);
 };

 // Reload the graph + risk data whenever the project changes.
 useEffect(() => {
 if (!selectedProject?.name) return;
 let cancelled = false;
 (async () => {
 setLoading(true);
 setError(null);
 setRescanMessage(null);
 try {
 const [graphData, risky] = await Promise.all([
 legacyApi.graphRank(selectedProject.name),
 legacyApi.topRisky(20, selectedProject.name).catch(() => []),
 ]);
 if (cancelled) return;
 setGraph(safeObject(graphData));
 setRiskData(safeArray(risky));
 } catch (e) {
 if (!cancelled) setError(e?.response?.data || e?.message || "Failed to load graph");
 } finally {
 if (!cancelled) setLoading(false);
 }
 })();
 return () => { cancelled = true; };
 }, [selectedProject?.name]);

 // Re-render the D3 graph whenever inputs change. The renderer
 // tears down the previous SVG before drawing, so this is safe
 // to call on every update.
 useEffect(() => {
 if (!graphContainerRef.current) return;
 if (!graph || nodes.length === 0) return;
 renderDependencyGraph({
 container: graphContainerRef.current,
 data: graph,
 riskData,
 onNodeClick: undefined,
 });
 // We deliberately don't depend on `riskData` length to avoid
 // restarting the simulation when only a single score changes.
 // eslint-disable-next-line react-hooks/exhaustive-deps
 }, [graph, graphContainerRef.current]);

 const nodes = safeArray(graph?.nodes);
 const edges = safeArray(graph?.edges);

 // Convert the legacy graph shape into the GNN-ready d3.json
 // payload (renumber nodeIds, attach moduleRank, etc.) and offer
 // it as a download. Same transform the GnnAnalysis dashboard uses.
 const handleExportD3Json = () => {
 const payload = toGnnGraphExport(graph);
 if (!payload) {
 setError("Graph payload is empty — pick a repo with data first.");
 return;
 }
 const blob = new Blob([JSON.stringify(payload, null, 2)], {
 type: "application/json",
 });
 const url = URL.createObjectURL(blob);
 const a = document.createElement("a");
 a.href = url;
 a.download = `d3json-${(selectedProject?.name || "graph").replace(/[^a-z0-9_-]/gi, "_")}.json`;
 document.body.appendChild(a);
 a.click();
 a.remove();
 URL.revokeObjectURL(url);
 };

 // Re-run a Trivy scan for the picked project and refresh the
 // graph once the scan completes. Uses the original repoUrl
 // recorded in the project's history snapshot so the backend
 // knows which URL to scan. Falls back to navigate(/scan) when
 // we don't have a URL on file (e.g. legacy Default Project).
 const handleRescan = async () => {
 if (!selectedProject) return;
 setRescanning(true);
 setError(null);
 setRescanMessage(null);
 try {
 let repoUrl = null;
 try {
 const history = await projectApi.history(selectedProject.id);
 const rows = safeArray(history);
 const latest = rows.length > 0 ? rows[rows.length - 1] : null;
 if (latest?.snapshotJson) {
 try {
 const parsed = JSON.parse(latest.snapshotJson);
 if (parsed?.repoUrl) repoUrl = parsed.repoUrl;
 } catch { /* ignore */ }
 }
 } catch { /* best-effort */ }
 if (!repoUrl) {
 setRescanMessage("No source URL on file for this project — open the Scan page to re-run a scan manually.");
 setRescanning(false);
 return;
 }
 await legacyApi.scanAndSave(repoUrl);
 setRescanMessage("Scan complete — refreshing graph…");
 // Refresh the project list and re-fetch the graph.
 const [list, graphData, risky] = await Promise.all([
 projectApi.list().catch(() => projects),
 legacyApi.graphRank(selectedProject.name),
 legacyApi.topRisky(20, selectedProject.name).catch(() => []),
 ]);
 setProjects(safeArray(list));
 const next = safeArray(list).find((p) => p.id === selectedProject.id);
 if (next) setSelectedProject(next);
 setGraph(safeObject(graphData));
 setRiskData(safeArray(risky));
 setRescanMessage("Graph refreshed.");
 } catch (e) {
 setError(e?.response?.data || e?.message || "Re-scan failed");
 } finally {
 setRescanning(false);
 }
 };

 return (
 <div>
 <PageHeader
 title="Graph"
 description="Module-rank graph for a repo. The D3 view colours nodes by anomaly score; the table below lists every node."
 />

 <div
 style={{
 display: "grid",
 gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))",
 gap: "var(--space-3)",
 marginBottom: "var(--space-4)",
 }}
 >
 <StatCard label="Nodes" value={nodes.length} subValue="In the dependency graph" />
 <StatCard label="Edges" value={edges.length} subValue="Direct dependencies" />
 <StatCard
 label="Risk packages"
 value={riskData.length}
 subValue="From anomaly endpoint"
 accent="warning"
 />
 <StatCard
 label="Top risk"
 value={
 riskData[0]?.vulnAnomaly != null
 ? riskData[0].vulnAnomaly.toFixed(2)
 : "—"
 }
 subValue={riskData[0]?.packageName || "No data"}
 accent="danger"
 />
 </div>

 <div style={{ display: "flex", gap: "var(--space-2)", alignItems: "center", flexWrap: "wrap", marginBottom: "var(--space-3)" }}>
 <label style={{ fontSize: "var(--text-sm)", color: "var(--text-secondary)" }}>Project</label>
 <select
 value={projectId}
 onChange={(e) => handleProjectChange(e.target.value)}
 disabled={projects.length === 0}
 style={{
 height: 36, padding: "0 12px", border: "1px solid var(--border-default)",
 borderRadius: "var(--radius-md)", fontSize: "var(--text-sm)", background: "var(--bg-surface)", minWidth: 240,
 }}
 >
 {projects.length === 0 && <option value="">(no projects)</option>}
 {projects.map((p) => (
 <option key={p.id} value={p.id}>
 {p.name}{p.packageCount != null ? ` (${p.packageCount} packages)` : ""}
 </option>
 ))}
 </select>
 <Button
 variant="secondary"
 size="sm"
 onClick={handleExportD3Json}
 disabled={!graph || nodes.length === 0}
 title="Download the current graph as a d3.json file (GNN-ready nodeId/moduleRank format)"
 >
 Export d3.json
 </Button>
 <Button
 variant="ghost"
 size="sm"
 onClick={handleRescan}
 disabled={!selectedProject || rescanning || loading}
 title="Re-run a Trivy scan for the picked project and refresh the graph"
 >
 {rescanning ? "Re-scanning…" : "Re-scan"}
 </Button>
 </div>

 {rescanMessage && (
 <div
 style={{
 marginBottom: "var(--space-3)",
 padding: "var(--space-2) var(--space-3)",
 background: "var(--color-info-soft, #eff6ff)",
 color: "var(--color-primary)",
 borderRadius: "var(--radius-md)",
 fontSize: "var(--text-sm)",
 }}
 >
 {rescanMessage}
 </div>
 )}

 <ErrorBanner error={error} />

 {loading ? (
 <Spinner center size="md" label="Building graph…" />
 ) : projects.length === 0 ? (
 <EmptyState title="No projects yet" hint="Run a scan from the Scan page to populate the graph." />
 ) : nodes.length === 0 ? (
 <EmptyState
 title={`No graph data for ${selectedProject?.name || "this project"}`}
 hint="Trigger a scan for this project to build the dependency graph."
 />
 ) : (
 <div
 ref={graphContainerRef}
 style={{
 background: "var(--bg-surface)",
 border: "1px solid var(--border-subtle)",
 borderRadius: "var(--radius-lg)",
 boxShadow: "var(--shadow-xs)",
 marginBottom: "var(--space-4)",
 overflow: "hidden",
 minHeight: 520,
 }}
 />
 )}
 </div>
 );
}
