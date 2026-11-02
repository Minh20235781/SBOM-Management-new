import { useEffect, useState } from "react";
import PageHeader from "../../components/shared/PageHeader";
import StatCard from "../../components/shared/StatCard";
import ErrorBanner from "../../components/shared/ErrorBanner";
import Spinner from "../../components/shared/Spinner";
import EmptyState from "../../components/shared/EmptyState";
import RiskDistributionView from "../../components/shared/RiskDistribution";
import projectApi from "../../api/projectApi";
import legacyApi from "../../api/legacyApi";
import { safeArray } from "../../utils/safe";

/** Build payload for Python GNN inference. */
function buildPythonPayload(graph, vulnIndex, model) {
 const idLookup = new Map();
 const nodes = safeArray(graph?.nodes).map((n, idx) => {
 const intId = typeof n?.id === "number" ? n.id : idx + 1;
 const name = n?.name || n?.packageName || `node-${intId}`;
 idLookup.set(String(n?.id), intId);
 idLookup.set(name, intId);
 const v = vulnIndex.get(String(name).toLowerCase()) || {};
 const maxCvss = Number(v.maxCvss ?? 0);
 const sevW = maxCvss > 0 ? maxCvss / 10 : 0;
 return {
 nodeId: intId,
 packageName: name,
 features: {
 moduleRank: Number(n?.rank ?? n?.moduleRank ?? n?.rankScore ?? 0),
 maxCvss,
 avgCvss: maxCvss,
 maxEpss: 0,
 avgEpss: 0,
 kevCount: Number(v.kevCount ?? 0),
 vulnerabilityCount: Number(v.vulnCount ?? 0),
 severityWeight: sevW,
 },
 };
 });
 const edges = safeArray(graph?.edges)
 .map((e) => {
 const rawSrc = e?.source ?? e?.from;
 const rawDst = e?.target ?? e?.to;
 const source = idLookup.get(String(rawSrc));
 const target = idLookup.get(String(rawDst));
 if (source == null || target == null) return null;
 return { source, target };
 })
 .filter(Boolean);
 const modelPath = model === "gcn"
 ? "../gnn-training/exports/gcn_model.pt"
 : "../gnn-training/exports/gat_model.pt";
 return {
 model_path: modelPath,
 model,
 data: { nodes, edges },
 timeout_seconds: 30,
 };
}

/** Severity to approximate CVSS mapping. */
const SEVERITY_TO_CVSS = {
 CRITICAL: 9.5,
 HIGH: 7.5,
 MEDIUM: 5.0,
 LOW: 3.0,
};

function buildVulnIndex(sbomRows) {
 const index = new Map();
 for (const row of safeArray(sbomRows)) {
 const name = String(row.package_name || "").toLowerCase();
 if (!name) continue;
 const cvss = Number(row.cvss ?? 0);
 const sev = String(row.severity || "").toUpperCase();
 const fallback = SEVERITY_TO_CVSS[sev] || 0;
 const effectiveCvss = cvss > 0 ? cvss : fallback;
 const kev = sev === "CRITICAL" ? 1 : 0;
 const existing = index.get(name) || { maxCvss: 0, vulnCount: 0, kevCount: 0 };
 existing.maxCvss = Math.max(existing.maxCvss, effectiveCvss);
 existing.vulnCount += 1;
 existing.kevCount = Math.max(existing.kevCount, kev);
 index.set(name, existing);
 }
 return index;
}

async function runPythonInference(payload) {
 // /gnn-inference is Vite-proxy → localhost:8000 in dev.
 const res = await fetch("/gnn-inference/predict", {
 method: "POST",
 headers: { "Content-Type": "application/json" },
 body: JSON.stringify(payload),
 });
 if (!res.ok) {
 const text = await res.text();
 throw new Error(text || `Python inference failed: ${res.status}`);
 }
 const data = await res.json();
 return safeArray(data?.items);
}

/** GNN page: GAT and GCN model inference. */
const TABS = [
 { key: "gat", label: "GAT" },
 { key: "gcn", label: "GCN" },
];

/** Reshape graph for GNN explainability endpoint. */
function flattenForExplainability(graphData) {
 const rawNodes = safeArray(graphData?.nodes);
 // /api/graph/rank uses string node IDs ("122", "compiler", …).
 // Build a map from that string id to the integer nodeId the
 // model wants. Edges reference the same string ids.
 const idLookup = new Map();
 const nodes = rawNodes.map((n, idx) => {
 const rawId = n?.id;
 const intId = typeof rawId === "number" ? rawId : idx + 1;
 const name = n?.name || n?.packageName || `node-${intId}`;
 idLookup.set(String(rawId), intId);
 idLookup.set(name, intId);
 return {
 nodeId: intId,
 packageName: name,
 moduleRank: Number(n?.moduleRank ?? n?.rank ?? n?.rankScore ?? 0),
 maxCvss: 0,
 avgCvss: 0,
 maxEpss: 0,
 avgEpss: 0,
 kevCount: 0,
 vulnerabilityCount: 0,
 severityWeight: 0,
 };
 });
 const edges = safeArray(graphData?.edges)
 .map((e) => {
 const rawSource = e?.source ?? e?.from;
 const rawTarget = e?.target ?? e?.to;
 const source = idLookup.get(String(rawSource));
 const target = idLookup.get(String(rawTarget));
 if (source == null || target == null) return null;
 return { source, target };
 })
 .filter(Boolean);
 return { nodes, edges };
}

function riskTone(level) {
 const v = String(level || "").toUpperCase();
 if (v === "HIGH") return { bg: "#dc2626", label: "HIGH" };
 if (v === "MEDIUM") return { bg: "#f59e0b", label: "MEDIUM" };
 if (v === "LOW") return { bg: "#10b981", label: "LOW" };
 return { bg: "var(--text-muted)", label: String(level || "—").toUpperCase() };
}

/** Compute percentile rank for moduleRank values (0-100 scale). */
function computePercentileRank(value, allValues) {
 if (value == null || !allValues?.length) return null;
 const sorted = [...allValues].sort((a, b) => a - b);
 let countBelow = 0;
 for (const v of sorted) {
 if (v < value) countBelow++;
 }
 return (countBelow * 100) / sorted.length;
}

/** Extra columns for GNN prediction results. */
const GNN_COLUMNS = [
 {
 key: "attention",
 header: "Self-Attention",
 width: 100,
 align: "right",
 numeric: true,
 sortable: true,
 render: (r) => `${Math.round((Number(r.attention) || 0) * 100)}%`,
 },
 {
 key: "propagation",
 header: "Propagation",
 width: 100,
 align: "right",
 numeric: true,
 sortable: true,
 render: (r) => `${Math.round((Number(r.propagation) || 0) * 100)}%`,
 },
 {
 key: "confidenceScore",
 header: "Confidence",
 width: 90,
 align: "right",
 numeric: true,
 sortable: true,
 render: (r) => `${((Number(r.confidenceScore) || 0) * 100).toFixed(1)}%`,
 },
 {
 key: "moduleRank",
 header: "Rank",
 width: 110,
 align: "right",
 numeric: true,
 sortable: true,
 render: (r) => r.moduleRank != null ? `Top ${(r.moduleRank).toFixed(1)}%` : "—",
 },
];

export default function GNNPage() {
 const [projects, setProjects] = useState([]);
 const [projectId, setProjectId] = useState(null);
 const [tab, setTab] = useState("gat");
 const [exportData, setExportData] = useState(null);
 const [explainations, setExplainations] = useState([]);
 const [loading, setLoading] = useState(false);
 const [error, setError] = useState(null);
 const [step, setStep] = useState("");

 useEffect(() => {
 projectApi.list()
 .then((list) => {
 const arr = safeArray(list);
 setProjects(arr);
 if (arr.length > 0 && projectId == null) {
 const richest = [...arr].sort((a, b) => (b.packageCount || 0) - (a.packageCount || 0))[0];
 setProjectId(richest.id);
 }
 })
 .catch((e) => setError(e?.message || "Failed to load projects"));
 // eslint-disable-next-line react-hooks/exhaustive-deps
 }, []);

 useEffect(() => {
 if (projectId == null) return;
 let cancelled = false;
 (async () => {
 const project = projects.find((p) => p.id === projectId);
 if (!project?.name) return;
 setLoading(true);
 setError(null);
 setExportData(null);
 setExplainations([]);
 try {
 // Step 1: fetch the dependency graph and the SBOM table
 // for this project in parallel. The graph gives us the
 // node list + edges; the SBOM table gives us per-package
 // vulnerability counts and CVSS that we attach to the
 // features block so the model sees real risk signals
 // (otherwise everything comes back HIGH with zero scores).
 setStep("Loading graph + vulnerability data…");
 const [graph, sbomRows] = await Promise.all([
 legacyApi.graphRank(project.name),
 legacyApi.sbomTable(project.name).catch(() => []),
 ]);
 if (cancelled) return;
 setExportData(graph);
 const vulnIndex = buildVulnIndex(sbomRows);

 // Step 2: run the actual model. We call the Python
 // inference service directly (Vite-proxied to :8000) so
 // the model sees the `features` block under each node —
 // going through /api/v2/gnn/explainability/analyze drops
 // that block on the Java side and the model silently
 // returns an empty list.
 setStep(`Running ${tab.toUpperCase()} inference…`);
 const payload = buildPythonPayload(graph, vulnIndex, tab);
 const items = await runPythonInference(payload);
 if (cancelled) return;
 setExplainations(items);
 } catch (e) {
 if (!cancelled) setError(e?.response?.data || e?.message || `Failed to load ${tab.toUpperCase()} result`);
 } finally {
 if (!cancelled) {
 setLoading(false);
 setStep("");
 }
 }
 })();
 return () => { cancelled = true; };
 // eslint-disable-next-line react-hooks/exhaustive-deps
 }, [projectId, tab]);

 const selected = projects.find((p) => p.id === projectId);
 const nodes = safeArray(exportData?.nodes);
 const edges = safeArray(exportData?.edges);

 // Index explanations by packageName for the table render.
 const explainByName = new Map();
 for (const ex of explainations) {
 if (ex && ex.packageName) explainByName.set(String(ex.packageName).toLowerCase(), ex);
 }

 // Collect all moduleRank values for percentile calculation
 const allModuleRanks = nodes.map((n) => Number(n.rank ?? n.moduleRank ?? 0));

 // Build the full per-node rows first (we need them to
 // compute the risk-distribution counts for the stat cards
 // — slicing to 20 first would under-count HIGH/MEDIUM/LOW).
 // Then we sort by risk + attention and slice to 20 for the
 // table view.
 const RISK_ORDER = { HIGH: 3, MEDIUM: 2, LOW: 1 };
 const allRows = nodes
 .map((n) => {
 const name = n.packageName || n.name || n.id || `node-${n.id}`;
 const ex = explainByName.get(String(name).toLowerCase());
 // Python /predict returns a flat item:
 // {nodeId, packageName, predictedRisk, confidenceScore,
 // attentionScore, propagationRisk}. The previous shape
 // (attentionScores.{selfAttention, propagationRisk, maxEpss,
 // vulnerabilityCount} + influentialNeighbors + explanationText)
 // was produced by the Java /api/v2/gnn/explainability/analyze
 // endpoint, which we no longer call from this page. Read the
 // flat fields directly; leave the absent ones at 0 / [] / ""
 // so the table still renders.
 const rawModuleRank = Number(n.rank ?? n.moduleRank ?? 0);
 // moduleRank displayed as percentile (Top X%)
 const moduleRank = computePercentileRank(rawModuleRank, allModuleRanks);
 return {
 id: n.id ?? n.nodeId,
 name,
 predictedRisk: ex?.predictedRisk || "—",
 attention: Number(ex?.attentionScore ?? 0),
 propagation: Number(ex?.propagationRisk ?? 0),
 confidenceScore: Number(ex?.confidenceScore ?? 0),
 maxEpss: 0,
 vulnCount: 0,
 neighbours: safeArray(ex?.influentialNeighbors),
 explanation: ex?.explanationText || "",
 moduleRank,
 };
 });

 const riskCounts = allRows.reduce((acc, r) => {
 const k = String(r.predictedRisk || "—").toUpperCase();
 acc[k] = (acc[k] || 0) + 1;
 return acc;
 }, {});

 const displayRows = allRows
 .slice()
 .sort((a, b) => {
 const ra = RISK_ORDER[a.predictedRisk] || 0;
 const rb = RISK_ORDER[b.predictedRisk] || 0;
 if (ra !== rb) return rb - ra;
 return (b.attention + b.propagation) - (a.attention + a.propagation);
 })
 .slice(0, 20);

 return (
 <div>
 <PageHeader
 title="GNN Module Rank"
 description="Top-ranked nodes per project, computed by the actual GAT/GCN model. Each row carries the predicted risk level, attention weight, and propagation risk from the model."
 />

 <div
 style={{
 display: "flex",
 gap: "var(--space-3)",
 alignItems: "center",
 flexWrap: "wrap",
 marginBottom: "var(--space-4)",
 }}
 >
 <label style={{ fontSize: "var(--text-sm)", color: "var(--text-secondary)" }}>Project</label>
 <select
 value={projectId ?? ""}
 onChange={(e) => setProjectId(Number(e.target.value))}
 style={{
 height: 36, padding: "0 12px", border: "1px solid var(--border-default)",
 borderRadius: "var(--radius-md)", fontSize: "var(--text-sm)", background: "var(--bg-surface)", minWidth: 260,
 }}
 >
 {projects.length === 0 && <option value="">(no projects)</option>}
 {projects.map((p) => (
 <option key={p.id} value={p.id}>{p.name} ({p.packageCount ?? 0} packages)</option>
 ))}
 </select>

 <div style={{ display: "flex", gap: 2, marginLeft: "auto" }}>
 {TABS.map((t) => (
 <button
 key={t.key}
 onClick={() => setTab(t.key)}
 style={{
 background: "transparent", border: "none", padding: "8px 14px",
 fontSize: "var(--text-sm)", fontWeight: tab === t.key ? "var(--weight-semibold)" : "var(--weight-medium)",
 color: tab === t.key ? "var(--color-primary)" : "var(--text-secondary)",
 borderBottom: tab === t.key ? "2px solid var(--color-primary)" : "2px solid transparent",
 cursor: "pointer",
 }}
 >
 {t.label}
 </button>
 ))}
 </div>
 </div>

 <div
 style={{
 display: "grid",
 gridTemplateColumns: "repeat(auto-fit, minmax(180px, 1fr))",
 gap: "var(--space-3)",
 marginBottom: "var(--space-4)",
 }}
 >
 <StatCard label="Nodes" value={allRows.length} subValue="In the dependency graph" />
 <StatCard label="Edges" value={edges.length} subValue="Direct dependencies" />
 <StatCard label="High risk" value={riskCounts.HIGH || 0} subValue="From model" accent="danger" />
 <StatCard label="Medium risk" value={riskCounts.MEDIUM || 0} subValue="From model" accent="warning" />
 <StatCard label="Low risk" value={riskCounts.LOW || 0} subValue="From model" accent="success" />
 </div>

 <ErrorBanner error={error} />

 {loading ? (
 <Spinner center size="md" label={step || `Running ${tab.toUpperCase()}…`} />
 ) : displayRows.length === 0 ? (
 <EmptyState
 title="No graph data"
 hint={selected
 ? `Project "${selected.name}" has no graph nodes yet. Trigger a scan to populate the dependency graph.`
 : "Pick a project above."}
 />
 ) : (
 <>
 <RiskDistributionView
 title={`${tab.toUpperCase()} prediction`}
 totalLabel="nodes"
 items={allRows}
 extraColumns={GNN_COLUMNS}
 showAll
 emptyHint="No nodes yet."
 />
 {displayRows.some((r) => r.explanation) && (
 <div style={{ marginTop: "var(--space-4)" }}>
 <h3 style={{ fontSize: "var(--text-md)", margin: "0 0 var(--space-2) 0" }}>
 Top risk explanations
 </h3>
 <div style={{ display: "grid", gap: "var(--space-2)" }}>
 {displayRows
 .filter((r) => r.predictedRisk === "HIGH")
 .slice(0, 5)
 .map((r) => (
 <div
 key={r.id}
 style={{
 background: "var(--bg-surface)", border: "1px solid var(--border-subtle)",
 borderRadius: "var(--radius-md)", padding: "var(--space-3) var(--space-4)",
 }}
 >
 <div style={{ display: "flex", alignItems: "center", gap: "var(--space-2)", marginBottom: 4 }}>
 <b>{r.name}</b>
 <span style={{
 ...riskTone(r.predictedRisk),
 background: riskTone(r.predictedRisk).bg,
 color: "white", padding: "2px 8px", borderRadius: "9999px",
 fontSize: "var(--text-xs)", fontWeight: 700,
 }}>
 {riskTone(r.predictedRisk).label}
 </span>
 </div>
 <pre style={{
 margin: 0, whiteSpace: "pre-wrap", fontSize: "var(--text-xs)",
 color: "var(--text-secondary)",
 }}>
 {r.explanation}
 </pre>
 {r.neighbours.length > 0 && (
 <div style={{ marginTop: 6, fontSize: "var(--text-xs)", color: "var(--text-muted)" }}>
 Top influential neighbours: {r.neighbours.slice(0, 3).map((n) => `${n.packageName} (${Number(n.influenceScore || 0).toFixed(2)})`).join(", ")}
 </div>
 )}
 </div>
 ))}
 </div>
 </div>
 )}
 </>
 )}
 </div>
 );
}
