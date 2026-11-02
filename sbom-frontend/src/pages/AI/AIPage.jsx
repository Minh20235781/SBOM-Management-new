import { useEffect, useState } from "react";
import PageHeader from "../../components/shared/PageHeader";
import Button from "../../components/shared/Button";
import ErrorBanner from "../../components/shared/ErrorBanner";
import Spinner from "../../components/shared/Spinner";
import EmptyState from "../../components/shared/EmptyState";
import StatCard from "../../components/shared/StatCard";
import RiskDistributionView from "../../components/shared/RiskDistribution";
import aiApi from "../../api/aiApi";
import projectApi from "../../api/projectApi";
import { safeArray, safeObject } from "../../utils/safe";

/** AI page: Risk Analysis (Gemini) and AI-RF Score (RandomForest 13 features). */
const TABS = [
 { key: "risk", label: "Risk Analysis" },
 { key: "rf-new", label: "AI-RF Score" },
];

export default function AIPage() {
 const [tab, setTab] = useState("risk");

 return (
 <div>
 <PageHeader
 title="AI"
 description="Gemini-backed risk analysis on uploaded SBOMs and the Zenodo-trained 13-feature RF model for package risk prediction."
 />

 <div style={{ display: "flex", gap: 2, borderBottom: "1px solid var(--border-subtle)", marginBottom: "var(--space-5)" }}>
 {TABS.map((t) => (
 <button
 key={t.key}
 onClick={() => setTab(t.key)}
 style={{
 background: "transparent", border: "none", padding: "10px 14px",
 fontSize: "var(--text-sm)", fontWeight: tab === t.key ? "var(--weight-semibold)" : "var(--weight-medium)",
 color: tab === t.key ? "var(--color-primary)" : "var(--text-secondary)",
 borderBottom: tab === t.key ? "2px solid var(--color-primary)" : "2px solid transparent",
 marginBottom: -1, cursor: "pointer",
 }}
 >
 {t.label}
 </button>
 ))}
 </div>

 {tab === "risk" && <RiskAnalysisTab />}
 {tab === "rf-new" && <RfNewTab />}
 </div>
 );
}

function RiskAnalysisTab() {
 const [file, setFile] = useState(null);
 const [running, setRunning] = useState(false);
 const [result, setResult] = useState(null);
 const [error, setError] = useState(null);

 const submit = async () => {
 if (!file) return;
 setRunning(true);
 setError(null);
 setResult(null);
 try {
 setResult(await aiApi.riskAnalysis(file, file.name.replace(/\.json$/i, "")));
 } catch (e) {
 setError(e?.response?.data || e?.message || "AI risk analysis failed");
 } finally {
 setRunning(false);
 }
 };

 return (
 <div style={{ display: "grid", gap: "var(--space-4)" }}>
 <div
 style={{
 background: "var(--bg-surface)", border: "1px solid var(--border-subtle)",
 borderRadius: "var(--radius-lg)", padding: "var(--space-5)", boxShadow: "var(--shadow-xs)",
 }}
 >
 <h3 style={{ margin: "0 0 var(--space-3) 0", fontSize: "var(--text-md)" }}>Upload SBOM JSON</h3>
 <p style={{ color: "var(--text-secondary)", fontSize: "var(--text-sm)", margin: "0 0 var(--space-3) 0" }}>
 Pick an SBOM file. The backend runs a Gemini-backed analysis to produce a risk score and breakdown.
 </p>
 <div style={{ display: "flex", gap: "var(--space-2)", alignItems: "center" }}>
 <input
 type="file"
 accept=".json"
 onChange={(e) => setFile(e.target.files?.[0] || null)}
 disabled={running}
 style={{ fontSize: "var(--text-sm)" }}
 />
 <Button onClick={submit} disabled={!file || running}>
 {running ? "Analyzing…" : "Run analysis"}
 </Button>
 </div>
 <ErrorBanner error={error} />
 </div>

 {running && <Spinner center label="Running AI analysis…" />}
 {!running && result && <ResultView result={result} />}
 </div>
 );
}

/** Extra columns for RF prediction results. */
const ML_COLUMNS = [
 { key: "version", header: "Version", render: (r) => r.version || "—" },
 {
 key: "confidence",
 header: "Confidence",
 width: 110,
 align: "right",
 numeric: true,
 render: (r) => r.confidence.toFixed(2),
 },
 {
 key: "probabilityHigh",
 header: "P(high)",
 width: 90,
 align: "right",
 numeric: true,
 render: (r) => r.probabilityHigh.toFixed(2),
 },
 {
 key: "probabilityMedium",
 header: "P(med)",
 width: 90,
 align: "right",
 numeric: true,
 render: (r) => r.probabilityMedium.toFixed(2),
 },
 {
 key: "probabilityLow",
 header: "P(low)",
 width: 90,
 align: "right",
 numeric: true,
 render: (r) => r.probabilityLow.toFixed(2),
 },
];

function GeminiResultView({ result }) {
 const score = result?.scoreData;
 const recommendations = safeArray(result?.recommendations);

 const gradeColor = score?.gradeColor || gradeToColor(score?.grade);

 return (
 <div
 style={{
 background: "var(--bg-surface)", border: "1px solid var(--border-subtle)",
 borderRadius: "var(--radius-lg)", padding: "var(--space-5)", boxShadow: "var(--shadow-xs)",
 display: "grid", gap: "var(--space-4)",
 }}
 >
 {/* Header — score + grade focal point */}
 <div
 style={{
 display: "flex", alignItems: "center", gap: "var(--space-4)",
 flexWrap: "wrap",
 }}
 >
 {score?.repoScore != null && (
 <div
 style={{
 display: "flex", alignItems: "baseline", gap: 4,
 padding: "var(--space-3) var(--space-4)",
 borderRadius: "var(--radius-lg)",
 background: "var(--bg-app)", border: "1px solid var(--border-subtle)",
 minWidth: 140,
 }}
 >
 <span style={{ fontSize: 40, fontWeight: "var(--weight-bold)", lineHeight: 1, color: gradeColor }}>
 {score.repoScore}
 </span>
 <span style={{ fontSize: "var(--text-sm)", color: "var(--text-secondary)" }}>
 /100
 </span>
 </div>
 )}
 {score?.grade && (
 <div
 style={{
 padding: "var(--space-2) var(--space-4)",
 borderRadius: "var(--radius-md)",
 background: gradeColor, color: "#fff",
 fontSize: "var(--text-lg)", fontWeight: "var(--weight-bold)",
 letterSpacing: 1, minWidth: 56, textAlign: "center",
 }}
 >
 {score.grade}
 </div>
 )}
 <div style={{ flex: 1, minWidth: 200 }}>
 <div style={{ fontSize: "var(--text-md)", fontWeight: "var(--weight-semibold)" }}>
 AI Risk Analysis
 </div>
 {score?.mostRiskyPackage && (
 <div style={{ fontSize: "var(--text-sm)", color: "var(--text-secondary)" }}>
 Most risky: <strong>{score.mostRiskyPackage}</strong>
 </div>
 )}
 </div>
 </div>

 {/* Compact stat row */}
 <div
 style={{
 display: "grid",
 gridTemplateColumns: "repeat(auto-fit, minmax(120px, 1fr))",
 gap: "var(--space-2)",
 }}
 >
 <StatCard label="Total packages" value={score?.totalPackages} />
 <StatCard label="Vulnerable" value={score?.vulnerablePackages} />
 <StatCard label="Critical" value={score?.criticalCount} tone="critical" />
 <StatCard label="High" value={score?.highCount} tone="high" />
 <StatCard label="Medium" value={score?.mediumCount} tone="medium" />
 <StatCard label="Low" value={score?.lowCount} tone="low" />
 </div>

 {/* Recommendations */}
 {recommendations.length > 0 ? (
 <div>
 <h4 style={{ margin: "0 0 var(--space-3) 0", fontSize: "var(--text-sm)", fontWeight: "var(--weight-semibold)" }}>
 Recommendations ({recommendations.length})
 </h4>
 <div
 style={{
 display: "grid", gap: "var(--space-3)",
 gridTemplateColumns: "repeat(auto-fit, minmax(280px, 1fr))",
 }}
 >
 {recommendations.map((rec, i) => (
 <RecommendationCard key={i} rec={rec} />
 ))}
 </div>
 </div>
 ) : (
 <p style={{ color: "var(--text-secondary)", fontSize: "var(--text-sm)", margin: 0 }}>
 No recommendations returned.
 </p>
 )}
 </div>
 );
}

function RecommendationCard({ rec }) {
 const priority = rec?.priority;
 const effort = rec?.estimatedEffort;
 const effortTone = effort === "HIGH" ? "high" : effort === "MEDIUM" ? "medium" : "low";

 return (
 <div
 style={{
 background: "var(--bg-app)", border: "1px solid var(--border-subtle)",
 borderRadius: "var(--radius-md)", padding: "var(--space-4)",
 display: "grid", gap: "var(--space-2)",
 }}
 >
 <div style={{ display: "flex", alignItems: "center", gap: "var(--space-2)", flexWrap: "wrap" }}>
 {priority != null && (
 <span style={priorityBadgeStyle(priority)}>
 P{priority}
 </span>
 )}
 <span style={{ fontSize: "var(--text-sm)", fontWeight: "var(--weight-semibold)", flex: 1, minWidth: 0, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
 {rec?.packageName || "Recommendation"}
 </span>
 {effort && (
 <span style={effortBadgeStyle(effortTone)}>
 {effort}
 </span>
 )}
 </div>

 {rec?.issue && (
 <p style={{ margin: 0, fontSize: "var(--text-sm)", color: "var(--text-primary)", lineHeight: 1.5 }}>
 {rec.issue}
 </p>
 )}

 {rec?.suggestion && (
 <div
 style={{
 fontSize: "var(--text-sm)", color: "var(--text-secondary)",
 paddingTop: "var(--space-2)",
 borderTop: "1px solid var(--border-subtle)",
 }}
 >
 <strong style={{ color: "var(--text-primary)" }}>Suggested fix:</strong> {rec.suggestion}
 </div>
 )}

 {rec?.impactIfNotFixed && (
 <div style={{ fontSize: "var(--text-xs)", color: "var(--text-secondary)" }}>
 <strong>Impact:</strong> {rec.impactIfNotFixed}
 </div>
 )}
 </div>
 );
}

function gradeToColor(grade) {
 if (!grade) return "var(--text-secondary)";
 const g = String(grade).toUpperCase().charAt(0);
 if (g === "A") return "#10b981"; // green
 if (g === "B") return "#22c55e";
 if (g === "C") return "#f59e0b"; // amber
 if (g === "D") return "#f97316"; // orange
 if (g === "F") return "#ef4444"; // red
 return "var(--text-secondary)";
}

function priorityBadgeStyle(p) {
 let bg = "#64748b"; // default slate
 if (p === 1) bg = "#ef4444"; // red
 else if (p === 2) bg = "#f97316"; // orange
 else if (p === 3) bg = "#f59e0b"; // amber
 else if (p === 4) bg = "#3b82f6"; // blue
 else if (p === 5) bg = "#64748b";
 return {
 background: bg, color: "#fff",
 fontSize: 11, fontWeight: "var(--weight-semibold)",
 padding: "2px 8px", borderRadius: 999,
 letterSpacing: 0.5,
 };
}

function effortBadgeStyle(tone) {
 const map = {
 high: { bg: "#fee2e2", color: "#b91c1c" },
 medium: { bg: "#fef3c7", color: "#92400e" },
 low: { bg: "#dcfce7", color: "#166534" },
 };
 const c = map[tone] || map.low;
 return {
 background: c.bg, color: c.color,
 fontSize: 11, fontWeight: "var(--weight-semibold)",
 padding: "2px 8px", borderRadius: 999,
 textTransform: "uppercase", letterSpacing: 0.5,
 };
}

function ResultView({ result }) {
 // Handle Gemini response (score + recommendations)
 if (result?.scoreData || Array.isArray(result?.recommendations)) {
 return <GeminiResultView result={result} />;
 }

 // Handle RF prediction response
 const items = safeArray(result?.items);
 const hasItems = items.length > 0;

 if (hasItems) {
 const display = items.map((it) => ({
 key: it.packageName,
 name: it.packageName,
 predictedRisk: String(it.predictedRisk || "").toUpperCase(),
 confidence: Number(it.confidence ?? 0),
 probabilityHigh: Number(it.probabilityHigh ?? 0),
 probabilityMedium: Number(it.probabilityMedium ?? 0),
 probabilityLow: Number(it.probabilityLow ?? 0),
 version: it.version,
 }));
 return (
 <RiskDistributionView
 title="ML Prediction"
 totalLabel="packages"
 items={display}
 extraColumns={ML_COLUMNS}
 emptyHint="No packages match the filter."
 />
 );
 }

 // Fallback: legacy / flat shape
 const score = result?.score ?? result?.scoreData?.score ?? result?.riskScore;
 const grade = result?.grade ?? result?.scoreData?.grade;
 const vulnCount = result?.totalVulnerabilities ?? result?.vulnerabilityCount;
 return (
 <div
 style={{
 background: "var(--bg-surface)", border: "1px solid var(--border-subtle)",
 borderRadius: "var(--radius-lg)", padding: "var(--space-5)", boxShadow: "var(--shadow-xs)",
 }}
 >
 <h3 style={{ margin: "0 0 var(--space-3) 0", fontSize: "var(--text-md)" }}>Result</h3>
 {(score != null || grade || vulnCount != null) && (
 <div
 style={{
 display: "grid",
 gridTemplateColumns: "repeat(auto-fit, minmax(140px, 1fr))",
 gap: "var(--space-3)",
 marginBottom: "var(--space-3)",
 }}
 >
 {score != null && <StatCard label="Score" value={typeof score === "number" ? score.toFixed(1) : score} />}
 {grade && <StatCard label="Grade" value={grade} />}
 {vulnCount != null && <StatCard label="Vulnerabilities" value={vulnCount} />}
 </div>
 )}
 <pre
 style={{
 background: "var(--bg-app)", border: "1px solid var(--border-subtle)",
 borderRadius: "var(--radius-md)", padding: "var(--space-3)",
 fontSize: "var(--text-xs)", overflow: "auto", maxHeight: 320,
 }}
 >
 {JSON.stringify(result, null, 2)}
 </pre>
 </div>
 );
}

function RfNewTab() {
 const [projects, setProjects] = useState([]);
 const [projectId, setProjectId] = useState(null);
 const [data, setData] = useState(null);
 const [loading, setLoading] = useState(false);
 const [error, setError] = useState(null);

 useEffect(() => {
 projectApi.list()
 .then((list) => {
 const arr = safeArray(list);
 setProjects(arr);
 if (arr.length > 0 && projectId == null) setProjectId(arr[0].id);
 })
 .catch((e) => setError(e?.message || "Failed to load projects"));
 // eslint-disable-next-line react-hooks/exhaustive-deps
 }, []);

 const selected = projects.find((p) => p.id === projectId);

 const run = async () => {
 if (!selected?.name) return;
 setLoading(true);
 setError(null);
 setData(null);
 try {
 setData(safeObject(await aiApi.rfNewPredict(selected.name)));
 } catch (e) {
 setError(e?.response?.data || e?.message || "Zenodo RF predict failed");
 } finally {
 setLoading(false);
 }
 };

 return (
 <div style={{ display: "grid", gap: "var(--space-4)" }}>
 <div
 style={{
 background: "var(--bg-surface)", border: "1px solid var(--border-subtle)",
 borderRadius: "var(--radius-lg)", padding: "var(--space-5)", boxShadow: "var(--shadow-xs)",
 }}
 >
 <h3 style={{ margin: "0 0 var(--space-3) 0", fontSize: "var(--text-md)" }}>
ML Score (RandomForest)
 </h3>
 <p style={{ color: "var(--text-secondary)", fontSize: "var(--text-sm)", margin: "0 0 var(--space-3) 0" }}>
Select a project to analyze.
 </p>
 <div style={{ display: "flex", gap: "var(--space-2)", alignItems: "center" }}>
 <select
 value={projectId ?? ""}
 onChange={(e) => { setProjectId(Number(e.target.value)); setData(null); }}
 disabled={projects.length === 0}
 style={{
 flex: 1, height: 36, padding: "0 12px", border: "1px solid var(--border-default)",
 borderRadius: "var(--radius-md)", fontSize: "var(--text-sm)", background: "var(--bg-surface)",
 }}
 >
 {projects.length === 0 && <option value="">(no projects scanned yet)</option>}
 {projects.map((p) => (
 <option key={p.id} value={p.id}>
 {p.name} ({p.packageCount ?? 0} packages)
 </option>
 ))}
 </select>
 <Button onClick={run} disabled={!selected || loading}>
 {loading ? "Predicting…" : "Predict"}
 </Button>
 </div>
 <ErrorBanner error={error} />
 </div>

 {loading && <Spinner center label="Running Zenodo RF prediction…" />}
 {!loading && data && <ResultView result={data} />}
 </div>
 );
}
