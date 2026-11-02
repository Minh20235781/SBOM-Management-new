import { BrowserRouter, Navigate, Route, Routes } from "react-router-dom";
import AppLayout from "./components/layout/AppLayout.jsx";
import MainDashboard from "./pages/Dashboard/MainDashboard.jsx";
import ProjectList from "./pages/Projects/ProjectList.jsx";
import ProjectDetail from "./pages/Projects/detail/ProjectDetail.jsx";
import AuditTimeline from "./pages/AuditTimeline/AuditTimeline.jsx";
import VulnsPage from "./pages/Vulnerabilities/VulnsPage.jsx";
import ScanPage from "./pages/Scan/ScanPage.jsx";
import SbomTablePage from "./pages/SbomTable/SbomTablePage.jsx";
import InsightsPage from "./pages/Insights/InsightsPage.jsx";
import GraphPage from "./pages/Graph/GraphPage.jsx";
import AIPage from "./pages/AI/AIPage.jsx";
import GNNPage from "./pages/GNN/GNNPage.jsx";
import TrustScorePage from "./pages/TrustScore/TrustScorePage.jsx";
import ReconciliationPage from "./pages/Reconciliation/ReconciliationPage.jsx";
import Toaster from "./components/shared/Toaster.jsx";

/**
 * Top-level router. Every page lives inside the AppLayout shell
 * and is reachable from the sidebar. The legacy "/" redirects
 * to "/dashboard" so old bookmarks keep working.
 *
 * Route inventory (12 routes total):
 * - /dashboard, /projects, /projects/:id
 * - /scan, /sbom-table, /insights, /graph
 * - /ai, /gnn, /trust-score (AI/research/security surfaces)
 * - /vulns, /audit (project-scoped history)
 *
 * (Threat Intel page was retired — its single CVE-lookup use case
 * is covered by a future Project detail panel.)
 */
function App() {
	return (
		<BrowserRouter>
			<Toaster />
			<Routes>
				<Route element={<AppLayout />}>
					<Route path="/" element={<Navigate to="/dashboard" replace />} />
					<Route path="/dashboard" element={<MainDashboard />} />
					<Route path="/projects" element={<ProjectList />} />
					<Route path="/projects/:id" element={<ProjectDetail />} />
					<Route path="/scan" element={<ScanPage />} />
					<Route path="/sbom-table" element={<SbomTablePage />} />
					<Route path="/insights" element={<InsightsPage />} />
					<Route path="/graph" element={<GraphPage />} />
					<Route path="/ai" element={<AIPage />} />
					<Route path="/gnn" element={<GNNPage />} />
					<Route path="/trust-score" element={<TrustScorePage />} />
					<Route path="/reconciliation" element={<ReconciliationPage />} />
					<Route path="/vulns" element={<VulnsPage />} />
					<Route path="/audit" element={<AuditTimeline />} />
					<Route path="*" element={<NotFoundPage />} />
				</Route>
			</Routes>
		</BrowserRouter>
	);
}

function NotFoundPage() {
	return (
		<div
			style={{
				background: "var(--bg-surface)",
				border: "1px dashed var(--border-default)",
				borderRadius: "var(--radius-lg)",
				padding: "var(--space-10)",
				textAlign: "center",
				color: "var(--text-muted)",
			}}
		>
			<h2 style={{ color: "var(--text-primary)" }}>Page not found</h2>
			<p>The URL you visited doesn't match any of our routes.</p>
		</div>
	);
}

export default App;
