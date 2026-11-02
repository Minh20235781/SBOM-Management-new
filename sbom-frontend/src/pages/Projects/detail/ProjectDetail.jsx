import { useState } from "react";
import { useParams } from "react-router-dom";
import StatusBadge from "../../../components/shared/StatusBadge";
import useProjectData from "../../../hooks/useProjectData";
import OverviewTab from "./tabs/OverviewTab";
import VulnsTab from "./tabs/VulnsTab";
import ResourcesTab from "./tabs/ResourcesTab";
import HistoryTab from "./tabs/HistoryTab";
import SettingsTab from "./tabs/SettingsTab";
import ErrorBanner from "../../../components/shared/ErrorBanner";
import Spinner from "../../../components/shared/Spinner";
import styles from "./ProjectDetail.module.css";

const TABS = [
 { key: "overview", label: "Overview" },
 { key: "vulns", label: "Vulnerabilities" },
 { key: "resources", label: "SBOM / Modules" },
 { key: "history", label: "History" },
 { key: "settings", label: "Settings" },
];

export default function ProjectDetail() {
 const { id } = useParams();
 const projectId = Number(id);
 const [tab, setTab] = useState("overview");
 const {
 project, modules, riskRows, latestRisk, vulnStats,
 loading, error, reload,
 } = useProjectData(projectId);

 if (loading) return <Spinner center size="lg" label="Loading project…" />;
 if (error) return <ErrorBanner error={error} />;
 if (!project) return null;

 return (
 <div>
 <div className={styles.header}>
 <div className={styles.titleRow}>
 <h1 className={styles.title}>{project.name}</h1>
 <StatusBadge status={project.status} />
 </div>
 {project.description && <p className={styles.subtitle}>{project.description}</p>}

 <div className={styles.tabs} role="tablist">
 {TABS.map((t) => (
 <button
 key={t.key}
 role="tab"
 aria-selected={tab === t.key}
 className={`${styles.tab} ${tab === t.key ? styles.tabActive : ""}`}
 onClick={() => setTab(t.key)}
 >
 {t.label}
 </button>
 ))}
 </div>
 </div>

 <div className={styles.tabContent}>
 {tab === "overview" && (
 <OverviewTab
 project={project}
 modules={modules}
 latestRisk={latestRisk}
 vulnStats={vulnStats}
 riskRows={riskRows}
 onDataChanged={reload}
 />
 )}
 {tab === "vulns" && <VulnsTab key={latestRisk?.id} project={project} />}
 {tab === "resources" && <ResourcesTab project={project} onChanged={reload} />}
 {tab === "history" && <HistoryTab project={project} />}
 {tab === "settings" && <SettingsTab project={project} onChanged={reload} />}
 </div>
 </div>
 );
}
