import { Link, useLocation } from "react-router-dom";
import { useMemo, useState } from "react";
import styles from "./Topbar.module.css";

/**
 * Top bar with breadcrumbs derived from the URL, a global search
 * input, and a user avatar placeholder. The search input is
 * presentational for now — wiring it up to a global command palette
 * or filter store is left for a later iteration.
 */
export default function Topbar() {
 const location = useLocation();
 const [query, setQuery] = useState("");

 const crumbs = useMemo(() => buildBreadcrumbs(location.pathname), [location.pathname]);

 return (
 <header className={styles.topbar}>
 <nav className={styles.breadcrumbs} aria-label="Breadcrumb">
 {crumbs.map((c, idx) => {
 const isLast = idx === crumbs.length - 1;
 return (
 <span key={c.path} style={{ display: "flex", alignItems: "center", gap: "8px" }}>
 {idx > 0 && <span className={styles.crumbSep}>/</span>}
 {isLast ? (
 <span className={styles.crumbCurrent}>{c.label}</span>
 ) : (
 <Link to={c.path} className={styles.crumb}>
 {c.label}
 </Link>
 )}
 </span>
 );
 })}
 </nav>

 <div className={styles.search}>
 <svg className={styles.searchIcon} viewBox="0 0 24 24" aria-hidden="true">
 <circle cx="11" cy="11" r="7" />
 <path d="M21 21l-4.3-4.3" />
 </svg>
 <input
 type="search"
 className={styles.searchInput}
 placeholder="Search projects, vulns, packages…"
 value={query}
 onChange={(e) => setQuery(e.target.value)}
 aria-label="Search"
 />
 </div>

 <div className={styles.right}>
 <button className={styles.iconBtn} aria-label="Notifications" type="button">
 <svg viewBox="0 0 24 24" aria-hidden="true">
 <path d="M6 8a6 6 0 1 1 12 0c0 5 2 6 2 6H4s2-1 2-6" />
 <path d="M10 19a2 2 0 0 0 4 0" />
 </svg>
 </button>
 <div className={styles.avatar} title="Current user">AD</div>
 </div>
 </header>
 );
}

/** Map URL segments to human labels. Add more mappings as routes grow. */
const LABEL_OVERRIDES = {
 dashboard: "Dashboard",
 projects: "Projects",
 scan: "Scan",
 "sbom-table": "SBOM Table",
 graph: "Graph",
 insights: "Insights",
 ai: "AI",
 gnn: "GNN",
 audit: "Audit Timeline",
 vulns: "Vulnerabilities",
};

function buildBreadcrumbs(pathname) {
 const segments = pathname.split("/").filter(Boolean);
 if (segments.length === 0) {
 return [{ label: "Dashboard", path: "/dashboard" }];
 }
 const crumbs = [];
 let acc = "";
 segments.forEach((seg, idx) => {
 acc += `/${seg}`;
 const isLast = idx === segments.length - 1;
 // If the segment is a numeric id (e.g. /projects/42), keep it short.
 const label = /^\d+$/.test(seg) ? `#${seg}` : LABEL_OVERRIDES[seg] || humanize(seg);
 crumbs.push({ label, path: isLast ? null : acc });
 });
 return crumbs;
}

function humanize(seg) {
 return seg.replace(/-/g, " ").replace(/\b\w/g, (c) => c.toUpperCase());
}
