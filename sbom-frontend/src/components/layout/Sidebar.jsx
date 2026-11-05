import { NavLink } from "react-router-dom";
import styles from "./Sidebar.module.css";

/**
 * Persistent left navigation. Items are grouped under three
 * sections (Workspace / Security / Audit) so the 11 routes don't
 * all run together.
 *
 * Icons are inline SVG (no third-party icon library) so the bundle
 * stays small and colors follow currentColor.
 */
const NAV_SECTIONS = [
	{
		title: "Workspace",
		items: [
			{ to: "/dashboard", label: "Dashboard", icon: "dashboard" },
			{ to: "/projects", label: "Projects", icon: "folder" },
			{ to: "/scan", label: "Scan", icon: "play" },
			{ to: "/sbom-table", label: "SBOM Table", icon: "table" },
			{ to: "/insights", label: "Insights", icon: "insights" },
			{ to: "/graph", label: "Graph", icon: "graph" },
		],
	},
	{
		title: "Security",
		items: [
			{ to: "/vulns", label: "Vulnerabilities", icon: "alert" },
			{ to: "/ai", label: "AI", icon: "ai" },
			{ to: "/gnn", label: "GNN", icon: "gnn" },
			{ to: "/trust-score", label: "Trust Score", icon: "shield" },
			{ to: "/provenance", label: "SBOM Provenance", icon: "shield" },
			{ to: "/reconciliation", label: "Runtime Reconcile", icon: "shield" },
		],
	},
	{
		title: "Audit",
		items: [
			{ to: "/audit", label: "Audit Timeline", icon: "history" },
		],
	},
];

function Icon({ name }) {
	const common = {
		className: styles.icon,
		viewBox: "0 0 24 24",
		xmlns: "http://www.w3.org/2000/svg",
		"aria-hidden": true,
	};
	switch (name) {
		case "dashboard":
			return (
				<svg {...common}>
					<rect x="3" y="3" width="7" height="9" rx="1.5" />
					<rect x="14" y="3" width="7" height="5" rx="1.5" />
					<rect x="14" y="12" width="7" height="9" rx="1.5" />
					<rect x="3" y="16" width="7" height="5" rx="1.5" />
				</svg>
			);
		case "folder":
			return (
				<svg {...common}>
					<path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z" />
				</svg>
			);
		case "play":
			return (
				<svg {...common}>
					<path d="M7 5l12 7-12 7z" />
				</svg>
			);
		case "table":
			return (
				<svg {...common}>
					<rect x="3" y="3" width="18" height="18" rx="2" />
					<path d="M3 9h18M3 15h18M9 3v18M15 3v18" />
				</svg>
			);
		case "graph":
			return (
				<svg {...common}>
					<circle cx="6" cy="6" r="2" />
					<circle cx="18" cy="6" r="2" />
					<circle cx="12" cy="18" r="2" />
					<path d="M8 6h8M7 8l4 8M17 8l-4 8" />
				</svg>
			);
		case "insights":
			return (
				<svg {...common}>
					<path d="M3 17l4-4 4 4 7-7" />
					<path d="M14 6h7v7" />
				</svg>
			);
		case "ai":
			return (
				<svg {...common}>
					<path d="M12 3v3M12 18v3M3 12h3M18 12h3M5.6 5.6l2.1 2.1M16.3 16.3l2.1 2.1M5.6 18.4l2.1-2.1M16.3 7.7l2.1-2.1" />
					<circle cx="12" cy="12" r="3" />
				</svg>
			);
		case "shield":
			return (
				<svg {...common}>
					<path d="M12 3l8 3v6c0 5-3.5 8.5-8 9-4.5-.5-8-4-8-9V6z" />
					<path d="M9 12l2 2 4-4" />
				</svg>
			);
		case "gnn":
			return (
				<svg {...common}>
					<circle cx="12" cy="12" r="3" />
					<circle cx="4" cy="6" r="2" />
					<circle cx="20" cy="6" r="2" />
					<circle cx="4" cy="18" r="2" />
					<circle cx="20" cy="18" r="2" />
					<path d="M6 7l5 4M18 7l-5 4M6 17l5-4M18 17l-5-4" />
				</svg>
			);
		case "alert":
			return (
				<svg {...common}>
					<path d="M12 3l10 18H2z" />
					<path d="M12 10v4M12 17h.01" />
				</svg>
			);
		case "history":
			return (
				<svg {...common}>
					<path d="M3 12a9 9 0 1 0 3-6.7" />
					<path d="M3 4v5h5" />
					<path d="M12 7v5l3 2" />
				</svg>
			);
		default:
			return null;
	}
}

export default function Sidebar() {
	return (
		<aside className={styles.sidebar}>
			<div className={styles.brand}>
				<div className={styles.brandMark} aria-hidden="true">SB</div>
				<div className={styles.brandName}>SBOM Management</div>
			</div>

			{NAV_SECTIONS.map((group) => (
				<nav key={group.title} className={styles.nav}>
					<div className={styles.sectionTitle}>{group.title}</div>
					{group.items.map((item) => (
						<NavLink
							key={item.to}
							to={item.to}
							end={item.to === "/dashboard"}
							className={({ isActive }) =>
								`${styles.link} ${isActive ? styles.linkActive : ""}`
							}
						>
							<Icon name={item.icon} />
							<span>{item.label}</span>
						</NavLink>
					))}
				</nav>
			))}

			<div className={styles.footer}>v0.2 · SBOM Risk Console</div>
		</aside>
	);
}
