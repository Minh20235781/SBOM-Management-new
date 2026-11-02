import styles from "./EmptyState.module.css";

/**
 * Reusable empty-state block. Use it inside cards or as a full
 * page section when there is no data. {@code icon} accepts a name
 * to pick from a small built-in library; supply your own SVG
 * via {@code children} for anything else.
 */
export default function EmptyState({ title, hint, actions, icon = "inbox", children }) {
 return (
 <div className={styles.empty}>
 <div className={styles.icon} aria-hidden="true">
 {children ?? <DefaultIcon name={icon} />}
 </div>
 {title && <h3 className={styles.title}>{title}</h3>}
 {hint && <p className={styles.hint}>{hint}</p>}
 {actions && <div className={styles.actions}>{actions}</div>}
 </div>
 );
}

function DefaultIcon({ name }) {
 const props = {
 viewBox: "0 0 24 24",
 xmlns: "http://www.w3.org/2000/svg",
 "aria-hidden": true,
 };
 switch (name) {
 case "inbox":
 return (
 <svg {...props}>
 <path d="M3 13l3-8h12l3 8" />
 <path d="M3 13v5a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-5" />
 <path d="M3 13h5l1 2h6l1-2h5" />
 </svg>
 );
 case "search":
 return (
 <svg {...props}>
 <circle cx="11" cy="11" r="7" />
 <path d="M21 21l-4.3-4.3" />
 </svg>
 );
 case "shield":
 return (
 <svg {...props}>
 <path d="M12 3l8 3v6c0 5-3.5 8.5-8 9-4.5-.5-8-4-8-9V6z" />
 </svg>
 );
 case "history":
 return (
 <svg {...props}>
 <path d="M3 12a9 9 0 1 0 3-6.7" />
 <path d="M3 4v5h5" />
 <path d="M12 7v5l3 2" />
 </svg>
 );
 default:
 return null;
 }
}
