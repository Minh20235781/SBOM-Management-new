import styles from "./StatusBadge.module.css";

/**
 * Pill-shaped status indicator. Use either a named {@code tone} or
 * a raw text label — the badge will auto-pick a tone based on a
 * small set of common status words.
 */
const TONE_FOR_STATUS = {
 ACTIVE: "success",
 ARCHIVED: "neutral",
 PENDING: "warning",
 SCANNING: "info",
 COMPLETED: "success",
 FAILED: "danger",
 NEW: "info",
 STILL_OPEN: "warning",
 FIXED: "success",
 REOPENED: "danger",
 CREATED: "primary",
 UPDATED: "neutral",
 DELETED: "danger",
 UPLOADED: "primary",
 SCAN_STARTED: "info",
 SCAN_COMPLETED: "success",
 SCAN_FAILED: "danger",
 FIXED_IN: "success",
};

export default function StatusBadge({ status, tone, withDot = true }) {
 const resolvedTone = tone || TONE_FOR_STATUS[String(status || "").toUpperCase()] || "neutral";
 return (
 <span className={`${styles.badge} ${styles[resolvedTone]}`}>
 {withDot && <span className={styles.dot} aria-hidden="true" />}
 {humanize(status)}
 </span>
 );
}

function humanize(s) {
 if (s == null) return "";
 return String(s).toLowerCase().replace(/_/g, " ");
}
