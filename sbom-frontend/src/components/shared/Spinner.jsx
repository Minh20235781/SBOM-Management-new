import styles from "./Spinner.module.css";

/**
 * Lightweight loading indicator. {@code size}: "sm" (default) |
 * "lg" | "xl". Set {@code center} to render it in a centered
 * column with an optional label.
 */
export default function Spinner({ size = "sm", center = false, label }) {
 const sizeClass = size === "lg" ? styles.lg : size === "xl" ? styles.xl : "";
 if (center) {
 return (
 <div className={styles.center} role="status" aria-live="polite">
 <span className={`${styles.spinner} ${sizeClass}`} aria-hidden="true" />
 {label && <span className={styles.label}>{label}</span>}
 </div>
 );
 return <span className={`${styles.spinner} ${sizeClass}`} role="status" aria-label="Loading" />;
 }
}
