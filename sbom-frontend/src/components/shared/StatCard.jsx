import styles from "./StatCard.module.css";

/**
 * Compact metric card. The value's color is controlled by the
 * {@code accent} prop ("primary" | "success" | "warning" | "danger" |
 * "neutral"), applied as a custom property so the value text picks
 * up the right semantic color.
 */
export default function StatCard({ label, value, subValue, accent = "neutral", delta }) {
 const accentColor = {
 primary: "var(--color-primary)",
 success: "var(--color-success)",
 warning: "var(--color-warning)",
 danger: "var(--color-danger)",
 neutral: "var(--text-primary)",
 }[accent] || "var(--text-primary)";

 return (
 <div className={styles.card}>
 <div className={styles.label}>{label}</div>
 <div className={styles.value} style={{ color: accentColor }}>{value}</div>
 {typeof subValue === "string" || typeof subValue === "number" ? (
 <div className={styles.subValue}>{subValue}</div>
 ) : (
 subValue
 )}
 {delta && <Delta value={delta} />}
 </div>
 );
}

function Delta({ value }) {
 // value is a number: positive = up, negative = down, 0 = flat
 const sign = value > 0 ? "up" : value < 0 ? "down" : "flat";
 const cls = sign === "up" ? styles.deltaUp : sign === "down" ? styles.deltaDown : styles.deltaFlat;
 const arrow = sign === "up" ? "↑" : sign === "down" ? "↓" : "→";
 return (
 <span className={`${styles.delta} ${cls}`}>
 {arrow} {Math.abs(value)}%
 </span>
 );
}
