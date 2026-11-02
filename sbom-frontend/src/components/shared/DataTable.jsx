import styles from "./DataTable.module.css";

/**
 * Generic table with sticky-style header and hover state. The
 * {@code columns} prop describes the shape:
 *
 * <pre>
 * [
 * { key: "name", header: "Name", render: (row) => row.name },
 * { key: "score", header: "Score", align: "right",
 * render: (row) => row.score.toFixed(1) }
 * ]
 * </pre>
 *
 * If the row should be clickable (e.g. navigates somewhere), set
 * {@code onRowClick} to a handler — the cursor + hover styles will
 * engage automatically.
 */
export default function DataTable({
 columns,
 rows,
 rowKey = (r, i) => r.id ?? i,
 onRowClick,
 emptyTitle = "No data yet",
 emptyHint = "There are no rows to display for this view.",
 loading = false,
}) {
 // Defensive: if a caller passes a non-array (e.g. an error object
 // from a failed fetch), normalize to [] so we never crash inside
 // rows.map(). Use a local var — never reassign function props.
 const safeRows = Array.isArray(rows) ? rows : [];
 if (rows != null && !Array.isArray(rows)) {
 // eslint-disable-next-line no-console
 console.warn("DataTable: rows prop was not an array, normalized to [].", rows);
 }

 if (loading) {
 return (
 <div className={styles.wrapper}>
 <div className={styles.empty}>Loading…</div>
 </div>
 );
 }

 if (!safeRows || safeRows.length === 0) {
 return (
 <div className={styles.wrapper}>
 <div className={styles.empty}>
 <strong>{emptyTitle}</strong>
 {emptyHint}
 </div>
 </div>
 );
 }

 return (
 <div className={styles.wrapper}>
 <table className={styles.table}>
 <thead>
 <tr>
 {columns.map((col) => (
 <th
 key={col.key}
 className={
 col.align === "right"
 ? styles.alignRight
 : col.align === "center"
 ? styles.alignCenter
 : ""
 }
 style={col.width ? { width: col.width } : undefined}
 >
 {col.header}
 </th>
 ))}
 </tr>
 </thead>
 <tbody>
 {safeRows.map((row, idx) => {
 const clickable = Boolean(onRowClick);
 const handleClick = onRowClick ? () => onRowClick(row) : undefined;
 return (
 <tr
 key={rowKey(row, idx)}
 className={clickable ? styles.clickable : ""}
 onClick={handleClick}
 tabIndex={clickable ? 0 : -1}
 onKeyDown={
 clickable
 ? (e) => {
 if (e.key === "Enter" || e.key === " ") {
 e.preventDefault();
 handleClick();
 }
 }
 : undefined
 }
 >
 {columns.map((col) => (
 <td
 key={col.key}
 className={
 col.align === "right"
 ? styles.alignRight
 : col.align === "center"
 ? styles.alignCenter
 : ""
 }
 >
 {col.render ? col.render(row) : row[col.key]}
 </td>
 ))}
 </tr>
 );
 })}
 </tbody>
 </table>
 </div>
 );
}
