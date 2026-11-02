import { useState } from "react";

/**
 * Shared risk-distribution view used by both the ML (AI) page
 * and the GNN page. Renders:
 * - a donut chart of HIGH / MEDIUM / LOW counts
 * - a horizontal bar summary next to the donut
 * - an optional risk-level filter (set {@code showFilter}
 * false to hide it — the GNN page shows every row unfiltered
 * so all 489 nodes are visible at once)
 * - a sortable table of items
 *
 * The data shape is intentionally generic: any list of items
 * with a {@code predictedRisk} field (case-insensitive) can
 * be rendered. Extra columns can be supplied via
 * {@code extraColumns} so callers (ML, GNN) can add their own
 * per-item fields without forking the layout.
 */
export default function RiskDistributionView({
 title,
 totalLabel = "packages",
 items,
 extraColumns = [],
 emptyHint = "No items to display.",
 showFilter = false,
 showAll = false,
 pageSize = 100,
}) {
 const [riskFilter, setRiskFilter] = useState("ALL");
 const [sortKey, setSortKey] = useState(null);
 const [sortDir, setSortDir] = useState("desc");

 // Aggregate counts. Backend returns risk as lowercase
 // ("low" / "medium" / "high") and the Python GNN service
 // returns uppercase ("LOW" / "MEDIUM" / "HIGH"); normalise
 // both into the same buckets.
 const distribution = items.reduce((acc, it) => {
 const key = String(it.predictedRisk || "unknown").toUpperCase();
 acc[key] = (acc[key] || 0) + 1;
 return acc;
 }, {});
 const distributionRows = [
 { key: "HIGH", label: "High", color: "#dc2626", count: distribution.HIGH || 0 },
 { key: "MEDIUM", label: "Medium", color: "#f59e0b", count: distribution.MEDIUM || 0 },
 { key: "LOW", label: "Low", color: "#10b981", count: distribution.LOW || 0 },
 ].filter((r) => r.count > 0);

 // Default sort: predicted risk (HIGH first) then by whatever
 // the caller passed for the first numeric column.
 const defaultSortKey = sortKey || (extraColumns[0]?.key || "confidence");
 const filtered = showFilter
 ? items.filter((it) => riskFilter === "ALL" || String(it.predictedRisk).toUpperCase() === riskFilter)
 : items;
 const sorted = filtered
 .slice()
 .sort((a, b) => {
 const va = a?.[defaultSortKey] ?? 0;
 const vb = b?.[defaultSortKey] ?? 0;
 if (typeof va === "string" || typeof vb === "string") {
 const cmp = String(va).localeCompare(String(vb));
 return sortDir === "asc" ? cmp : -cmp;
 }
 return sortDir === "asc" ? va - vb : vb - va;
 })
 .slice(0, showAll ? filtered.length : pageSize);

 const toggleSort = (key) => {
 if (sortKey === key) {
 setSortDir((d) => (d === "asc" ? "desc" : "asc"));
 } else {
 setSortKey(key);
 setSortDir("desc");
 }
 };

 const baseColumns = [
 {
 key: "name",
 header: "Package",
 render: (r) => <b>{r.name || r.packageName || "—"}</b>,
 },
 {
 key: "predictedRisk",
 header: "Predicted risk",
 width: 130,
 render: (r) => {
 const v = String(r.predictedRisk || "—").toUpperCase();
 const tone =
 v === "HIGH"
 ? { bg: "#dc2626", label: "HIGH" }
 : v === "MEDIUM"
 ? { bg: "#f59e0b", label: "MEDIUM" }
 : v === "LOW"
 ? { bg: "#10b981", label: "LOW" }
 : { bg: "var(--text-muted)", label: v };
 return (
 <span style={{ background: tone.bg, color: "white", padding: "2px 10px", borderRadius: "9999px", fontSize: "var(--text-xs)", fontWeight: 700 }}>
 {tone.label}
 </span>
 );
 },
 },
 ];

 const allColumns = [...baseColumns, ...extraColumns];

 return (
 <div
 style={{
 background: "var(--bg-surface)", border: "1px solid var(--border-subtle)",
 borderRadius: "var(--radius-lg)", padding: "var(--space-5)", boxShadow: "var(--shadow-xs)",
 display: "grid", gap: "var(--space-4)",
 }}
 >
 <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center" }}>
 <h3 style={{ margin: 0, fontSize: "var(--text-md)" }}>
 {title} — {items.length} {totalLabel}
 </h3>
 </div>

 <div
 style={{
 display: "grid",
 gridTemplateColumns: "minmax(220px, 1fr) 2fr",
 gap: "var(--space-4)",
 alignItems: "stretch",
 }}
 >
 <RiskPie data={distributionRows} total={items.length} totalLabel={totalLabel} />
 <DistributionBars rows={distributionRows} total={items.length} />
 </div>

 <div style={{ display: "flex", gap: "var(--space-2)", alignItems: "center" }}>
 {showFilter && (
 <>
 <label style={{ fontSize: "var(--text-sm)", color: "var(--text-secondary)" }}>Filter</label>
 <select
 value={riskFilter}
 onChange={(e) => setRiskFilter(e.target.value)}
 style={{
 height: 32, padding: "0 10px", border: "1px solid var(--border-default)",
 borderRadius: "var(--radius-md)", fontSize: "var(--text-sm)", background: "var(--bg-surface)",
 }}
 >
 <option value="ALL">All ({items.length})</option>
 <option value="HIGH">High ({distribution.HIGH || 0})</option>
 <option value="MEDIUM">Medium ({distribution.MEDIUM || 0})</option>
 <option value="LOW">Low ({distribution.LOW || 0})</option>
 </select>
 </>
 )}
 <span style={{ fontSize: "var(--text-xs)", color: "var(--text-muted)" }}>
 Showing {sorted.length} of {items.length}
 </span>
 </div>

 <RiskTable
 rows={sorted}
 columns={allColumns}
 sortKey={defaultSortKey}
 sortDir={sortDir}
 toggleSort={toggleSort}
 emptyHint={emptyHint}
 />
 </div>
 );
}

function RiskTable({ rows, columns, sortKey, sortDir, toggleSort, emptyHint }) {
 const headerStyle = (key) => ({
 cursor: "pointer",
 userSelect: "none",
 color: sortKey === key ? "var(--color-primary)" : "var(--text-muted)",
 });
 const arrow = (key) => (sortKey === key ? (sortDir === "asc" ? " ▲" : " ▼") : "");
 return (
 <div
 style={{
 border: "1px solid var(--border-subtle)", borderRadius: "var(--radius-md)",
 overflow: "auto", maxHeight: 480, background: "var(--bg-surface)",
 }}
 >
 <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "var(--text-sm)" }}>
 <thead style={{ position: "sticky", top: 0, background: "var(--bg-subtle)" }}>
 <tr>
 {columns.map((col) => (
 <th
 key={col.key}
 style={{
 ...headerStyle(col.key),
 textAlign: col.align === "right" ? "right" : "left",
 padding: "8px 12px",
 fontSize: "var(--text-xs)",
 textTransform: "uppercase",
 letterSpacing: "0.06em",
 fontWeight: "var(--weight-semibold)",
 }}
 onClick={() => col.sortable !== false && toggleSort(col.key)}
 >
 {col.header}{arrow(col.key)}
 </th>
 ))}
 </tr>
 </thead>
 <tbody>
 {rows.length === 0 ? (
 <tr>
 <td colSpan={columns.length} style={{ padding: "var(--space-4)", textAlign: "center", color: "var(--text-muted)" }}>
 {emptyHint}
 </td>
 </tr>
 ) : (
 rows.map((r, idx) => (
 // Always include idx in the key — the dependency graph can
 // contain many nodes with the same package name (e.g. the
 // retrofit graph has two `internal-helpers` rows), and React
 // will warn + potentially mis-render if the key is only the
 // duplicate-prone name.
 <tr key={r.key || `${r.name || r.packageName || "row"}-${idx}`} style={{ borderTop: "1px solid var(--border-subtle)" }}>
 {columns.map((col) => (
 <td
 key={col.key}
 style={{
 padding: "8px 12px",
 textAlign: col.align === "right" ? "right" : "left",
 fontVariantNumeric: col.numeric ? "tabular-nums" : undefined,
 fontWeight: col.bold ? "var(--weight-semibold)" : undefined,
 }}
 >
 {col.render ? col.render(r) : r[col.key]}
 </td>
 ))}
 </tr>
 ))
 )}
 </tbody>
 </table>
 </div>
 );
}

function RiskPie({ data, total, totalLabel = "items" }) {
 if (data.length === 0) {
 return (
 <div
 style={{
 border: "1px solid var(--border-subtle)", borderRadius: "var(--radius-md)",
 padding: "var(--space-4)", display: "flex", alignItems: "center", justifyContent: "center",
 minHeight: 220, color: "var(--text-muted)",
 }}
 >
 No risk data
 </div>
 );
 }

 const size = 180;
 const radius = size / 2;
 const cx = radius;
 const cy = radius;
 const innerR = radius * 0.55;

 let cumulative = 0;
 const slices = data.map((d) => {
 const fraction = total > 0 ? d.count / total : 0;
 const startAngle = cumulative * Math.PI * 2;
 const endAngle = (cumulative + fraction) * Math.PI * 2;
 cumulative += fraction;
 const largeArc = fraction > 0.5 ? 1 : 0;
 const x1 = cx + radius * Math.sin(startAngle);
 const y1 = cy - radius * Math.cos(startAngle);
 const x2 = cx + radius * Math.sin(endAngle);
 const y2 = cy - radius * Math.cos(endAngle);
 const ix1 = cx + innerR * Math.sin(startAngle);
 const iy1 = cy - innerR * Math.cos(startAngle);
 const ix2 = cx + innerR * Math.sin(endAngle);
 const iy2 = cy - innerR * Math.cos(endAngle);
 const path =
 fraction >= 0.999
 ? `M ${cx - radius} ${cy} A ${radius} ${radius} 0 1 1 ${cx + radius} ${cy} A ${radius} ${radius} 0 1 1 ${cx - radius} ${cy} Z M ${cx - innerR} ${cy} A ${innerR} ${innerR} 0 1 0 ${cx + innerR} ${cy} A ${innerR} ${innerR} 0 1 0 ${cx - innerR} ${cy} Z`
 : `M ${x1} ${y1} A ${radius} ${radius} 0 ${largeArc} 1 ${x2} ${y2} L ${ix2} ${iy2} A ${innerR} ${innerR} 0 ${largeArc} 0 ${ix1} ${iy1} Z`;
 return { path, color: d.color, label: d.label, count: d.count, fraction };
 });

 return (
 <div
 style={{
 border: "1px solid var(--border-subtle)", borderRadius: "var(--radius-md)",
 padding: "var(--space-4)", display: "flex", flexDirection: "column", alignItems: "center",
 gap: "var(--space-2)",
 }}
 >
 <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`}>
 {slices.map((s, i) => (
 <path key={i} d={s.path} fill={s.color}>
 <title>{`${s.label}: ${s.count} (${(s.fraction * 100).toFixed(1)}%)`}</title>
 </path>
 ))}
 <text x={cx} y={cy - 4} textAnchor="middle" fontSize="22" fontWeight="700" fill="var(--text-primary)">
 {total}
 </text>
 <text x={cx} y={cy + 14} textAnchor="middle" fontSize="11" fill="var(--text-muted)">
 {totalLabel}
 </text>
 </svg>
 <div style={{ display: "flex", gap: "var(--space-3)", fontSize: "var(--text-xs)" }}>
 {slices.map((s) => (
 <span key={s.label} style={{ display: "inline-flex", alignItems: "center", gap: 4 }}>
 <span style={{ width: 10, height: 10, borderRadius: 2, background: s.color, display: "inline-block" }} />
 {s.label}
 </span>
 ))}
 </div>
 </div>
 );
}

function DistributionBars({ rows, total }) {
 if (rows.length === 0) {
 return (
 <div
 style={{
 border: "1px solid var(--border-subtle)", borderRadius: "var(--radius-md)",
 padding: "var(--space-4)", display: "flex", alignItems: "center", justifyContent: "center",
 minHeight: 220, color: "var(--text-muted)",
 }}
 >
 No risk data
 </div>
 );
 }
 return (
 <div
 style={{
 border: "1px solid var(--border-subtle)", borderRadius: "var(--radius-md)",
 padding: "var(--space-4)", display: "flex", flexDirection: "column", gap: "var(--space-3)",
 justifyContent: "center",
 }}
 >
 <div style={{ fontSize: "var(--text-sm)", color: "var(--text-secondary)", fontWeight: "var(--weight-semibold)" }}>
 Distribution
 </div>
 {rows.map((r) => {
 const pct = total > 0 ? (r.count / total) * 100 : 0;
 return (
 <div key={r.key} style={{ display: "grid", gap: 4 }}>
 <div style={{ display: "flex", justifyContent: "space-between", fontSize: "var(--text-xs)", color: "var(--text-secondary)" }}>
 <span>
 <span style={{ width: 8, height: 8, borderRadius: 2, background: r.color, display: "inline-block", marginRight: 6 }} />
 {r.label}
 </span>
 <span style={{ fontVariantNumeric: "tabular-nums" }}>
 {r.count} ({pct.toFixed(1)}%)
 </span>
 </div>
 <div style={{ height: 10, background: "var(--bg-subtle)", borderRadius: 9999, overflow: "hidden" }}>
 <div style={{ width: `${pct}%`, height: "100%", background: r.color, transition: "width var(--duration-fast) var(--ease)" }} />
 </div>
 </div>
 );
 })}
 </div>
 );
}
