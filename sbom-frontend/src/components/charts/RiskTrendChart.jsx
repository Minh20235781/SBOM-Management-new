import {
 LineChart,
 Line,
 XAxis,
 YAxis,
 CartesianGrid,
 Tooltip,
 Legend,
 ResponsiveContainer,
} from "recharts";

/**
 * Multi-line risk trend chart. X axis is the scan's {@code assessedAt}
 * timestamp; the chart shows score, total vulns, and critical count
 * in three separate lines so the operator can see how the project
 * health changed over time.
 *
 * The data is reversed to chronological order before rendering because
 * the backend returns newest first.
 */
export default function RiskTrendChart({ rows, height = 280 }) {
 if (!rows || rows.length === 0) {
 return (
 <div style={{ height, display: "flex", alignItems: "center", justifyContent: "center", color: "#6b7280" }}>
 No scans yet.
 </div>
 );
 }

 const data = [...rows]
 .sort((a, b) => new Date(a.assessedAt) - new Date(b.assessedAt))
 .map((r) => ({
 when: new Date(r.assessedAt).toLocaleString(undefined, {
 month: "short",
 day: "2-digit",
 hour: "2-digit",
 minute: "2-digit",
 }),
 score: r.score,
 totalVulns: r.totalVulnerabilities,
 critical: r.criticalCount,
 grade: r.grade,
 }));

 return (
 <ResponsiveContainer width="100%" height={height}>
 <LineChart data={data} margin={{ top: 8, right: 16, bottom: 8, left: 0 }}>
 <CartesianGrid strokeDasharray="3 3" stroke="#e5e7eb" />
 <XAxis dataKey="when" stroke="#6b7280" fontSize={11} />
 <YAxis yAxisId="left" stroke="#4f8cff" fontSize={11} domain={[0, 100]} />
 <YAxis yAxisId="right" orientation="right" stroke="#ea580c" fontSize={11} />
 <Tooltip
 contentStyle={{ fontSize: "0.85rem" }}
 formatter={(value, name) => {
 if (name === "score") return [Number(value).toFixed(1), "Score"];
 return [value, name];
 }}
 />
 <Legend wrapperStyle={{ fontSize: "0.85rem" }} />
 <Line yAxisId="left" type="monotone" dataKey="score" stroke="#4f8cff" name="score" dot={{ r: 3 }} />
 <Line yAxisId="right" type="monotone" dataKey="totalVulns" stroke="#9ca3af" name="total vulns" dot={{ r: 3 }} />
 <Line yAxisId="right" type="monotone" dataKey="critical" stroke="#dc2626" name="critical" dot={{ r: 3 }} />
 </LineChart>
 </ResponsiveContainer>
 );
}
