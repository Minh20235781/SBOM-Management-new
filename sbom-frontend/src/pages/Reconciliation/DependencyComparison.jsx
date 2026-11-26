import { useMemo, useState } from "react";
import NodeDetailsDialog from "../../components/dependency-graph/NodeDetailsDialog";
import DependencyTree, { DependencyTreeLegend } from "./DependencyTree";
import styles from "./DependencyComparison.module.css";

const edgeLabels = {
  MATCHED: "Cạnh chung",
  STATIC_ONLY: "Chỉ có ở SBOM tĩnh",
  RUNTIME_ONLY: "Chỉ có ở runtime",
  UNVERIFIED: "Chưa đủ dữ liệu đối sánh",
};

function label(node) {
  return node.version ? `${node.name} @ ${node.version}` : node.name;
}

function NodeFields({ title, node, graph }) {
  if (!node) return null;
  return (
    <section>
      <h3>{title}</h3>
      <dl>
        <dt>Tên</dt><dd>{node.name}</dd>
        <dt>Phiên bản</dt><dd>{node.version || "Chưa xác định"}</dd>
        <dt>PURL</dt><dd>{node.purl || "Chưa có"}</dd>
        <dt>bom-ref</dt><dd>{node.ref || "Chưa có"}</dd>
        <dt>Gói phụ thuộc vào node này</dt>
        <dd>{node.parents.map((id) => label(graph.nodes.get(id))).join(", ") || "Chưa ghi nhận"}</dd>
        <dt>Phụ thuộc trực tiếp</dt>
        <dd>{node.children.map((id) => label(graph.nodes.get(id))).join(", ") || (node.outgoingKnown ? "Khai báo rỗng" : "Chưa có dữ liệu quan hệ")}</dd>
        {Object.entries(node.properties).filter(([name]) => name.startsWith("runtime:")).map(([name, value]) => (
          <div key={name}><dt>{name}</dt><dd>{String(value)}</dd></div>
        ))}
      </dl>
    </section>
  );
}

export default function DependencyComparison({ staticGraph, runtimeGraph, report, selection, onSelect }) {
  const [filter, setFilter] = useState("ALL");
  const { staticRows, runtimeRows } = useMemo(() => {
    const staticRows = new Map();
    const runtimeRows = new Map();
    for (const row of report.results) {
      if (row.staticNodeId) staticRows.set(row.staticNodeId, row);
      if (row.runtimeNodeId) runtimeRows.set(row.runtimeNodeId, row);
    }
    return { staticRows, runtimeRows };
  }, [report.results]);
  const { staticEdges, runtimeEdges, counts } = useMemo(() => {
    const staticEdges = new Map();
    const runtimeEdges = new Map();
    const counts = {};
    for (const { static: left, runtime: right, status } of report.edgeDiffs) {
      if (left) staticEdges.set(`${left.from}/${left.to}`, status);
      if (right) runtimeEdges.set(`${right.from}/${right.to}`, status);
      counts[status] = (counts[status] || 0) + 1;
    }
    return { staticEdges, runtimeEdges, counts };
  }, [report.edgeDiffs]);
  const staticNode = staticGraph.nodes.get(selection?.staticNodeId);
  const runtimeNode = runtimeGraph.nodes.get(selection?.runtimeNodeId);

  return (
    <section className={styles.comparison} aria-label="Đối sánh quan hệ phụ thuộc">
      <h2>Quan hệ phụ thuộc</h2>
      {(!staticGraph.coveredNodeCount || !runtimeGraph.coveredNodeCount) && (
        <p className={styles.coverage} role="status">Chưa đủ dữ liệu để đối sánh cạnh giữa hai nguồn. Cạnh chưa xác minh được vẽ bằng nét đứt.</p>
      )}
      <div className={styles.comparisonControls}>
        <DependencyTreeLegend />
        {report.edgeDiffs.length > 0 && (
          <label className={styles.edgeFilter}>Trạng thái cạnh <select value={filter} onChange={(event) => setFilter(event.target.value)}>
            <option value="ALL">Tất cả ({report.edgeDiffs.length})</option>
            {Object.entries(edgeLabels).filter(([status]) => counts[status]).map(([status, title]) => (
              <option key={status} value={status}>{title} ({counts[status]})</option>
            ))}
          </select></label>
        )}
      </div>
      <div className={styles.graphGrid}>
        <DependencyTree title="SBOM tĩnh" graph={staticGraph} rows={staticRows} edgeStatuses={staticEdges} edgeFilter={filter}
          onSelect={(id) => onSelect(staticRows.get(id) || { staticNodeId: id })} />
        <DependencyTree title="SBOM runtime" graph={runtimeGraph} rows={runtimeRows} edgeStatuses={runtimeEdges} edgeFilter={filter}
          onSelect={(id) => onSelect(runtimeRows.get(id) || { runtimeNodeId: id })} />
      </div>
      {(staticNode || runtimeNode) && (
        <NodeDetailsDialog title={staticNode?.name || runtimeNode.name} onClose={() => onSelect(null)}>
          {selection.status && <p><strong>{selection.status}</strong> · {selection.evidence}</p>}
          <div className={styles.grid}>
            <NodeFields title="SBOM tĩnh" node={staticNode} graph={staticGraph} />
            <NodeFields title="SBOM runtime" node={runtimeNode} graph={runtimeGraph} />
          </div>
        </NodeDetailsDialog>
      )}
    </section>
  );
}
