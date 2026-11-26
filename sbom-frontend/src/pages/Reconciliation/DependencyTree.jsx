import { useId, useLayoutEffect, useMemo, useRef, useState } from "react";
import { hierarchy, linkHorizontal, tree } from "d3";
import styles from "./DependencyComparison.module.css";

const branchSize = 5;
const inventoryPageSize = 36;
const card = { width: 192, height: 58, row: 74, column: 232, padding: 12 };

const nodeStatusLabels = {
  MATCHED: "Khớp",
  STATIC_ONLY: "Chỉ thấy ở SBOM tĩnh",
  RUNTIME_ONLY: "Chỉ thấy ở runtime",
  UNRESOLVED: "Cần xác minh",
};

export function DependencyTreeLegend() {
  return (
    <ul className={styles.legend} aria-label="Trạng thái thành phần">
      {Object.entries(nodeStatusLabels).map(([status, label]) => <li key={status} data-status={status}>{label}</li>)}
    </ul>
  );
}

function byName(a, b) {
  return a.name.localeCompare(b.name) || (a.version || "").localeCompare(b.version || "") || a.id.localeCompare(b.id);
}

function displayName(node) {
  return node.root ? node.name.split(/[\\/]/).filter(Boolean).at(-1) || node.name : node.name;
}

function matchesQuery(node, query) {
  return `${node.name} ${node.version || ""} ${node.purl || ""}`.toLowerCase().includes(query);
}

function makeLayout(from, childrenByNode, limits, edgeStatuses) {
  function branch(id, key, ancestors) {
    const cycle = ancestors.includes(id);
    const available = cycle ? [] : childrenByNode.get(id) || [];
    const limit = limits.get(key) ?? (ancestors.length ? 0 : branchSize);
    const nextAncestors = [...ancestors, id];
    const children = available.slice(0, limit).map((child) => branch(child, `${key}/${child}`, nextAncestors));
    return { id, key, cycle, count: available.length, limit, children };
  }

  const layout = tree().nodeSize([card.row, card.column])(hierarchy(branch(from, from, [])));
  const entries = layout.descendants();
  const minY = Math.min(...entries.map((entry) => entry.x));
  const maxY = Math.max(...entries.map((entry) => entry.x));
  const position = (entry) => [entry.y + card.padding, entry.x - minY + card.padding];
  const path = linkHorizontal();

  return {
    width: layout.height * card.column + card.width + 2 * card.padding,
    height: maxY - minY + card.height + 2 * card.padding,
    nodes: entries.map((entry) => {
      const [left, top] = position(entry);
      return { ...entry.data, left, top };
    }),
    links: layout.links().map(({ source, target }) => {
      const [left, top] = position(source);
      const [right, bottom] = position(target);
      return {
        key: target.data.key,
        status: edgeStatuses.get(`${source.data.id}/${target.data.id}`),
        path: path({ source: [left + card.width, top + card.height / 2], target: [right - 6, bottom + card.height / 2] }),
      };
    }),
  };
}

function NodeCard({ node, status, cycle, onSelect, children }) {
  const name = displayName(node);
  const nodeStatus = nodeStatusLabels[status] || (node.root ? "Ứng dụng" : "");
  return (
    <div className={styles.treeCard} data-status={status} data-root={node.root || undefined}>
      <button className={styles.nodeButton} type="button" onClick={() => onSelect(node.id)}
        title={node.version ? `${node.name} @ ${node.version}` : node.name}>
        <strong>{name}</strong>
        <span>{[node.version, cycle ? "Vòng lặp" : nodeStatus].filter(Boolean).join(" · ")}</span>
      </button>
      {children && <div className={styles.branchActions}>{children}</div>}
    </div>
  );
}

function BranchDiagram({ rootId, graph, rows, childrenByNode, edgeStatuses, onSelect }) {
  const [limits, setLimits] = useState(() => new Map());
  const [zoom, setZoom] = useState(100);
  const arrowId = useId();
  const viewport = useRef(null);
  const branchAnchor = useRef(null);
  const layout = useMemo(() => makeLayout(rootId, childrenByNode, limits, edgeStatuses), [rootId, childrenByNode, limits, edgeStatuses]);
  const scale = zoom / 100;

  useLayoutEffect(() => {
    if (!branchAnchor.current) return;
    const { key, top, scrollTop } = branchAnchor.current;
    const movedNode = layout.nodes.find((node) => node.key === key);
    if (movedNode) viewport.current.scrollTop = scrollTop + (movedNode.top - top) * scale;
    branchAnchor.current = null;
  }, [layout, scale]);

  const setLimit = (key, top, limit) => {
    branchAnchor.current = { key, top, scrollTop: viewport.current.scrollTop };
    setLimits((previous) => new Map(previous).set(key, limit));
  };
  return (
    <>
      <div className={styles.zoomControls} role="group" aria-label="Thu phóng sơ đồ">
        <button type="button" aria-label="Thu nhỏ" disabled={zoom <= 60} onClick={() => setZoom(zoom - 20)}>−</button>
        <button type="button" aria-label="Đặt lại thu phóng" onClick={() => setZoom(100)}>{zoom}%</button>
        <button type="button" aria-label="Phóng to" disabled={zoom >= 140} onClick={() => setZoom(zoom + 20)}>+</button>
      </div>
      <div ref={viewport} className={styles.viewport} role="region" aria-label="Sơ đồ phụ thuộc" tabIndex={0}>
        <div className={styles.diagramBounds} style={{ width: layout.width * scale, height: layout.height * scale }}>
          <div className={styles.diagram} style={{ width: layout.width, height: layout.height, transform: `scale(${scale})` }}>
            <svg aria-hidden="true" focusable="false" width={layout.width} height={layout.height} className={styles.links}>
              <defs>
                <marker id={arrowId} viewBox="0 0 8 8" refX="6" refY="4" markerWidth="5" markerHeight="5" orient="auto-start-reverse">
                  <path d="M0 0 L8 4 L0 8 Z" fill="context-stroke" />
                </marker>
              </defs>
              {layout.links.map((link) => (
                <path key={link.key} d={link.path} data-status={link.status} markerEnd={`url(#${arrowId})`} />
              ))}
            </svg>
            {layout.nodes.map(({ id, key, left, top, count, limit, cycle }) => {
              const node = graph.nodes.get(id);
              const more = count - limit;
              return (
                <div className={styles.positionedNode} key={key} style={{ left, top, width: card.width, height: card.height }}>
                  <NodeCard node={node} status={rows.get(id)?.status} cycle={cycle} onSelect={onSelect}>
                    {count > 0 && (
                      <button type="button" aria-expanded={limit > 0} title={`${count} phụ thuộc trực tiếp`}
                        aria-label={`${limit ? "Thu gọn" : "Mở"} nhánh ${node.name}`}
                        onClick={() => setLimit(key, top, limit ? 0 : branchSize)}>{limit ? "−" : "+"}</button>
                    )}
                    {limit > 0 && more > 0 && (
                      <button type="button" aria-label={`Hiện thêm phụ thuộc của ${node.name}`} title={`Còn ${more} phụ thuộc`}
                        onClick={() => setLimit(key, top, limit + branchSize)}>+{more}</button>
                    )}
                  </NodeCard>
                </div>
              );
            })}
          </div>
        </div>
      </div>
    </>
  );
}

export default function DependencyTree({ title, graph, rows, onSelect, edgeStatuses, edgeFilter }) {
  const [query, setQuery] = useState("");
  const [focusId, setFocusId] = useState("");
  const [inventoryLimit, setInventoryLimit] = useState(inventoryPageSize);
  const nodes = useMemo(() => [...graph.nodes.values()].sort(byName), [graph]);
  const isTree = graph.edges.size > 0;
  const childrenByNode = useMemo(() => {
    const result = new Map();
    for (const node of nodes) {
      const children = node.children.filter((child) => edgeFilter === "ALL" || edgeStatuses.get(`${node.id}/${child}`) === edgeFilter);
      if (children.length) result.set(node.id, children.sort((a, b) => byName(graph.nodes.get(a), graph.nodes.get(b))));
    }
    return result;
  }, [nodes, graph, edgeFilter, edgeStatuses]);
  const normalizedQuery = query.trim().toLowerCase();
  const candidates = nodes.filter((node) => (!isTree || edgeFilter === "ALL" || childrenByNode.has(node.id)) && matchesQuery(node, normalizedQuery));
  const preferredRoot = candidates.find((node) => node.root && childrenByNode.has(node.id))
    || candidates.reduce((best, node) => (childrenByNode.get(node.id)?.length || 0) > (childrenByNode.get(best?.id)?.length || 0) ? node : best, candidates[0]);
  const focused = candidates.find(({ id }) => id === focusId) || preferredRoot;

  return (
    <section className={styles.panel} aria-label={title}>
      <h3>{title}</h3>
      <p>{graph.nodes.size} node · {graph.edges.size} cạnh · {graph.coveredNodeCount} node có khai báo phụ thuộc</p>
      {graph.warnings.map((warning) => <p key={warning}>{warning}</p>)}
      {graph.nodes.size > 0 && (
        <div className={styles.graphControls}>
          <label>Tìm gói <input type="search" value={query} placeholder="Tên, phiên bản hoặc PURL"
            onChange={(event) => { setQuery(event.target.value); setFocusId(""); setInventoryLimit(inventoryPageSize); }} /></label>
          {isTree && candidates.length > 0 && (
            <label>Nút bắt đầu <select value={focused.id} onChange={(event) => setFocusId(event.target.value)}>
              {candidates.map((node) => <option key={node.id} value={node.id} title={node.ref || node.purl || node.name}>
                {displayName(node)}{node.version ? ` @ ${node.version}` : ""}{childrenByNode.has(node.id) ? ` · ${childrenByNode.get(node.id).length} nhánh` : ""}
              </option>)}
            </select></label>
          )}
        </div>
      )}
      {isTree && focused && (
        <BranchDiagram key={`${edgeFilter}/${focused.id}`} rootId={focused.id} graph={graph} rows={rows} childrenByNode={childrenByNode}
          edgeStatuses={edgeStatuses} onSelect={onSelect} />
      )}
      {!isTree && candidates.length > 0 && (
        <div className={styles.inventory}>
          {candidates.slice(0, inventoryLimit).map((node) => <NodeCard key={node.id} node={node} status={rows.get(node.id)?.status} onSelect={onSelect} />)}
          {candidates.length > inventoryLimit && <button type="button" onClick={() => setInventoryLimit(inventoryLimit + inventoryPageSize)}>
            Hiện thêm ({candidates.length - inventoryLimit})
          </button>}
        </div>
      )}
      {candidates.length === 0 && (
        <div className={styles.graphEmpty} role="status">
          {!graph.nodes.size ? "Nguồn này chưa có thành phần." : query.trim() ? "Không tìm thấy gói phù hợp." : "Không có cạnh phù hợp trong nguồn này."}
        </div>
      )}
    </section>
  );
}
