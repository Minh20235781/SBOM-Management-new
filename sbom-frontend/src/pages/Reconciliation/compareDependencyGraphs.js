const statuses = ["MATCHED", "STATIC_ONLY", "RUNTIME_ONLY", "UNRESOLVED"];
const list = (value) => Array.isArray(value) ? value : [];
const text = (value) => typeof value === "string" ? value.trim() : "";

function knownVersion(value) {
  const version = typeof value === "string" ? value.trim() : "";
  return version && !/^(unknown|version_unknown|n\/a)$/i.test(version) ? version : null;
}

function decode(value) {
  try { return decodeURIComponent(value); } catch { return value; }
}

function identify(component) {
  const purl = text(component.purl) || text(list(component.externalRefs).find(
    (ref) => text(ref?.referenceCategory).toLowerCase() === "package-manager" && text(ref?.referenceType).toLowerCase() === "purl",
  )?.referenceLocator);
  const parsed = /^pkg:([^/]+)\/([^?#]+)(?:\?([^#]*))?(?:#(.*))?$/i.exec(purl);
  if (!parsed) {
    const name = text(component.name);
    const group = text(component.group) || text(component.namespace);
    const ecosystem = text(component.ecosystem).toLowerCase();
    const qualifiedName = group ? `${group}/${name}` : name;
    return {
      purl,
      packageKey: ecosystem && name ? `${ecosystem}:${ecosystem === "npm" ? qualifiedName.toLowerCase() : qualifiedName}` : null,
      version: knownVersion(component.version ?? component.versionInfo),
      variant: "",
    };
  }

  const [, type, path, query = "", subpath = ""] = parsed;
  const separator = path.lastIndexOf("@");
  const ecosystem = type.toLowerCase();
  const coordinate = decode(separator > 0 ? path.slice(0, separator) : path);
  const qualifiers = [...new URLSearchParams(query.replaceAll("+", "%2B"))].sort(([a, av], [b, bv]) => a.localeCompare(b) || av.localeCompare(bv));
  const purlVersion = knownVersion(separator > 0 ? decode(path.slice(separator + 1)) : null);
  const declaredVersion = knownVersion(component.version ?? component.versionInfo);
  const versionConflict = purlVersion && declaredVersion && purlVersion !== declaredVersion;
  return {
    purl,
    packageKey: `${ecosystem}:${ecosystem === "npm" ? coordinate.toLowerCase() : coordinate}`,
    version: versionConflict ? null : purlVersion ?? declaredVersion,
    variant: qualifiers.length || subpath ? JSON.stringify([qualifiers, decode(subpath)]) : "",
  };
}

export function readDependencyGraph(document) {
  if (!document || (!Array.isArray(document.components) && !Array.isArray(document.packages))) {
    throw new Error("SBOM cần có danh sách thành phần hợp lệ.");
  }
  const nodes = new Map();
  const refs = new Map();
  const duplicateRefs = new Set();
  const warnings = [];
  function add(component, root = false) {
    const name = text(component?.name);
    if (!name) return;
    const ref = text(component["bom-ref"]) || text(component.SPDXID);
    const id = `node-${nodes.size}`;
    const properties = Object.fromEntries(list(component.properties).filter((property) => text(property?.name)).map(({ name, value }) => [name, value]));
    nodes.set(id, {
      id, ref, root, name, ...identify(component), properties,
      outgoingKnown: false, children: [], parents: [],
    });
    if (!ref) return;
    if (refs.has(ref)) duplicateRefs.add(ref);
    else refs.set(ref, id);
  }

  add(document.metadata?.component, true);
  const pending = [...(Array.isArray(document.components) ? document.components : document.packages)].reverse();
  while (pending.length) {
    const component = pending.pop();
    add(component);
    for (const child of [...list(component?.components)].reverse()) pending.push(child);
  }
  for (const ref of duplicateRefs) refs.delete(ref);
  if (duplicateRefs.size) warnings.push(`${duplicateRefs.size} bom-ref trùng lặp trong SBOM.`);

  const edges = new Map();
  let unresolvedRefs = 0;
  const incomplete = new Set();
  for (const dependency of list(document.dependencies)) {
    const from = nodes.get(refs.get(dependency?.ref));
    if (!from) {
      unresolvedRefs++;
      continue;
    }
    if (!Array.isArray(dependency.dependsOn)) {
      incomplete.add(from.id);
      continue;
    }
    from.outgoingKnown = true;
    for (const ref of dependency.dependsOn) {
      const to = nodes.get(refs.get(ref));
      if (!to) {
        unresolvedRefs++;
        incomplete.add(from.id);
        continue;
      }
      const key = edgeKey(from.id, to.id);
      if (edges.has(key)) continue;
      edges.set(key, { from: from.id, to: to.id });
      from.children.push(to.id);
      to.parents.push(from.id);
    }
  }
  for (const composition of list(document.compositions)) {
    if (composition?.aggregate === "complete") continue;
    for (const ref of list(composition?.dependencies)) incomplete.add(refs.get(ref));
  }
  for (const id of incomplete) {
    const node = nodes.get(id);
    if (node) node.outgoingKnown = false;
  }
  if (unresolvedRefs) warnings.push(`${unresolvedRefs} tham chiếu cạnh chưa xác định được node.`);

  const roots = [];
  const visited = new Set();
  const ordered = [...nodes.values()].sort((a, b) => a.name.localeCompare(b.name) || (a.version || "").localeCompare(b.version || ""));
  const seeds = [
    ...ordered.filter((node) => node.root),
    ...ordered.filter((node) => !node.parents.length),
    ...ordered,
  ];
  for (const seed of seeds) {
    if (visited.has(seed.id)) continue;
    roots.push(seed.id);
    const queue = [seed.id];
    while (queue.length) {
      const id = queue.pop();
      if (visited.has(id)) continue;
      visited.add(id);
      for (const child of nodes.get(id).children) queue.push(child);
    }
  }

  return { nodes, edges, roots, warnings, coveredNodeCount: ordered.filter((node) => node.outgoingKnown).length };
}

function edgeKey(from, to) {
  return `${from}/${to}`;
}

function groupBy(nodes, keyOf) {
  const groups = new Map();
  for (const node of nodes) {
    const key = keyOf(node);
    if (!key) continue;
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(node);
  }
  return groups;
}

function exactKey(node) {
  return node.packageKey && node.version ? JSON.stringify([node.packageKey, node.version, node.variant]) : null;
}

export function compareDependencyGraphs(staticGraph, runtimeGraph) {
  const staticNodes = [...staticGraph.nodes.values()].filter(({ root }) => !root);
  const runtimeNodes = [...runtimeGraph.nodes.values()].filter(({ root }) => !root);
  const staticToRuntime = new Map();
  const runtimeToStatic = new Map();
  const results = [];
  const usedStatic = new Set();
  const usedRuntime = new Set();

  function result(left, right, status, versionStatus, explanation, mapEdge = true) {
    if (left) usedStatic.add(left.id);
    if (right) usedRuntime.add(right.id);
    if (status === "MATCHED" && mapEdge) {
      staticToRuntime.set(left.id, right.id);
      runtimeToStatic.set(right.id, left.id);
    }
    const evidence = right?.properties["runtime:evidence"];
    results.push({
      status, versionStatus,
      component: left?.name || right.name,
      staticVersion: left?.version ?? null,
      runtimeVersion: right?.version ?? null,
      runtimeResource: right?.properties["runtime:scriptUrl"] || right?.purl || right?.name || null,
      staticNodeId: left?.id ?? null,
      runtimeNodeId: right?.id ?? null,
      evidence: evidence ? `${explanation} ${evidence}` : explanation,
    });
  }

  const exactRuntime = groupBy(runtimeNodes, exactKey);
  for (const [key, left] of groupBy(staticNodes, exactKey)) {
    const right = exactRuntime.get(key);
    if (right?.length === 1) {
      for (const node of left) result(node, right[0], "MATCHED", "VERSION_MATCH", left.length === 1
        ? "Khớp định danh gói và phiên bản." : "Khớp gói và phiên bản ở nhiều vị trí tĩnh. Chưa xác định vị trí nạp.", left.length === 1);
    }
  }

  const baseKey = (node) => node.packageKey;
  const allStaticPackages = new Set(staticNodes.map(node => node.packageKey));
  const allRuntimePackages = new Set(runtimeNodes.map(node => node.packageKey));
  const staticGroups = groupBy(staticNodes.filter(({ id }) => !usedStatic.has(id)), baseKey);
  const runtimeGroups = groupBy(runtimeNodes.filter(({ id }) => !usedRuntime.has(id)), baseKey);
  const staticNames = groupBy(staticNodes, ({ name }) => name.toLowerCase());
  const runtimeNames = groupBy(runtimeNodes, ({ name }) => name.toLowerCase());
  for (const [key, left] of staticGroups) {
    const right = runtimeGroups.get(key);
    if (left.length !== 1 || right?.length !== 1) continue;
    const [a] = left;
    const [b] = right;
    const drift = a.version && b.version && a.version !== b.version && a.variant === b.variant;
    result(a, b, "UNRESOLVED", drift ? "VERSION_MISMATCH" : "VERSION_UNKNOWN",
      drift ? "Cùng định danh gói, khác phiên bản." : "Cần xác minh phiên bản hoặc biến thể của gói.");
  }

  for (const node of staticNodes) {
    if (usedStatic.has(node.id)) continue;
    const ambiguous = allRuntimePackages.has(node.packageKey) || !node.packageKey
      || runtimeNames.get(node.name.toLowerCase())?.some((candidate) => !candidate.packageKey);
    result(node, null, ambiguous ? "UNRESOLVED" : "STATIC_ONLY", "VERSION_UNKNOWN",
      ambiguous ? "Định danh còn thiếu hoặc có nhiều ứng viên runtime." : "Chưa thấy gói trong phiên runtime này.");
  }
  for (const node of runtimeNodes) {
    if (usedRuntime.has(node.id)) continue;
    const ambiguous = allStaticPackages.has(node.packageKey) || !node.packageKey
      || ["BUNDLE_CODE_FINGERPRINT", "SOURCE_MAP_NODE_MODULES"].includes(node.properties["runtime:identificationMethod"])
      || staticNames.get(node.name.toLowerCase())?.some((candidate) => !candidate.packageKey);
    result(null, node, ambiguous ? "UNRESOLVED" : "RUNTIME_ONLY", "VERSION_UNKNOWN",
      ambiguous ? "Định danh còn thiếu hoặc có nhiều ứng viên tĩnh." : "Đã quan sát gói trong runtime; SBOM tĩnh chưa có định danh tương ứng.");
  }

  const staticRoot = [...staticGraph.nodes.values()].find(({ root }) => root);
  const runtimeRoot = [...runtimeGraph.nodes.values()].find(({ root }) => root);
  if (staticRoot && runtimeRoot) {
    staticToRuntime.set(staticRoot.id, runtimeRoot.id);
    runtimeToStatic.set(runtimeRoot.id, staticRoot.id);
  }

  const edgeDiffs = [];
  const seenRuntimeEdges = new Set();
  for (const edge of staticGraph.edges.values()) {
    const from = staticToRuntime.get(edge.from);
    const to = staticToRuntime.get(edge.to);
    const key = edgeKey(from, to);
    const runtime = runtimeGraph.edges.get(key);
    if (runtime) seenRuntimeEdges.add(key);
    const comparable = to && runtimeGraph.nodes.get(from)?.outgoingKnown;
    edgeDiffs.push({ static: edge, runtime, status: runtime ? "MATCHED" : comparable ? "STATIC_ONLY" : "UNVERIFIED" });
  }
  for (const [key, edge] of runtimeGraph.edges) {
    if (seenRuntimeEdges.has(key)) continue;
    const from = runtimeToStatic.get(edge.from);
    const to = runtimeToStatic.get(edge.to);
    const comparable = to && staticGraph.nodes.get(from)?.outgoingKnown;
    edgeDiffs.push({ runtime: edge, status: comparable ? "RUNTIME_ONLY" : "UNVERIFIED" });
  }

  const statusCounts = Object.fromEntries(statuses.map((status) => [status, 0]));
  for (const row of results) statusCounts[row.status]++;
  return {
    summary: { staticComponentCount: staticNodes.length, runtimeResourceCount: runtimeNodes.length, resultCount: results.length, statusCounts },
    results,
    edgeDiffs,
  };
}
