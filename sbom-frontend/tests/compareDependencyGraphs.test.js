import test from "node:test";
import assert from "node:assert/strict";
import { compareDependencyGraphs, readDependencyGraph } from "../src/pages/Reconciliation/compareDependencyGraphs.js";

function component(name, version = "1.0.0", ref = name, purl = `pkg:npm/${name}@${version}`) {
  return { name, version, "bom-ref": ref, purl };
}

function graph(components, relationships = {}) {
  return readDependencyGraph({
    components,
    dependencies: Object.entries(relationships).map(([ref, dependsOn]) => ({ ref, dependsOn })),
  });
}

test("aligns refs by package identity across SBOMs and detects directed edge changes", () => {
  const left = graph([component("a"), component("b"), component("c")], { a: ["b", "c"], b: [], c: [] });
  const same = graph([component("c", "1.0.0", "C"), component("a", "1.0.0", "A"), component("b", "1.0.0", "B")], {
    C: [], B: [], A: ["C", "B"],
  });
  const changed = graph([component("c", "1.0.0", "C"), component("a", "1.0.0", "A"), component("b", "1.0.0", "B")], {
    C: [], B: ["A"], A: ["C"],
  });

  assert.deepEqual(compareDependencyGraphs(left, same).edgeDiffs.map(({ status }) => status), ["MATCHED", "MATCHED"]);
  assert.deepEqual(compareDependencyGraphs(left, changed).edgeDiffs.map(({ status }) => status), ["STATIC_ONLY", "MATCHED", "RUNTIME_ONLY"]);
});

test("keeps edges unverified when the other SBOM has missing or partial relationships", () => {
  const left = graph([component("a"), component("b")], { a: ["b"] });
  for (const right of [
    graph([component("a"), component("b")]),
    graph([component("a"), component("b")], { a: ["unknown-ref"] }),
  ]) {
    const report = compareDependencyGraphs(left, right);
    assert.equal(report.summary.statusCounts.MATCHED, 2);
    assert.equal(report.edgeDiffs[0].status, "UNVERIFIED");
  }
  const explicitEmpty = graph([component("a"), component("b")], { a: [] });
  assert.equal(compareDependencyGraphs(left, explicitEmpty).edgeDiffs[0].status, "STATIC_ONLY");
  const markedIncomplete = readDependencyGraph({
    components: [component("a"), component("b")],
    dependencies: [{ ref: "a", dependsOn: [] }],
    compositions: [{ aggregate: "incomplete", dependencies: ["a"] }],
  });
  assert.equal(compareDependencyGraphs(left, markedIncomplete).edgeDiffs[0].status, "UNVERIFIED");
});

test("uses scoped identities and preserves uncertainty in missing versions, ambiguous and cross-ecosystem cases", () => {
  const left = graph([
    component("@scope/a", "1.0.0", "a", "pkg:npm/%40scope%2Fa@1.0.0"),
    component("b"), component("c"), component("d"), component("cross", "1.0.0", "cross", "pkg:maven/example/cross@1.0.0"),
  ]);
  const right = graph([
    component("@scope/a"), component("b", "2.0.0"), component("c", "VERSION_UNKNOWN", "c", "pkg:npm/c"),
    component("d", "2.0.0", "d-2"), component("d", "3.0.0", "d-3"), component("cross"), component("extra"),
  ]);
  const report = compareDependencyGraphs(left, right);

  assert.equal(report.summary.statusCounts.MATCHED, 1);
  assert.equal(report.results.find((row) => row.component === "b").versionStatus, "VERSION_MISMATCH");
  assert.equal(report.results.find((row) => row.component === "c").versionStatus, "VERSION_UNKNOWN");
  assert.equal(report.results.filter((row) => row.component === "d" && row.status === "UNRESOLVED").length, 3);
  assert.deepEqual(report.results.filter((row) => row.component === "cross").map(({ status }) => status), ["STATIC_ONLY", "RUNTIME_ONLY"]);
});

test("keeps shared libraries, cycles and duplicate edges finite in the tree data", () => {
  const dependencyGraph = graph([component("a"), component("b"), component("c"), component("d")], {
    a: ["b", "b", "c"], b: ["d"], c: ["d"], d: ["b"],
  });
  assert.equal(dependencyGraph.edges.size, 5);
  assert.equal(dependencyGraph.roots.length, 1);
  assert.equal([...dependencyGraph.nodes.values()].find(({ name }) => name === "d").parents.length, 2);

  const cycle = graph([component("a"), component("b")], { a: ["b"], b: ["a"] });
  assert.equal(cycle.roots.length, 1);
});
