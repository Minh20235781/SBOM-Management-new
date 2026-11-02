import { useEffect, useRef } from "react";
import { renderDependencyGraph } from "./DependencyGraphD3";
import "./DependencyGraph.css";

export default function DependencyGraph({
  data,
  riskData,
  onSelectPackage
}) {
  const ref = useRef();

  useEffect(() => {
    if (!data) return;

    renderDependencyGraph({
      container: ref.current,
      data,
      riskData,
      onNodeClick: onSelectPackage
    });
  }, [data, riskData, onSelectPackage]);

  return (
    <div>
      <h3>Dependency Graph</h3>
      <div ref={ref} />
    </div>
  );
}
