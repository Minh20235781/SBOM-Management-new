import { useEffect, useRef } from "react";
import * as d3 from "d3";
import { getRiskColor, getRiskLevel } from "./utils/graphRiskUtils";
import { normalizeAttention } from "./utils/attentionUtils";
import { normalizePropagation } from "./utils/propagationUtils";
import "./GnnPropagationGraph.css";

/**
 * Experimental propagation graph.
 *
 * Exploit propagation visualization highlights contextual exposure across dependencies.
 * Dependency centrality indicates which nodes amplify risk in the graph.
 * Graph-based exposure analysis emphasizes paths that can spread vulnerabilities.
 */
export default function GnnPropagationGraph({ graphPayload, explainabilityIndex }) {
  const containerRef = useRef(null);

  useEffect(() => {
    if (!graphPayload || !containerRef.current) return;

    const container = containerRef.current;
    d3.select(container).selectAll("*").remove();

    const width = container.clientWidth || 800;
    const height = 420;

    const root = d3
      .select(container)
      .attr("class", "gnn-analysis-graph-container")
      .style("position", "relative");

    const svg = root
      .append("svg")
      .attr("width", width)
      .attr("height", height)
      .call(
        d3.zoom().scaleExtent([0.2, 3]).on("zoom", (event) => {
          g.attr("transform", event.transform);
        })
      )
      .append("g");

    const g = svg.append("g");

    const nodes = (graphPayload.nodes || []).map((node, index) => {
      const name = node.packageName || `node-${index}`;
      const explain = explainabilityIndex?.get(name.toLowerCase());
      return {
        id: node.nodeId ?? index,
        name,
        risk: getRiskLevel(explain?.predictedRisk),
        attention: normalizeAttention(explain?.attentionScores?.selfAttention ?? 0),
        propagation: normalizePropagation(explain?.attentionScores?.propagationRisk ?? 0)
      };
    });

    const nodeMap = new Map(nodes.map((node) => [node.id, node]));

    const links = (graphPayload.edges || [])
      .map((edge) => {
        const source = nodeMap.get(edge.source);
        const target = nodeMap.get(edge.target);
        if (!source || !target) return null;
        return { source, target };
      })
      .filter(Boolean);

    const sim = d3
      .forceSimulation(nodes)
      .force("link", d3.forceLink(links).distance(90).strength(0.7))
      .force("charge", d3.forceManyBody().strength(-260))
      .force("center", d3.forceCenter(width / 2, height / 2))
      .force("collision", d3.forceCollide().radius((d) => 18 + d.attention * 12))
      .alphaDecay(0.02);

    const link = g
      .append("g")
      .selectAll("line")
      .data(links)
      .enter()
      .append("line")
      .attr("class", (d) =>
        d.source.propagation > 0.6 || d.target.propagation > 0.6
          ? "gnn-analysis-link gnn-analysis-link-propagation"
          : "gnn-analysis-link"
      );

    const node = g
      .append("g")
      .selectAll("circle")
      .data(nodes)
      .enter()
      .append("circle")
      .attr("class", (d) => {
        const classes = ["gnn-analysis-node"];
        if (d.risk === "HIGH") classes.push("gnn-analysis-node-high");
        if (d.attention >= 0.6) classes.push("gnn-analysis-node-attention");
        if (d.propagation >= 0.65) classes.push("gnn-analysis-node-propagation");
        return classes.join(" ");
      })
      .attr("r", (d) => 12 + d.attention * 10)
      .attr("fill", (d) => getRiskColor(d.risk));

    const labels = g
      .append("g")
      .selectAll("text")
      .data(nodes)
      .enter()
      .append("text")
      .attr("class", "gnn-analysis-label")
      .text((d) => (d.name.length > 16 ? `${d.name.slice(0, 16)}...` : d.name));

    const tooltip = root
      .append("div")
      .attr("class", "gnn-analysis-tooltip")
      .style("opacity", 0);

    node
      .on("mouseover", (event, d) => {
        tooltip
          .style("opacity", 1)
          .style("left", `${event.offsetX + 18}px`)
          .style("top", `${event.offsetY + 18}px`)
          .html(
            `<strong>${d.name}</strong><br/>Risk: ${d.risk}<br/>Attention: ${Math.round(
              d.attention * 100
            )}%<br/>Propagation: ${Math.round(d.propagation * 100)}%`
          );
      })
      .on("mouseout", () => {
        tooltip.style("opacity", 0);
      });

    sim.on("tick", () => {
      link
        .attr("x1", (d) => d.source.x)
        .attr("y1", (d) => d.source.y)
        .attr("x2", (d) => d.target.x)
        .attr("y2", (d) => d.target.y);

      node.attr("cx", (d) => d.x).attr("cy", (d) => d.y);
      labels.attr("x", (d) => d.x + 14).attr("y", (d) => d.y + 4);
    });

    return () => {
      sim.stop();
    };
  }, [graphPayload, explainabilityIndex]);

  return <div ref={containerRef} />;
}
