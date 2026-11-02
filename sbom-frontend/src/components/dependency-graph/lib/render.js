import * as d3 from 'd3';
import { DEFAULT_HEIGHT } from '../utils/constants';
import { prepareNodesAndLinks } from '../utils/graphHelpers';
import { createLegend } from './legend';
import { makeDragHandlers, makeTooltipHandlers, makeHighlightHandlers } from './interactions';

export function renderDependencyGraph({ container, data, riskData, onNodeClick }) {
  // remove prior content
  d3.select(container).selectAll('*').remove();

  const width = container.clientWidth || 800;
  const height = DEFAULT_HEIGHT;

  const root = d3.select(container)
    .attr('class', 'dependency-graph-container')
    .style('position', 'relative');

  const svg = root.append('svg')
    .attr('width', width)
    .attr('height', height)
    .call(
      d3.zoom()
        .scaleExtent([0.1, 4])
        .on('zoom', (event) => {
          g.attr('transform', event.transform);
        })
    )
    .append('g');

  const g = svg.append('g');

  /* arrow marker for directed edges */
  const defs = svg.append('defs');
  defs.append('marker')
    .attr('id', 'arrowhead')
    .attr('viewBox', '0 -5 10 10')
    .attr('refX', 8)
    .attr('refY', 0)
    .attr('markerWidth', 6)
    .attr('markerHeight', 6)
    .attr('orient', 'auto')
    .append('path')
    .attr('d', 'M0,-5L10,0L0,5')
    .attr('fill', '#999');

  const tooltip = root.append('div')
    .attr('class', 'tooltip')
    .style('opacity', 0);

  const { nodes, links } = prepareNodesAndLinks(data, riskData);

  /* scales */
  const color = d3.scaleThreshold()
    .domain([0.3, 0.6, 0.9])
    .range(['#4CAF50', '#FFC107', '#FF9800', '#F44336']);

  const size = d3.scaleLinear()
    .domain(d3.extent(nodes, d => d.rankScore))
    .range([8, 25]);

  /* simulation */
  const sim = d3.forceSimulation(nodes)
    .force('link', d3.forceLink(links).id(d => d.id).distance(100).strength(0.5))
    .force('charge', d3.forceManyBody().strength(-200))
    .force('center', d3.forceCenter(width / 2, height / 2))
    .force('collision', d3.forceCollide().radius(d => size(d.rankScore) + 5))
    .alphaDecay(0.02);

  /* draw links */
  const link = g.append('g')
    .selectAll('line')
    .data(links)
    .enter()
    .append('line')
    .attr('class', 'link')
    .attr('stroke', '#999')
    .attr('stroke-width', 1.5)
    .attr('stroke-opacity', 0.6)
    .attr('marker-end', 'url(#arrowhead)');

  /* draw nodes */
  const node = g.append('g')
    .selectAll('circle')
    .data(nodes)
    .enter()
    .append('circle')
    .attr('class', 'node')
    .attr('r', d => size(d.rankScore))
    .attr('fill', d => color(Math.max(d.vulnAnomaly, d.hubAnomaly)))
    .attr('stroke', '#fff')
    .attr('stroke-width', 2);

  /* labels */
  const labels = g.append('g')
    .selectAll('text')
    .data(nodes)
    .enter()
    .append('text')
    .attr('class', 'label')
    .text(d => {
      const name = d.displayName || d.id || '';
      return name.length > 15 ? name.substring(0, 15) + '...' : name;
    })
    .attr('font-size', '10px')
    .attr('dx', d => size(d.rankScore) + 5)
    .attr('dy', '.35em')
    .style('pointer-events', 'none')
    .style('fill', '#333')
    .style('text-shadow', '1px 1px 2px white');

  /* legend */
  createLegend(root);

  /* controls */
  const controls = root.append('div')
    .style('position', 'absolute')
    .style('bottom', '20px')
    .style('right', '20px')
    .style('display', 'flex')
    .style('gap', '8px');

  const resetBtn = controls.append('button')
    .style('padding', '6px 12px')
    .style('background', '#fff')
    .style('border', '1px solid #ccc')
    .style('border-radius', '4px')
    .style('cursor', 'pointer')
    .style('font-size', '12px')
    .style('transition', 'all 0.2s')
    .text('Reset View')
    .on('mouseover', function() { d3.select(this).style('background', '#f5f5f5'); })
    .on('mouseout', function() { d3.select(this).style('background', '#fff'); })
    .on('click', () => {
      svg.transition().duration(750).call(zoom.transform, d3.zoomIdentity);
      // reset highlights
      highlight.resetHighlights();
      sim.alpha(1).restart();
    });

  /* interactions */
  const drag = makeDragHandlers(sim);
  const tooltipHandlers = makeTooltipHandlers({ tooltip, color });
  const highlight = makeHighlightHandlers({ d3, link, node, links, sim });

  node.call(d3.drag()
    .on('start', drag.dragstarted)
    .on('drag', drag.dragged)
    .on('end', drag.dragended))
    .on('click', (event, d) => { highlight.highlightConnections(d); onNodeClick?.(d.displayName); event.stopPropagation(); })
    .on('dblclick', (event) => { highlight.resetHighlights(); event.stopPropagation(); })
    .on('mouseover', (event, d) => {
      tooltipHandlers.showTooltip(event, d);
      d3.select(event.currentTarget).transition().duration(200).attr('r', size(d.rankScore) * 1.2);
    })
    .on('mouseout', (event, d) => {
      tooltipHandlers.hideTooltip();
      d3.select(event.currentTarget).transition().duration(200).attr('r', size(d.rankScore));
    });

  sim.on('tick', () => {
    // Link ends at edge of target node (so arrow is visible)
    link.attr('x1', d => d.source.x)
        .attr('y1', d => d.source.y)
        .attr('x2', d => {
          const dx = d.target.x - d.source.x;
          const dy = d.target.y - d.source.y;
          const dist = Math.sqrt(dx * dx + dy * dy);
          if (dist === 0) return d.target.x;
          const nodeRadius = size(d.target.rankScore || d.target.rank);
          const ratio = (dist - nodeRadius - 5) / dist; // 5px padding
          return d.source.x + dx * ratio;
        })
        .attr('y2', d => {
          const dx = d.target.x - d.source.x;
          const dy = d.target.y - d.source.y;
          const dist = Math.sqrt(dx * dx + dy * dy);
          if (dist === 0) return d.target.y;
          const nodeRadius = size(d.target.rankScore || d.target.rank);
          const ratio = (dist - nodeRadius - 5) / dist; // 5px padding
          return d.source.y + dy * ratio;
        });
    node.attr('cx', d => d.x).attr('cy', d => d.y);
    labels.attr('x', d => d.x).attr('y', d => d.y);
  });

  const zoom = d3.zoom();
}

export default { renderDependencyGraph };
