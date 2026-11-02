export function makeDragHandlers(sim) {
  function dragstarted(event, d) {
    if (!event.active) sim.alphaTarget(0.3).restart();
    d.fx = d.x;
    d.fy = d.y;
  }

  function dragged(event, d) {
    d.fx = event.x;
    d.fy = event.y;
  }

  function dragended(event, d) {
    if (!event.active) sim.alphaTarget(0);
    d.fx = null;
    d.fy = null;
  }

  return { dragstarted, dragged, dragended };
}

export function makeTooltipHandlers({ tooltip, color }) {
  function showTooltip(event, d) {
    const riskLevel = d.riskLevel || 'UNKNOWN';
    const riskColors = {
      LOW: '#4CAF50',
      MEDIUM: '#FFC107',
      HIGH: '#FF9800',
      CRITICAL: '#F44336'
    };

    tooltip
      .style('opacity', 1)
      .html(`
        <div class="tooltip-content">
          <div class="tooltip-header">
            <strong>${d.displayName || d.id || 'Unknown'}</strong>
            <span class="risk-level" style="background: ${riskColors[riskLevel]}">
              ${riskLevel}
            </span>
          </div>
          <div class="tooltip-section">
            <strong>Risk Scores</strong>
            <div>Vuln Risk: <span class="value" style="color: ${color(d.vulnAnomaly)}">${(d.vulnAnomaly * 100).toFixed(1)}%</span></div>
            <div>Hub Risk: <span class="value" style="color: ${color(d.hubAnomaly)}">${(d.hubAnomaly * 100).toFixed(1)}%</span></div>
          </div>
          <div class="tooltip-section">
            <strong>Package Info</strong>
            <div>Rank: <span class="value">${d.rankScore?.toFixed(4)}</span></div>
            ${d.vulnCount !== undefined ? `<div>Vulnerabilities: <span class="value">${d.vulnCount}</span></div>` : ''}
            ${d.highSeverity !== undefined ? `<div>High Severity: <span class="value">${d.highSeverity}</span></div>` : ''}
          </div>
        </div>
      `)
      .style('left', (event.pageX + 15) + 'px')
      .style('top', (event.pageY - 15) + 'px');
  }

  function hideTooltip() {
    tooltip.style('opacity', 0);
  }

  return { showTooltip, hideTooltip };
}

export function makeHighlightHandlers({ d3, link, node, links, sim }) {
  function highlightConnections(selectedNode) {
    // Reset all highlights first
    resetHighlights();

    // Highlight selected node
    d3.selectAll('.node')
      .filter(n => n.id === selectedNode.id)
      .attr('stroke', '#2196F3')
      .attr('stroke-width', 4);

    const connectedLinks = links.filter(l => l.source.id === selectedNode.id || l.target.id === selectedNode.id);

    connectedLinks.forEach(linkData => {
      d3.selectAll('.link')
        .filter(l => l.id === linkData.id)
        .attr('stroke', '#ff4444')
        .attr('stroke-width', 3)
        .attr('stroke-opacity', 0.9);
    });

    const connectedNodeIds = new Set();
    connectedLinks.forEach(l => {
      if (l.source.id !== selectedNode.id) connectedNodeIds.add(l.source.id);
      if (l.target.id !== selectedNode.id) connectedNodeIds.add(l.target.id);
    });

    connectedNodeIds.forEach(nodeId => {
      d3.selectAll('.node')
        .filter(n => n.id === nodeId)
        .attr('stroke', '#ff4444')
        .attr('stroke-width', 3);
    });
  }

  function resetHighlights() {
    link
      .attr('stroke', '#999')
      .attr('stroke-width', 1.5)
      .attr('stroke-opacity', 0.6);

    node
      .attr('stroke', '#fff')
      .attr('stroke-width', 2);
  }

  return { highlightConnections, resetHighlights };
}
