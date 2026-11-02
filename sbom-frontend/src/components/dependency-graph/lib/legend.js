import { LEGEND_DATA } from '../utils/constants';

export function createLegend(root) {
  const legend = root.append('div')
    .attr('class', 'legend')
    .style('position', 'absolute')
    .style('top', '20px')
    .style('right', '20px')
    .style('background', 'white')
    .style('padding', '12px')
    .style('border-radius', '6px')
    .style('box-shadow', '0 2px 8px rgba(0,0,0,0.1)')
    .style('border', '1px solid #e0e0e0');

  legend.append('h4')
    .style('margin', '0 0 10px 0')
    .style('font-size', '14px')
    .style('font-weight', '600')
    .style('color', '#333')
    .text('Risk Level');

  const legendItems = legend.selectAll('.legend-item')
    .data(LEGEND_DATA)
    .enter()
    .append('div')
    .attr('class', 'legend-item')
    .style('display', 'flex')
    .style('align-items', 'center')
    .style('margin', '5px 0');

  legendItems.append('div')
    .style('width', '16px')
    .style('height', '16px')
    .style('margin-right', '8px')
    .style('border-radius', '50%')
    .style('background-color', d => d.color);

  legendItems.append('span')
    .style('font-size', '12px')
    .style('color', '#555')
    .text(d => d.label);

  return legend;
}
