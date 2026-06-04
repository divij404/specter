/* Specter — Network graph panel (v1.4)
 * Loaded before dashboard.js. Expects D3 from extension/lib/d3.min.js.
 */

const GRAPH_NODE_CAP = 500;
const GRAPH_DEBOUNCE_MS = 500;
const GRAPH_CATS = [
  'behavioral',
  'fingerprinting',
  'session_replay',
  'ad_network',
  'analytics',
  'legitimate',
  'unclassified',
];

let graphDeps = null;
let graphPanelActive = false;
let graphDebounceTimer = null;
let graphSimulation = null;
let graphResizeObserver = null;
let graphRenderGeneration = 0;

const GRAPH_BRAND_CDN = /cdn|assets?|images?|img|static|media|content/i;

/** Mirror service_worker brand-sibling heuristic for graph display on stored requests. */
function isBrandSiblingAssetHost(pageDomain, targetDomain) {
  if (!pageDomain || !targetDomain || pageDomain === targetDomain) return false;
  const stem = pageDomain.split('.')[0];
  if (stem.length < 4) return false;
  if (!targetDomain.startsWith(stem)) return false;
  return GRAPH_BRAND_CDN.test(targetDomain);
}

function graphRequestCategory(req) {
  const src = req.initiator_domain || '_direct';
  const dst = req.domain;
  if (dst && isBrandSiblingAssetHost(src, dst)) return 'legitimate';
  return req.category || 'unclassified';
}

function buildRequestGraph(requests) {
  const nodes = new Map();
  const edgeMap = new Map();
  const domainVolume = new Map();

  function bumpVolume(id, n) {
    domainVolume.set(id, (domainVolume.get(id) || 0) + n);
  }

  function ensurePageNode(id) {
    if (!nodes.has(id)) {
      nodes.set(id, { id, type: 'page', category: 'legitimate', catCounts: null });
    }
  }

  function ensureDestNode(id, category, related) {
    const cat = category || 'unclassified';
    let n = nodes.get(id);
    if (!n) {
      n = { id, type: related ? 'related' : 'tracker', category: cat, catCounts: {} };
      nodes.set(id, n);
    }
    if (n.type === 'tracker' || n.type === 'related') {
      if (related) n.type = 'related';
      n.catCounts[cat] = (n.catCounts[cat] || 0) + 1;
    }
  }

  for (const req of requests) {
    const src = req.initiator_domain || '_direct';
    const dst = req.domain;
    if (!dst || dst === src) continue;

    const cat = graphRequestCategory(req);
    const related = cat === 'legitimate' && isBrandSiblingAssetHost(src, dst);

    bumpVolume(src, 1);
    bumpVolume(dst, 1);
    ensurePageNode(src);
    ensureDestNode(dst, cat, related);

    const key = src + '\0' + dst;
    if (!edgeMap.has(key)) {
      edgeMap.set(key, { source: src, target: dst, category: cat, count: 0, related });
    }
    const edge = edgeMap.get(key);
    edge.count += 1;
    if (related) edge.related = true;
  }

  // Domains used only as cross-site targets must not stay typed as page initiators.
  for (const e of edgeMap.values()) {
    if (e.related || e.source === e.target) continue;
    const tgt = nodes.get(e.target);
    if (tgt && tgt.type === 'page') tgt.type = 'tracker';
  }

  for (const n of nodes.values()) {
    if ((n.type === 'tracker' || n.type === 'related') && n.catCounts) {
      let best = n.category;
      let bestN = 0;
      for (const [cat, cnt] of Object.entries(n.catCounts)) {
        if (cnt > bestN) {
          bestN = cnt;
          best = cat;
        }
      }
      n.category = best;
      delete n.catCounts;
    }
    n.volume = domainVolume.get(n.id) || 0;
  }

  let nodeList = [...nodes.values()];
  let edgeList = [...edgeMap.values()];
  let capped = false;

  if (nodeList.length > GRAPH_NODE_CAP) {
    capped = true;
    nodeList.sort((a, b) => b.volume - a.volume);
    const keep = new Set(nodeList.slice(0, GRAPH_NODE_CAP).map((n) => n.id));
    nodeList = nodeList.filter((n) => keep.has(n.id));
    edgeList = edgeList.filter((e) => keep.has(e.source) && keep.has(e.target));
  }

  const nodeById = new Map(nodeList.map((n) => [n.id, n]));
  for (const e of edgeList) {
    const tgt = nodeById.get(e.target);
    e.strokeCategory = e.related ? 'legitimate' : (tgt?.category || 'unclassified');
  }

  const thirdPartyCount = nodeList.filter((n) => n.type === 'tracker').length;

  return {
    nodes: nodeList,
    edges: edgeList,
    capped,
    thirdPartyCount,
    nodeById,
  };
}

function graphNodeLabel(id) {
  if (!graphDeps) return id;
  if (id === '_direct') return 'Direct';
  return graphDeps.formatSiteDisplayName(id);
}

function graphShowTooltip(event, lines) {
  const tooltipEl = document.getElementById('specter-tooltip');
  if (!tooltipEl) return;
  tooltipEl.textContent = lines.join('\n');
  tooltipEl.setAttribute('aria-hidden', 'false');
  tooltipEl.classList.add('is-visible');
  const pad = 12;
  let left = event.clientX + pad;
  let top = event.clientY + pad;
  requestAnimationFrame(() => {
    const tw = tooltipEl.offsetWidth;
    const th = tooltipEl.offsetHeight;
    if (left + tw > window.innerWidth - 8) left = event.clientX - tw - pad;
    if (top + th > window.innerHeight - 8) top = event.clientY - th - pad;
    tooltipEl.style.left = left + 'px';
    tooltipEl.style.top = top + 'px';
  });
}

function graphHideTooltip() {
  const tooltipEl = document.getElementById('specter-tooltip');
  if (!tooltipEl) return;
  tooltipEl.classList.remove('is-visible');
  tooltipEl.setAttribute('aria-hidden', 'true');
}

function renderGraphLegend(root) {
  if (!graphDeps) return;
  const legend = document.createElement('div');
  legend.className = 'graph-legend';
  for (const cat of GRAPH_CATS) {
    if (cat === 'legitimate') continue;
    const item = document.createElement('span');
    item.className = 'graph-legend-item';
    const swatch = document.createElement('span');
    swatch.className = 'graph-legend-swatch';
    swatch.style.background = graphDeps.getCategoryColorHex(cat);
    item.appendChild(swatch);
    item.appendChild(document.createTextNode(graphDeps.categoryLabel(cat)));
    legend.appendChild(item);
  }
  const pageItem = document.createElement('span');
  pageItem.className = 'graph-legend-item';
  const pageSwatch = document.createElement('span');
  pageSwatch.className = 'graph-legend-swatch graph-legend-swatch--page';
  pageItem.appendChild(pageSwatch);
  pageItem.appendChild(document.createTextNode('Page / initiator'));
  legend.appendChild(pageItem);
  const relatedItem = document.createElement('span');
  relatedItem.className = 'graph-legend-item';
  const relatedSwatch = document.createElement('span');
  relatedSwatch.className = 'graph-legend-swatch graph-legend-swatch--related';
  relatedItem.appendChild(relatedSwatch);
  relatedItem.appendChild(document.createTextNode('Site assets'));
  legend.appendChild(relatedItem);
  root.appendChild(legend);
}

function renderGraphEmpty(container, message, showDragHint) {
  container.innerHTML =
    '<div class="graph-empty-state">' +
    '<svg class="graph-empty-icon" viewBox="0 0 48 32" fill="none" stroke="currentColor" stroke-width="1.2" aria-hidden="true">' +
    '<circle cx="12" cy="16" r="5"/>' +
    '<circle cx="36" cy="10" r="4" opacity="0.7"/>' +
    '<circle cx="38" cy="24" r="3" opacity="0.5"/>' +
    '<line x1="17" y1="14" x2="32" y2="11"/>' +
    '<line x1="17" y1="18" x2="35" y2="23"/>' +
    '</svg>' +
    '<span class="graph-empty-text">' + message + '</span>' +
    (showDragHint
      ? '<span class="graph-drag-hint">Drag nodes to rearrange the layout</span>'
      : '') +
    '</div>';
}

function graphHeadlineText(thirdPartyCount, hasEdges) {
  if (!hasEdges) return { text: 'No third-party connections in this view', html: false };
  if (thirdPartyCount === 0) {
    return {
      text: 'Only same-brand asset hosts — no third-party trackers in this view',
      html: false,
    };
  }
  const n = thirdPartyCount;
  return {
    text: null,
    html:
      '<strong>' +
      n +
      '</strong> third-party ' +
      (n === 1 ? 'system' : 'systems') +
      ' detected',
  };
}

function graphNodeRadius(d) {
  if (d.type === 'page') return 11;
  if (d.type === 'related') return 7 + Math.min(3, Math.sqrt(d.volume || 1) * 0.35);
  const vol = d.volume || 1;
  return 6 + Math.min(10, Math.sqrt(vol) * 1.15);
}

function graphCollisionRadius(d) {
  return graphNodeRadius(d) + 4;
}

function renderGraphPanel() {
  const container = document.getElementById('graph-container');
  const headlineEl = document.getElementById('graph-headline');
  const capBanner = document.getElementById('graph-cap-banner');
  const legendHost = document.getElementById('graph-legend-host');
  if (!container || !graphDeps) return;

  const gen = ++graphRenderGeneration;
  if (graphSimulation) {
    graphSimulation.stop();
    graphSimulation = null;
  }

  if (typeof d3 === 'undefined') {
    renderGraphEmpty(container, 'Run npm run bundle-libs to load D3.');
    return;
  }

  const requests = graphDeps.getGraphRequests();
  const { nodes, edges, capped, thirdPartyCount } = buildRequestGraph(requests);

  const dragHintEl = document.getElementById('graph-drag-hint');
  if (dragHintEl) {
    dragHintEl.hidden = edges.length === 0;
  }

  if (headlineEl) {
    const hl = graphHeadlineText(thirdPartyCount, edges.length > 0);
    if (hl.html) headlineEl.innerHTML = hl.html;
    else headlineEl.textContent = hl.text;
  }

  if (capBanner) {
    capBanner.hidden = !capped;
    capBanner.textContent = capped ? 'Showing top ' + GRAPH_NODE_CAP + ' domains by request volume' : '';
  }

  if (legendHost) {
    legendHost.textContent = '';
    if (edges.length > 0) renderGraphLegend(legendHost);
  }

  container.textContent = '';

  if (edges.length === 0) {
    let msg = 'No third-party connections in this view.';
    if (graphDeps.feedRequestsLength() === 0) {
      msg = 'Start a session and browse to map network connections.';
    } else if (requests.length === 0) {
      msg = 'No requests for the selected site match the current filters.';
    }
    renderGraphEmpty(container, msg, true);
    return;
  }

  const W = container.clientWidth || 400;
  const H = container.clientHeight || 200;
  if (W < 40 || H < 40) return;

  const VIEW_PAD = 22;

  const svg = d3.select(container).append('svg').attr('width', W).attr('height', H).attr('class', 'graph-svg');

  const g = svg.append('g');
  const nodeData = nodes.map((n) => ({ ...n }));
  const linkData = edges.map((e) => ({ ...e }));

  const colorFor = (d) => {
    if (d.type === 'page' || d.type === 'related') {
      return graphDeps.getCategoryColorHex('legitimate') || '#64748b';
    }
    return graphDeps.getCategoryColorHex(d.category) || '#888';
  };

  const edgeColorFor = (d) => {
    const cat = d.strokeCategory || (d.related ? 'legitimate' : 'unclassified');
    return graphDeps.getCategoryColorHex(cat) || '#888';
  };

  const clampNode = (d) => {
    const r = graphNodeRadius(d);
    d.x = Math.max(VIEW_PAD + r, Math.min(W - VIEW_PAD - r, d.x));
    d.y = Math.max(VIEW_PAD + r, Math.min(H - VIEW_PAD - r, d.y));
  };

  const simulation = d3
    .forceSimulation(nodeData)
    .force(
      'link',
      d3
        .forceLink(linkData)
        .id((d) => d.id)
        .distance((l) => 80 + Math.min(40, Math.log((l.count || 1) + 1) * 12)),
    )
    .force('charge', d3.forceManyBody().strength(-220))
    .force('center', d3.forceCenter(W / 2, H / 2))
    .force('collision', d3.forceCollide().radius((d) => graphCollisionRadius(d)));

  graphSimulation = simulation;

  const link = g
    .append('g')
    .attr('class', 'graph-links')
    .selectAll('line')
    .data(linkData)
    .join('line')
    .attr('stroke', edgeColorFor)
    .attr('stroke-width', (d) => Math.min(6, 1 + Math.log(d.count || 1)))
    .attr('stroke-opacity', 0.65);

  const node = g
    .append('g')
    .attr('class', 'graph-nodes')
    .selectAll('circle')
    .data(nodeData)
    .join('circle')
    .attr('r', graphNodeRadius)
    .attr('fill', colorFor)
    .attr('stroke', 'var(--bg-base)')
    .attr('stroke-width', 1.5)
    .style('cursor', 'pointer')
    .call(
      d3
        .drag()
        .on('start', (event, d) => {
          if (!event.active) simulation.alphaTarget(0.3).restart();
          d.fx = d.x;
          d.fy = d.y;
        })
        .on('drag', (event, d) => {
          const r = graphNodeRadius(d);
          d.fx = Math.max(VIEW_PAD + r, Math.min(W - VIEW_PAD - r, event.x));
          d.fy = Math.max(VIEW_PAD + r, Math.min(H - VIEW_PAD - r, event.y));
        })
        .on('end', (event, d) => {
          if (!event.active) simulation.alphaTarget(0);
          d.fx = null;
          d.fy = null;
        }),
    );

  const label = g
    .append('g')
    .attr('class', 'graph-labels')
    .selectAll('text')
    .data(nodeData)
    .join('text')
    .text((d) => {
      const name = graphNodeLabel(d.id);
      return name.length > 22 ? name.slice(0, 20) + '\u2026' : name;
    })
    .attr('font-size', 9)
    .attr('fill', 'var(--text-secondary)')
    .attr('dx', 12)
    .attr('dy', 3)
    .style('pointer-events', 'none');

  node
    .on('mouseenter', function (event, d) {
      const lines = [graphNodeLabel(d.id)];
      if (d.type === 'page') lines.push('Page / initiator');
      else if (d.type === 'related') lines.push('Site assets (same brand)');
      else lines.push(graphDeps.categoryLabel(d.category));
      lines.push('Requests: ' + (d.volume || 0));
      graphShowTooltip(event, lines);
    })
    .on('mouseleave', graphHideTooltip)
    .on('click', (_, d) => {
      if (graphDeps.onNodeClick) graphDeps.onNodeClick(d.id);
    });

  link
    .on('mouseenter', function (event, d) {
      const src = typeof d.source === 'object' ? d.source.id : d.source;
      const tgt = typeof d.target === 'object' ? d.target.id : d.target;
      const cat = d.strokeCategory || 'unclassified';
      graphShowTooltip(event, [
        graphNodeLabel(src) + ' \u2192 ' + graphNodeLabel(tgt),
        graphDeps.categoryLabel(cat) + ' \u00b7 ' + d.count + ' request' + (d.count === 1 ? '' : 's'),
      ]);
    })
    .on('mouseleave', graphHideTooltip);

  simulation.on('tick', () => {
    if (gen !== graphRenderGeneration) return;
    for (const d of nodeData) clampNode(d);
    link
      .attr('x1', (d) => d.source.x)
      .attr('y1', (d) => d.source.y)
      .attr('x2', (d) => d.target.x)
      .attr('y2', (d) => d.target.y);
    node.attr('cx', (d) => d.x).attr('cy', (d) => d.y);
    label.attr('x', (d) => d.x).attr('y', (d) => d.y);
  });
}

function scheduleGraphRender(immediate) {
  if (!graphPanelActive) return;
  if (graphDebounceTimer) clearTimeout(graphDebounceTimer);
  if (immediate) {
    graphDebounceTimer = null;
    requestAnimationFrame(renderGraphPanel);
    return;
  }
  graphDebounceTimer = setTimeout(() => {
    graphDebounceTimer = null;
    if (graphPanelActive) requestAnimationFrame(renderGraphPanel);
  }, GRAPH_DEBOUNCE_MS);
}

function setGraphPanelActive(active) {
  graphPanelActive = !!active;
  if (!graphPanelActive) {
    if (graphDebounceTimer) clearTimeout(graphDebounceTimer);
    graphDebounceTimer = null;
    if (graphSimulation) {
      graphSimulation.stop();
      graphSimulation = null;
    }
    graphHideTooltip();
    return;
  }
  scheduleGraphRender(true);
}

function resetGraphLayout() {
  scheduleGraphRender(true);
}

function exportGraphSvg() {
  const svg = document.querySelector('#graph-container svg.graph-svg');
  if (!svg) return;
  const blob = new Blob([svg.outerHTML], { type: 'image/svg+xml;charset=utf-8' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = 'specter-graph-' + Date.now() + '.svg';
  a.click();
  URL.revokeObjectURL(a.href);
}

function initGraphPanel(deps) {
  graphDeps = deps;

  document.getElementById('graph-reset-btn')?.addEventListener('click', resetGraphLayout);
  document.getElementById('graph-export-btn')?.addEventListener('click', exportGraphSvg);

  const container = document.getElementById('graph-container');
  const layer = document.getElementById('dashboard-network-layer');
  if (typeof ResizeObserver !== 'undefined' && (container || layer)) {
    if (graphResizeObserver) graphResizeObserver.disconnect();
    graphResizeObserver = new ResizeObserver(() => {
      if (graphPanelActive) scheduleGraphRender(true);
    });
    if (container) graphResizeObserver.observe(container);
    if (layer) graphResizeObserver.observe(layer);
  }
}
