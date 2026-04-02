/* Specter — dashboard script (Phase 6: live request feed) */

const CATEGORIES = [
  'behavioral',
  'fingerprinting',
  'session_replay',
  'ad_network',
  'analytics',
  'legitimate',
  'unclassified',
];

function categoryToBadgeClass(cat) {
  if (!cat) return 'feed-badge--unclassified';
  const k = cat.replace(/_/g, '-');
  return 'feed-badge--' + (k === 'fingerprinting' ? 'fingerprint' : k);
}

function categoryLabel(cat) {
  if (!cat) return 'Unclassified';
  return cat
    .split('_')
    .map((w) => w.charAt(0).toUpperCase() + w.slice(1))
    .join(' ');
}

function categoryTooltip(cat) {
  const tips = {
    behavioral: 'Behavioral — tracks user actions and behavior patterns',
    analytics: 'Analytics — measures site traffic and usage',
    fingerprinting: 'Fingerprinting — identifies users via browser/device attributes',
    session_replay: 'Session Replay — records and replays user sessions',
    ad_network: 'Ad Network — serves or tracks advertising',
    legitimate: 'Legitimate — standard site functionality',
    unclassified: 'Unclassified — could not be classified',
  };
  return tips[cat] || '';
}

let feedRequests = [];
let selectedRequestId = null;
let currentSession = null;
let settings = { autoscroll_feed: true, min_confidence: 0 };
let currentTabId = null;
let filterState = {
  categories: new Set(),
  tabFilter: 'all',
  minConfidence: 0,
  domainSearch: '',
  collapseDuplicates: true,
};
const scrollState = { userScrolledUp: false };
let requestCount = 0;
let feedPaused = false;
let sessionStartTime = null;
let timerInterval = null;
let pendingNewCount = 0;
const FEED_CAP = 200;
let lastGroupCounts = new Map();
let expandedGroups = new Set();
// clearFeedOnStart removed — keep_rows flag is now carried in the session_started message
let frozenElapsedSeconds = 0;

/* Phase 9: request detail + VirusTotal */
let vtLastRequestTime = 0;
let vtCountdownInterval = null;

/* Phase 7: site summary */
/** Dropdown sentinel: aggregate stats + timeline across the whole session (feed filters still apply). */
const SUMMARY_SCOPE_ALL_SITES = '__specter_all_sites__';
let siteScores = {};
let currentSiteDomain = null;
let lastRenderedScore = null;
let summarySelectedDomain = null;
/** True when summarySelectedDomain was set automatically by clicking a request (not by user dropdown choice). */
let summaryAutoSelected = false;

function extractETLDPlusOne(hostname) {
  if (!hostname) return '';
  const parts = hostname.split('.');
  if (parts.length <= 2) return hostname;
  return parts.slice(-2).join('.');
}

function isExtensionSchemeSiteKey(siteKey) {
  return /^(chrome-extension|moz-extension|safari-web-extension):\/\//i.test(String(siteKey));
}

function isBrowserInternalSiteKey(siteKey) {
  const s = String(siteKey).toLowerCase();
  return (
    /^(chrome|edge|brave|opera|vivaldi|about|devtools|view-source|chrome-extension|moz-extension|safari-web-extension):/i.test(
      siteKey
    ) ||
    s.startsWith('chrome://') ||
    s.startsWith('edge://') ||
    s.startsWith('about:') ||
    s.startsWith('devtools:')
  );
}

/** Hostname-like site key (eTLD+1 / site row key), not a full URL. */
function hasLikelyPublicTld(hostname) {
  if (!hostname || typeof hostname !== 'string') return false;
  const h = hostname.trim().toLowerCase();
  if (h === 'localhost') return true;
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(h)) return false;
  const i = h.lastIndexOf('.');
  if (i <= 0 || i >= h.length - 1) return false;
  const tld = h.slice(i + 1);
  if (tld.length < 2 || tld.length > 63) return false;
  if (!/^[a-z0-9][a-z0-9-]*[a-z0-9]$/i.test(tld) && !/^xn--[a-z0-9-]+$/i.test(tld)) return false;
  if (/^\d+$/.test(tld)) return false;
  return true;
}

function formatSiteDisplayName(siteKey) {
  if (siteKey == null || siteKey === '') return '\u2014';
  if (siteKey === '_direct') return 'Direct';
  const raw = String(siteKey);
  const hasDot = raw.includes('.');
  if (raw.length > 30) {
    if (isExtensionSchemeSiteKey(raw)) return '[EXTENSION PAGE]';
    if (isBrowserInternalSiteKey(raw)) return '[INTERNAL]';
    return '[EXTENSION PAGE]';
  }
  if (!hasDot || !hasLikelyPublicTld(raw)) {
    if (isExtensionSchemeSiteKey(raw)) return '[EXTENSION PAGE]';
    return '[INTERNAL]';
  }
  return raw;
}

function isMaskedSiteDisplayName(display) {
  return display === '[EXTENSION PAGE]' || display === '[INTERNAL]';
}

function getCurrentSiteDomain(callback) {
  if (summarySelectedDomain === SUMMARY_SCOPE_ALL_SITES) {
    callback(null);
    return;
  }
  if (summarySelectedDomain != null && siteScores[summarySelectedDomain]) {
    callback(summarySelectedDomain);
    return;
  }
  // Prefer the active browser tab's domain if we have data for it; otherwise fall back to worst site.
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    const tab = tabs && tabs[0];
    if (tab && tab.url) {
      try {
        const hostname = new URL(tab.url).hostname;
        const eTLD = extractETLDPlusOne(hostname);
        if (eTLD && siteScores[eTLD]) {
          callback(eTLD);
          return;
        }
      } catch {
        // ignore
      }
    }
    callback(getWorstSiteDomain());
  });
}

/** Site key used for per-site timeline (null = none / empty chart). */
function getSummaryTimelineSiteKey() {
  if (summarySelectedDomain === SUMMARY_SCOPE_ALL_SITES) return null;
  if (summarySelectedDomain != null && siteScores[summarySelectedDomain]) {
    return summarySelectedDomain;
  }
  return getWorstSiteDomain();
}

function getWorstSiteDomain() {
  const entries = Object.entries(siteScores);
  if (entries.length === 0) return null;
  let worst = entries[0];
  for (let i = 1; i < entries.length; i++) {
    if (entries[i][1].privacy_score < worst[1].privacy_score) worst = entries[i];
  }
  return worst[0];
}

function getSessionWorstPrivacyScore() {
  const entries = Object.values(siteScores);
  if (entries.length === 0) return null;
  let min = 100;
  for (const s of entries) {
    const p = s.privacy_score;
    if (p != null && p < min) min = p;
  }
  return min;
}

/** Privacy score color by numeric band only (dashboard + doughnut legend consistency). */
function getScoreColorClass(scoreVal) {
  const v = Number(scoreVal);
  if (Number.isNaN(v)) return 'score-low';
  if (v >= 80) return 'score-high';
  if (v >= 50) return 'score-mid';
  return 'score-low';
}

function animatePrivacyScore(element, fromVal, toVal, durationMs) {
  if (!element) return;
  const start = performance.now();
  const from = Number(fromVal);
  const to = Number(toVal);
  function tick(now) {
    const elapsed = now - start;
    const t = Math.min(1, elapsed / durationMs);
    const eased = t < 0.5 ? 2 * t * t : 1 - Math.pow(-2 * t + 2, 2) / 2;
    const value = Math.round(from + (to - from) * eased);
    element.textContent = String(value);
    element.className = 'site-summary-score-value ' + getScoreColorClass(value);
    if (t < 1) requestAnimationFrame(tick);
  }
  requestAnimationFrame(tick);
}

function renderSiteSummary() {
  const isAllSitesScope = summarySelectedDomain === SUMMARY_SCOPE_ALL_SITES;

  if (!isAllSitesScope) {
    if (summarySelectedDomain != null && siteScores[summarySelectedDomain]) {
      currentSiteDomain = summarySelectedDomain;
    } else {
      currentSiteDomain = getWorstSiteDomain();
    }
  } else {
    currentSiteDomain = null;
  }

  const dropdownContainer = document.getElementById('site-summary-site-dropdown');
  if (dropdownContainer) {
    buildSiteSummaryDropdown(dropdownContainer);
  }

  const root = document.getElementById('site-summary-root');
  if (!root) return;

  if (isAllSitesScope) {
    const scopeRequests = applyFilters(feedRequests);
    if (scopeRequests.length === 0 && Object.keys(siteScores).length === 0) {
      root.className = 'site-summary-layout site-summary-layout--empty';
      root.innerHTML =
        '<div class="site-summary-empty-state">' +
        '<svg class="site-summary-empty-icon" viewBox="0 0 40 40" fill="none" stroke="currentColor" stroke-width="1.5" aria-hidden="true">' +
        '<circle cx="20" cy="20" r="4"/>' +
        '<circle cx="20" cy="20" r="10" stroke-dasharray="3 3" opacity="0.5"/>' +
        '<circle cx="20" cy="20" r="16" stroke-dasharray="3 3" opacity="0.25"/>' +
        '</svg>' +
        '<span class="site-summary-empty-title">No session data</span>' +
        '<span class="site-summary-empty-hint">Click ▶ NEW SESSION above or start one from the popup, then browse.</span>' +
        '</div>';
      renderFingerprintingAlerts();
      scheduleTimelineRender();
      return;
    }
  } else if (!currentSiteDomain || !siteScores[currentSiteDomain]) {
    root.className = 'site-summary-layout site-summary-layout--empty';
    root.innerHTML =
      '<div class="site-summary-empty-state">' +
      '<svg class="site-summary-empty-icon" viewBox="0 0 40 40" fill="none" stroke="currentColor" stroke-width="1.5" aria-hidden="true">' +
      '<circle cx="20" cy="20" r="4"/>' +
      '<circle cx="20" cy="20" r="10" stroke-dasharray="3 3" opacity="0.5"/>' +
      '<circle cx="20" cy="20" r="16" stroke-dasharray="3 3" opacity="0.25"/>' +
      '</svg>' +
      '<span class="site-summary-empty-title">No data for this site</span>' +
      '<span class="site-summary-empty-hint">Visit this site during an active session to see its tracker summary.</span>' +
      '</div>';
    renderFingerprintingAlerts();
    scheduleTimelineRender();
    return;
  }

  const score = !isAllSitesScope ? siteScores[currentSiteDomain] : null;
  const domainLabel = isAllSitesScope ? 'All sites (session)' : formatSiteDisplayName(currentSiteDomain);
  const scoreVal = isAllSitesScope
    ? (getSessionWorstPrivacyScore() ?? 100)
    : (score.privacy_score ?? 0);
  const scoreClass = getScoreColorClass(scoreVal);

  const requestsForSite = isAllSitesScope
    ? applyFilters(feedRequests)
    : feedRequests.filter((r) => (r.initiator_domain || '_direct') === currentSiteDomain);

  let totalRequests;
  let uniqueTrackers;
  let dataVolumeKB;
  if (isAllSitesScope) {
    totalRequests = requestsForSite.length;
    const trackerDomSet = new Set();
    for (const r of requestsForSite) {
      if (r.category !== 'legitimate' && r.category !== 'unclassified' && r.domain) {
        trackerDomSet.add(r.domain);
      }
    }
    uniqueTrackers = trackerDomSet.size;
    let dataVolumeBytes = 0;
    for (const r of requestsForSite) {
      if (r.response_size_bytes != null) dataVolumeBytes += r.response_size_bytes;
    }
    dataVolumeKB = dataVolumeBytes > 0 ? (dataVolumeBytes / 1024).toFixed(1) + ' KB' : '—';
  } else {
    totalRequests = score.total_requests ?? 0;
    uniqueTrackers = score.unique_tracker_domains ?? 0;
    let dataVolumeBytes = 0;
    for (const r of requestsForSite) {
      if (r.response_size_bytes != null) dataVolumeBytes += r.response_size_bytes;
    }
    dataVolumeKB = dataVolumeBytes > 0 ? (dataVolumeBytes / 1024).toFixed(1) + ' KB' : '—';
  }

  // Worst offenders: for site-specific view use the complete stored siteScore arrays
  // (immune to the 200-row feed cap). For all-sites view, scan the capped feedRequests.
  // Each entry: { domain, category, barPct }
  let worstOffenders = [];
  if (!isAllSitesScope && score) {
    const PRIORITY = [
      { key: 'unique_fingerprinting', cat: 'fingerprinting', barPct: 100 },
      { key: 'unique_behavioral',     cat: 'behavioral',     barPct: 80  },
      { key: 'unique_ad_network',     cat: 'ad_network',     barPct: 60  },
      { key: 'unique_analytics',      cat: 'analytics',      barPct: 40  },
    ];
    for (const { key, cat, barPct } of PRIORITY) {
      for (const d of (score[key] || [])) {
        worstOffenders.push({ domain: d, category: cat, barPct });
      }
    }
    if (score.has_session_replay) {
      worstOffenders.unshift({ domain: currentSiteDomain || '(this site)', category: 'session_replay', barPct: 100 });
    }
    worstOffenders = worstOffenders.slice(0, 4);
  } else {
    // All-sites: scan feedRequests (best effort, may be capped)
    const domainByCount = new Map();
    for (const r of requestsForSite) {
      if (r.category === 'legitimate' || r.category === 'unclassified') continue;
      const d = r.domain || '';
      domainByCount.set(d, { count: (domainByCount.get(d)?.count || 0) + 1, category: r.category || 'unclassified' });
    }
    const maxCount = Math.max(1, ...Array.from(domainByCount.values()).map((v) => v.count));
    worstOffenders = Array.from(domainByCount.entries())
      .sort((a, b) => b[1].count - a[1].count)
      .slice(0, 4)
      .map(([domain, { count, category }]) => ({ domain, category, barPct: Math.max(4, (count / maxCount) * 100), count }));
  }

  const categoryCounts = {};
  for (const c of CATEGORIES) categoryCounts[c] = 0;
  for (const r of requestsForSite) {
    const cat = r.category || 'unclassified';
    if (categoryCounts[cat] != null) categoryCounts[cat] += 1;
  }

  const scoreValueEl = document.createElement('span');
  scoreValueEl.className = 'site-summary-score-value ' + scoreClass;
  scoreValueEl.setAttribute('aria-live', 'polite');
  if (lastRenderedScore !== null && lastRenderedScore !== scoreVal) {
    animatePrivacyScore(scoreValueEl, lastRenderedScore, scoreVal, 600);
  } else {
    scoreValueEl.textContent = String(scoreVal);
  }
  lastRenderedScore = scoreVal;

  root.className = 'site-summary-layout';
  root.innerHTML = '';

  const mainCol = document.createElement('div');
  mainCol.className = 'site-summary-main';

  const asideCol = document.createElement('div');
  asideCol.className = 'site-summary-aside';

  const domainEl = document.createElement('h3');
  domainEl.className =
    'site-summary-domain' + (isMaskedSiteDisplayName(domainLabel) ? ' site-summary-domain--masked' : '');
  domainEl.textContent = domainLabel;
  if (!isAllSitesScope && currentSiteDomain) {
    domainEl.setAttribute('title', currentSiteDomain);
  } else {
    domainEl.setAttribute('title', domainLabel);
  }
  mainCol.appendChild(domainEl);

  const scoreBlock = document.createElement('div');
  scoreBlock.className = 'site-summary-score-block';
  scoreBlock.appendChild(scoreValueEl);
  const scoreLabel = document.createElement('div');
  scoreLabel.className = 'site-summary-score-label';
  scoreLabel.textContent = isAllSitesScope
    ? '/100  WORST SITE SCORE (SESSION)'
    : '/100  PRIVACY SCORE';
  scoreBlock.appendChild(scoreLabel);

  const stats = document.createElement('div');
  stats.className = 'site-summary-stats';
  stats.innerHTML =
    '<div class="site-summary-stat-box"><div class="label">TOTAL REQUESTS</div><div class="value">' +
    escapeAttr(String(totalRequests)) +
    '</div></div>' +
    '<div class="site-summary-stat-box"><div class="label">UNIQUE TRACKER DOMAINS</div><div class="value">' +
    escapeAttr(String(uniqueTrackers)) +
    '</div></div>' +
    '<div class="site-summary-stat-box"><div class="label">DATA VOLUME</div><div class="value">' +
    escapeAttr(dataVolumeKB) +
    '</div></div>';

  const kpis = document.createElement('div');
  kpis.className = 'site-summary-kpis';
  kpis.appendChild(scoreBlock);
  kpis.appendChild(stats);
  mainCol.appendChild(kpis);

  const worstWrap = document.createElement('div');
  worstWrap.className = 'site-summary-worst';
  worstWrap.innerHTML = '<div class="site-summary-worst-title">WORST OFFENDERS</div>';
  const worstList = document.createElement('ul');
  worstList.className = 'site-summary-worst-list';
  for (const { domain: dom, category, barPct, count } of worstOffenders) {
    const li = document.createElement('li');
    li.className = 'site-summary-worst-item';
    const barWrap = document.createElement('span');
    barWrap.className = 'site-summary-worst-bar-wrap';
    const bar = document.createElement('span');
    bar.className = 'site-summary-worst-bar';
    bar.style.width = barPct + '%';
    barWrap.appendChild(bar);
    const label = document.createElement('span');
    label.className = 'site-summary-worst-label';
    label.textContent = dom;
    label.setAttribute('title', dom);
    const badge = document.createElement('span');
    badge.className = 'site-summary-worst-badge';
    badge.textContent = count != null
      ? (count + ' request' + (count !== 1 ? 's' : ''))
      : categoryLabel(category);
    li.appendChild(barWrap);
    li.appendChild(label);
    li.appendChild(badge);
    worstList.appendChild(li);
  }
  if (worstOffenders.length === 0) {
    const li = document.createElement('li');
    li.className = 'site-summary-worst-item site-summary-worst-empty';
    li.textContent = 'None';
    worstList.appendChild(li);
  }
  worstWrap.appendChild(worstList);
  mainCol.appendChild(worstWrap);

  const doughnutWrap = document.createElement('div');
  doughnutWrap.className = 'site-summary-doughnut-wrap';
  doughnutWrap.id = 'site-summary-doughnut';
  asideCol.appendChild(doughnutWrap);

  root.appendChild(mainCol);
  root.appendChild(asideCol);

  /* Pass element: querySelector cannot find nodes not yet attached to document. */
  renderDoughnut(doughnutWrap, categoryCounts);

  renderFingerprintingAlerts();
  scheduleTimelineRender();
}

function getCategoryColorVar(cat) {
  const map = {
    behavioral: '--cat-behavioral',
    fingerprinting: '--cat-fingerprint',
    session_replay: '--cat-session-replay',
    ad_network: '--cat-ad-network',
    analytics: '--cat-analytics',
    legitimate: '--cat-legitimate',
    unclassified: '--cat-unclassified',
  };
  return map[cat] || '--cat-unclassified';
}

const DOUGHNUT_MIN_ANGLE = 0.08;

function renderDoughnut(containerOrSelector, dataByCategory) {
  const container =
    typeof containerOrSelector === 'string'
      ? document.querySelector(containerOrSelector)
      : containerOrSelector;
  if (!container) return;
  container.innerHTML = '';
  const total = Object.values(dataByCategory).reduce((a, b) => a + b, 0);
  /* viewBox size; displayed size set in CSS (aside column scales to fit panel) */
  const size = 136;
  const radius = size / 2;
  const innerRadius = radius * 0.55;
  const doc = document.documentElement;
  const getColor = (cat) => {
    const v = getCategoryColorVar(cat);
    return getComputedStyle(doc).getPropertyValue(v).trim() || '#3D5268';
  };
  const borderMuted =
    getComputedStyle(doc).getPropertyValue('--border-default').trim() || '#263040';
  const order = [
    'behavioral',
    'fingerprinting',
    'session_replay',
    'ad_network',
    'analytics',
    'legitimate',
    'unclassified',
  ];
  const rawSegments = [];
  for (const cat of order) {
    const count = dataByCategory[cat] || 0;
    if (count <= 0) continue;
    const angle = (count / total) * 2 * Math.PI;
    rawSegments.push({ category: cat, count, angle, color: getColor(cat) });
  }
  const minAngle = DOUGHNUT_MIN_ANGLE;
  const withMin = rawSegments.map((s) => ({ ...s, angle: Math.max(s.angle, minAngle) }));
  const sumAngles = withMin.reduce((a, s) => a + s.angle, 0);
  const scale = sumAngles > 2 * Math.PI ? (2 * Math.PI) / sumAngles : 1;
  let startAngle = 0;
  const segments = withMin.map((s) => {
    const angle = s.angle * scale;
    const seg = { category: s.category, count: s.count, startAngle, angle, color: s.color };
    startAngle += angle;
    return seg;
  });
  const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
  svg.setAttribute('viewBox', '0 0 ' + size + ' ' + size);
  svg.setAttribute('width', String(size));
  svg.setAttribute('height', String(size));
  svg.setAttribute('preserveAspectRatio', 'xMidYMid meet');
  svg.className = 'site-summary-doughnut-svg';
  svg.setAttribute('role', 'img');
  svg.setAttribute('aria-label', 'Tracker requests by category, total ' + total);
  const g = document.createElementNS('http://www.w3.org/2000/svg', 'g');
  g.setAttribute('transform', 'translate(' + radius + ',' + radius + ')');
  if (segments.length === 0) {
    const ringR = (radius + innerRadius) / 2;
    const ringW = radius - innerRadius;
    const emptyRing = document.createElementNS('http://www.w3.org/2000/svg', 'circle');
    emptyRing.setAttribute('r', String(ringR));
    emptyRing.setAttribute('fill', 'none');
    emptyRing.setAttribute('stroke', borderMuted);
    emptyRing.setAttribute('stroke-width', String(ringW));
    emptyRing.setAttribute('class', 'site-summary-doughnut-empty-ring');
    g.appendChild(emptyRing);
  }
  for (const seg of segments) {
    const path = document.createElementNS('http://www.w3.org/2000/svg', 'path');
    const start = seg.startAngle - Math.PI / 2;
    // Cap at 2π−ε: a perfect full-circle arc has coincident start/end points
    // which SVG treats as a zero-length path (renders nothing).
    const drawAngle = Math.min(seg.angle, 2 * Math.PI - 0.0005);
    const end = start + drawAngle;
    const x0 = radius * Math.cos(start);
    const y0 = radius * Math.sin(start);
    const x1 = radius * Math.cos(end);
    const y1 = radius * Math.sin(end);
    const xi0 = innerRadius * Math.cos(start);
    const yi0 = innerRadius * Math.sin(start);
    const xi1 = innerRadius * Math.cos(end);
    const yi1 = innerRadius * Math.sin(end);
    const large = drawAngle > Math.PI ? 1 : 0;
    const d =
      'M' + x0 + ',' + y0 +
      ' A' + radius + ',' + radius + ' 0 ' + large + ',1 ' + x1 + ',' + y1 +
      ' L' + xi1 + ',' + yi1 +
      ' A' + innerRadius + ',' + innerRadius + ' 0 ' + large + ',0 ' + xi0 + ',' + yi0 + ' Z';
    path.setAttribute('d', d);
    path.setAttribute('fill', seg.color);
    path.setAttribute('opacity', '0.9');
    g.appendChild(path);
  }
  svg.appendChild(g);
  const centerText = document.createElementNS('http://www.w3.org/2000/svg', 'text');
  centerText.setAttribute('x', 0);
  centerText.setAttribute('y', 0);
  centerText.setAttribute('text-anchor', 'middle');
  centerText.setAttribute('dominant-baseline', 'middle');
  centerText.setAttribute('class', 'site-summary-doughnut-center');
  centerText.textContent = String(total);
  g.appendChild(centerText);
  container.appendChild(svg);
  const legend = document.createElement('div');
  legend.className = 'site-summary-doughnut-legend';
  for (const seg of segments) {
    const item = document.createElement('div');
    item.className = 'site-summary-doughnut-legend-item';
    const tip = categoryTooltip(seg.category);
    if (tip) item.setAttribute('data-tooltip', tip);
    const swatch = document.createElement('span');
    swatch.className = 'site-summary-doughnut-legend-swatch';
    swatch.style.background = seg.color;
    item.appendChild(swatch);
    item.appendChild(document.createTextNode(categoryLabel(seg.category) + ' ' + seg.count));
    legend.appendChild(item);
  }
  if (segments.length === 0) {
    const item = document.createElement('div');
    item.className = 'site-summary-doughnut-legend-item';
    item.textContent = 'No tracker requests';
    legend.appendChild(item);
  }
  container.appendChild(legend);
}

/** URL heuristics for fingerprint surface APIs (network-visible script URLs only). */
const FP_SURFACE_SIGNALS = [
  {
    key: 'canvas',
    label: 'Canvas',
    test: (u) =>
      /canvas|html2canvas|fingerprintjs|fpjs|evercookie|cc\.canvas|fingerprint.?pro/i.test(u),
  },
  {
    key: 'webgl',
    label: 'WebGL',
    test: (u) => /webgl|three\.js|three\.min|\/three\/|twigl|babylon\.js|regl\.min/i.test(u),
  },
  {
    key: 'audio',
    label: 'AudioContext',
    test: (u) =>
      /audiocontext|webaudio|audioctx|audio_fingerprint|audiobuffer|oscillator|offlineaudiocontext/i.test(
        u
      ),
  },
  {
    key: 'font',
    label: 'Font Enumeration',
    test: (u) =>
      /font[_-]?enumer|document\.fonts|fontface|font-detect|font_list|fontprobe|fontmetrics/i.test(u),
  },
];

/**
 * Requests initiated by the given site that are plausible carriers for fingerprint-related
 * script URLs (avoids matching "canvas" in HTML page paths, etc.).
 */
function isFingerprintSurfaceCandidateRequest(r, siteDomain) {
  if (!siteDomain || (r.initiator_domain || '_direct') !== siteDomain) return false;
  if (r.category === 'fingerprinting') return true;
  const url = r.url || '';
  const u = url.toLowerCase();
  const ct = (r.content_type || '').toLowerCase();
  const looksLikeScript =
    ct.includes('javascript') ||
    ct.includes('ecmascript') ||
    /\.(js|mjs|wasm)(\?|$|#)/i.test(url);
  if (!looksLikeScript) return false;
  return true;
}

/** All feed rows for fingerprint surface + entropy analysis for the selected summary site. */
function getSiteFingerprintAnalysisRequests(siteDomain) {
  if (!siteDomain) return [];
  return feedRequests.filter((r) => isFingerprintSurfaceCandidateRequest(r, siteDomain));
}

function isGlobalFingerprintSurfaceCandidateRequest(r) {
  if (r.category === 'fingerprinting') return true;
  const url = r.url || '';
  const ct = (r.content_type || '').toLowerCase();
  const looksLikeScript =
    ct.includes('javascript') ||
    ct.includes('ecmascript') ||
    /\.(js|mjs|wasm)(\?|$|#)/i.test(url);
  return looksLikeScript;
}

function getGlobalFingerprintAnalysisRequests() {
  return applyFilters(feedRequests).filter((r) => isGlobalFingerprintSurfaceCandidateRequest(r));
}

function analyzeFingerprintSurfaceSignals(fpRequests) {
  const byKey = {};
  for (const s of FP_SURFACE_SIGNALS) {
    byKey[s.key] = { ok: false, domain: '' };
  }
  for (const r of fpRequests) {
    const u = (r.url || '').toLowerCase();
    const dom = r.domain || '—';
    for (const s of FP_SURFACE_SIGNALS) {
      if (!byKey[s.key].ok && s.test(u)) {
        byKey[s.key] = { ok: true, domain: dom };
      }
    }
  }
  const typesHit = FP_SURFACE_SIGNALS.filter((s) => byKey[s.key].ok).length;
  const uniqDomains = [...new Set(fpRequests.map((r) => r.domain).filter(Boolean))];
  let entropy = Math.min(10, typesHit * 2 + Math.min(5, uniqDomains.length));
  if (typesHit === 0 && uniqDomains.length > 0) {
    entropy = Math.min(10, Math.max(entropy, Math.min(6, uniqDomains.length * 2)));
  }
  return { byKey, typesHit, entropy, uniqDomains };
}

function updateFingerprintDrawerHeaderSite() {
  const el = document.getElementById('fingerprint-drawer-heading');
  if (!el) return;
  if (summarySelectedDomain === SUMMARY_SCOPE_ALL_SITES) {
    el.textContent = 'FINGERPRINTING \u2014 All sites (session)';
    el.classList.remove('fingerprint-drawer-heading--muted');
    return;
  }
  if (!currentSiteDomain || !siteScores[currentSiteDomain]) {
    el.textContent = 'FINGERPRINTING \u2014 \u2014';
    el.classList.add('fingerprint-drawer-heading--muted');
    return;
  }
  const disp = formatSiteDisplayName(currentSiteDomain);
  el.textContent = 'FINGERPRINTING \u2014 ' + disp;
  el.classList.toggle('fingerprint-drawer-heading--muted', isMaskedSiteDisplayName(disp));
}

function entropyTierInfo(entropy) {
  const n = Math.max(0, Math.min(10, Number(entropy) || 0));
  if (n >= 7) return { label: 'HIGH RISK', colorCls: 'entropy-value--high', barCls: 'fp-risk-bar--high' };
  if (n >= 4) return { label: 'MODERATE',  colorCls: 'entropy-value--mid',  barCls: 'fp-risk-bar--mid' };
  return          { label: 'LOW RISK',   colorCls: 'entropy-value--low',  barCls: 'fp-risk-bar--low' };
}

function setEntropyTierDisplay(entropy) {
  // No-op: entropy display is now fully rendered by renderFingerprintingAlerts.
}

function renderFingerprintingAlerts() {
  const rowsRoot = document.getElementById('fingerprint-signal-rows');
  if (!rowsRoot) return;

  updateFingerprintDrawerHeaderSite();
  rowsRoot.textContent = '';

  const noSession = !currentSession || !currentSession.active;

  // Empty state: no session running yet
  if (noSession && feedRequests.length === 0) {
    const empty = document.createElement('div');
    empty.className = 'fingerprint-panel-empty';
    empty.innerHTML =
      '<svg class="fingerprint-panel-empty-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" aria-hidden="true">' +
      '<path stroke-linecap="round" stroke-linejoin="round" d="M12 2C6.48 2 2 6.48 2 12s4.48 10 10 10 10-4.48 10-10S17.52 2 12 2z"/>' +
      '<path stroke-linecap="round" stroke-linejoin="round" d="M12 8v4m0 4h.01" />' +
      '</svg>' +
      '<span class="fingerprint-panel-empty-title">No fingerprinting data</span>' +
      '<span class="fingerprint-panel-empty-hint">Start a session and browse to detect fingerprinting signals.</span>';
    rowsRoot.appendChild(empty);
    return;
  }

  let fpRequests;
  if (summarySelectedDomain === SUMMARY_SCOPE_ALL_SITES) {
    fpRequests = getGlobalFingerprintAnalysisRequests();
  } else if (currentSiteDomain && siteScores[currentSiteDomain]) {
    fpRequests = getSiteFingerprintAnalysisRequests(currentSiteDomain);
  } else {
    fpRequests = [];
  }

  const { byKey, entropy } = analyzeFingerprintSurfaceSignals(fpRequests);
  const tier = entropyTierInfo(entropy);
  const detected = FP_SURFACE_SIGNALS.filter((s) => byKey[s.key].ok);
  const notDetected = FP_SURFACE_SIGNALS.filter((s) => !byKey[s.key].ok);
  const barPct = Math.round((entropy / 10) * 100);

  // --- Risk summary row ---
  const riskRow = document.createElement('div');
  riskRow.className = 'fp-risk-row';
  riskRow.setAttribute('aria-live', 'polite');
  riskRow.innerHTML =
    '<div class="fp-risk-score">' +
    '<span class="fp-risk-number ' + tier.colorCls + '">' + entropy + '</span>' +
    '<span class="fp-risk-denom">/10</span>' +
    '</div>' +
    '<div class="fp-risk-meta">' +
    '<span class="fp-risk-tier ' + tier.colorCls + '">' + tier.label + '</span>' +
    '<div class="fp-risk-bar-track" aria-hidden="true">' +
    '<div class="fp-risk-bar ' + tier.barCls + '" style="width:' + barPct + '%"></div>' +
    '</div>' +
    '<span class="fp-risk-count">' + detected.length + ' / ' + FP_SURFACE_SIGNALS.length + ' APIs detected</span>' +
    '</div>';
  rowsRoot.appendChild(riskRow);

  // --- Divider ---
  const divider = document.createElement('div');
  divider.className = 'fp-signals-divider';
  rowsRoot.appendChild(divider);

  // --- Detected signals (full rows) ---
  if (detected.length > 0) {
    const detectedGroup = document.createElement('div');
    detectedGroup.className = 'fingerprint-signal-group';
    const groupLabel = document.createElement('span');
    groupLabel.className = 'fingerprint-signal-group-label fingerprint-signal-group-label--detected';
    groupLabel.textContent = 'DETECTED (' + detected.length + ')';
    detectedGroup.appendChild(groupLabel);
    for (const s of detected) {
      const { domain } = byKey[s.key];
      detectedGroup.appendChild(buildFingerprintSignalRow(s.label, true, domain));
    }
    rowsRoot.appendChild(detectedGroup);
  }

  // --- Not detected signals (compact 2-column grid) ---
  if (notDetected.length > 0) {
    const notGroup = document.createElement('div');
    notGroup.className = 'fingerprint-signal-group';
    const groupLabel = document.createElement('span');
    groupLabel.className = 'fingerprint-signal-group-label fingerprint-signal-group-label--clear';
    groupLabel.textContent = 'NOT DETECTED (' + notDetected.length + ')';
    notGroup.appendChild(groupLabel);
    const grid = document.createElement('div');
    grid.className = 'fingerprint-signal-grid';
    for (const s of notDetected) {
      const cell = document.createElement('div');
      cell.className = 'fingerprint-signal-grid-cell';
      cell.innerHTML =
        '<span class="fingerprint-signal-indicator" aria-hidden="true" style="color:var(--text-ghost)">○</span>' +
        '<span class="fingerprint-signal-label" style="color:var(--text-muted);font-weight:400">' + escapeHtml(s.label) + '</span>';
      grid.appendChild(cell);
    }
    notGroup.appendChild(grid);
    rowsRoot.appendChild(notGroup);
  }
}

function buildFingerprintSignalRow(label, ok, domain) {
  const row = document.createElement('div');
  row.className = 'fingerprint-signal-row' + (ok ? ' fingerprint-signal-row--ok' : ' fingerprint-signal-row--no');

  const indicator = document.createElement('span');
  indicator.className = 'fingerprint-signal-indicator';
  indicator.setAttribute('aria-hidden', 'true');
  indicator.textContent = ok ? '●' : '○';

  const lab = document.createElement('span');
  lab.className = 'fingerprint-signal-label';
  lab.textContent = label;

  const right = document.createElement('span');
  right.className = 'fingerprint-signal-right';

  if (ok && domain != null && domain !== '') {
    const dom = document.createElement('span');
    const fd = formatSiteDisplayName(domain);
    dom.className =
      'fingerprint-signal-domain fingerprint-signal-domain--ok' +
      (isMaskedSiteDisplayName(fd) ? ' fingerprint-signal-domain--masked' : '');
    dom.textContent = fd;
    dom.setAttribute('data-tooltip', String(domain));
    right.appendChild(dom);
  } else if (ok) {
    const chip = document.createElement('span');
    chip.className = 'fingerprint-signal-chip fingerprint-signal-chip--ok';
    chip.textContent = 'DETECTED';
    right.appendChild(chip);
  }

  row.appendChild(indicator);
  row.appendChild(lab);
  row.appendChild(right);
  return row;
}

/** When true, bottom zone shows fingerprinting panel (timeline hidden). */
let fingerprintDrawerOpen = false;

function updateBottomViewToggleLabel() {
  const btn = document.getElementById('bottom-view-toggle');
  const toolbarTitle = document.getElementById('dashboard-bottom-toolbar-title');
  if (btn) {
    btn.textContent = fingerprintDrawerOpen ? '\u25bc CLOSE' : '\u25b2 FINGERPRINTING';
    btn.setAttribute('aria-expanded', fingerprintDrawerOpen ? 'true' : 'false');
    btn.classList.toggle('bottom-view-toggle--active', fingerprintDrawerOpen);
  }
  if (toolbarTitle) {
    toolbarTitle.textContent = fingerprintDrawerOpen ? 'FINGERPRINTING' : 'TIMELINE';
  }
}

function setFingerprintDrawerOpen(open) {
  fingerprintDrawerOpen = !!open;
  updateBottomViewToggleLabel();
  const stack = document.getElementById('dashboard-bottom-stack');
  const drawer = document.getElementById('fingerprint-drawer');
  const tlLayer = document.getElementById('dashboard-timeline-layer');
  if (stack) stack.setAttribute('data-view', fingerprintDrawerOpen ? 'fingerprint' : 'timeline');
  if (drawer) {
    drawer.setAttribute('aria-hidden', fingerprintDrawerOpen ? 'false' : 'true');
  }
  if (tlLayer) {
    tlLayer.setAttribute('aria-hidden', fingerprintDrawerOpen ? 'true' : 'false');
  }
  if (fingerprintDrawerOpen) {
    updateFingerprintDrawerHeaderSite();
    renderFingerprintingAlerts();
  }
  requestAnimationFrame(() => scheduleTimelineRender());
}

function setupFingerprintDrawer() {
  const toggle = document.getElementById('bottom-view-toggle');
  const closeBtn = document.getElementById('fingerprint-drawer-close');
  if (toggle) {
    toggle.addEventListener('click', (e) => {
      e.stopPropagation();
      const next = !fingerprintDrawerOpen;
      fingerprintDrawerOpen = next;
      updateBottomViewToggleLabel();
      const stack = document.getElementById('dashboard-bottom-stack');
      const drawer = document.getElementById('fingerprint-drawer');
      const tlLayer = document.getElementById('dashboard-timeline-layer');
      if (stack) stack.setAttribute('data-view', next ? 'fingerprint' : 'timeline');
      if (drawer) drawer.setAttribute('aria-hidden', next ? 'false' : 'true');
      if (tlLayer) tlLayer.setAttribute('aria-hidden', next ? 'true' : 'false');
      if (next) {
        updateFingerprintDrawerHeaderSite();
        renderFingerprintingAlerts();
      }
      requestAnimationFrame(() => scheduleTimelineRender());
    });
  }
  if (closeBtn) {
    closeBtn.addEventListener('click', () => setFingerprintDrawerOpen(false));
  }
}

function buildSiteSummaryDropdown(container) {
  container.textContent = '';
  const domains = Object.entries(siteScores)
    .filter(([, s]) => s && (s.privacy_score != null || s.total_requests != null))
    .sort((a, b) => (a[1].privacy_score ?? 100) - (b[1].privacy_score ?? 100));
  const worstDomain = domains.length > 0 ? domains[0][0] : null;
  let displayLabel;
  if (summarySelectedDomain === SUMMARY_SCOPE_ALL_SITES) {
    displayLabel = 'All sites';
  } else if (currentSiteDomain == null || currentSiteDomain === '') {
    displayLabel = 'Worst site';
  } else {
    displayLabel = formatSiteDisplayName(currentSiteDomain);
  }
  const isAllSitesSelected = summarySelectedDomain === SUMMARY_SCOPE_ALL_SITES;
  const isWorstSelected =
    summarySelectedDomain == null || summarySelectedDomain === '';

  const wrap = document.createElement('div');
  wrap.className = 'feed-filter-dropdown site-summary-dropdown';
  wrap.setAttribute('data-open', 'false');
  wrap.id = 'site-summary-dropdown';

  const trigger = document.createElement('button');
  trigger.type = 'button';
  trigger.className = 'feed-filter-dropdown-trigger site-summary-dropdown-trigger';
  trigger.setAttribute('aria-haspopup', 'listbox');
  trigger.setAttribute('aria-expanded', 'false');
  trigger.id = 'site-summary-dropdown-trigger';
  trigger.innerHTML =
    '<span class="feed-filter-dropdown-label" id="site-summary-dropdown-label">SITE: ' +
    escapeAttr(displayLabel) +
    '</span><span class="feed-filter-dropdown-chevron" aria-hidden="true">▼</span>';

  const panel = document.createElement('div');
  panel.className = 'feed-filter-dropdown-panel';
  panel.setAttribute('role', 'listbox');

  const allSitesOpt = document.createElement('div');
  allSitesOpt.className =
    'feed-filter-dropdown-option' + (isAllSitesSelected ? ' is-selected' : '');
  allSitesOpt.setAttribute('role', 'option');
  allSitesOpt.setAttribute('data-value', SUMMARY_SCOPE_ALL_SITES);
  allSitesOpt.textContent = 'All sites (session)';
  allSitesOpt.addEventListener('click', () => {
    summarySelectedDomain = SUMMARY_SCOPE_ALL_SITES;
    summaryAutoSelected = false;
    setOpen(false);
    renderSiteSummary();
  });
  panel.appendChild(allSitesOpt);

  const worstOpt = document.createElement('div');
  worstOpt.className =
    'feed-filter-dropdown-option' + (!isAllSitesSelected && isWorstSelected ? ' is-selected' : '');
  worstOpt.setAttribute('role', 'option');
  worstOpt.setAttribute('data-value', '');
  worstOpt.textContent = worstDomain
    ? 'Worst site (' + formatSiteDisplayName(worstDomain) + ')'
    : 'Worst site';
  worstOpt.addEventListener('click', () => {
    summarySelectedDomain = null;
    summaryAutoSelected = false;
    setOpen(false);
    renderSiteSummary();
  });
  panel.appendChild(worstOpt);
  domains.forEach(([domain]) => {
    if (domain === SUMMARY_SCOPE_ALL_SITES) return;
    const opt = document.createElement('div');
    opt.className =
      'feed-filter-dropdown-option' +
      (!isAllSitesSelected && summarySelectedDomain === domain ? ' is-selected' : '');
    opt.setAttribute('role', 'option');
    opt.setAttribute('data-value', domain);
    opt.textContent = formatSiteDisplayName(domain);
    opt.addEventListener('click', () => {
      summarySelectedDomain = domain;
      summaryAutoSelected = false;
      setOpen(false);
      renderSiteSummary();
    });
    panel.appendChild(opt);
  });

  function setOpen(open) {
    wrap.setAttribute('data-open', open ? 'true' : 'false');
    trigger.setAttribute('aria-expanded', String(open));
    panel.classList.toggle('is-open', open);
  }

  trigger.addEventListener('click', (e) => {
    e.stopPropagation();
    setOpen(!panel.classList.contains('is-open'));
  });

  document.addEventListener('click', (e) => {
    if (!wrap.contains(e.target)) setOpen(false);
  });

  wrap.appendChild(trigger);
  wrap.appendChild(panel);
  container.appendChild(wrap);
}

function refreshSiteSummary() {
  if (summarySelectedDomain === SUMMARY_SCOPE_ALL_SITES) {
    currentSiteDomain = null;
    renderSiteSummary();
    return;
  }
  getCurrentSiteDomain((domain) => {
    currentSiteDomain = domain;
    renderSiteSummary();
  });
}

function updateStatus(text) {
  const header = document.querySelector('.dashboard-nav');
  let el = document.getElementById('specter-dashboard-status');
  if (!el) {
    el = document.createElement('span');
    el.id = 'specter-dashboard-status';
    el.className = 'dashboard-status';
    el.setAttribute('aria-live', 'polite');
    header.appendChild(el);
  }
  el.textContent = text;
}

function getPathFromUrl(url) {
  try {
    const u = new URL(url);
    return u.pathname + u.search;
  } catch {
    return null;
  }
}

function truncatePath(path, maxLen = 60) {
  if (!path) return '—';
  return path.length <= maxLen ? path : path.slice(0, maxLen - 1) + '…';
}

function escapeAttr(s) {
  if (s == null) return '';
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/"/g, '&quot;')
    .replace(/</g, '&lt;');
}

function applyFilters(requests) {
  return requests.filter((r) => {
    if (filterState.categories.size > 0 && !filterState.categories.has(r.category)) return false;
    if (filterState.tabFilter === 'current' && currentTabId != null && r.tab_id !== currentTabId) return false;
    const conf = (r.confidence ?? 0) * 100;
    if (conf < filterState.minConfidence) return false;
    if (filterState.domainSearch.trim()) {
      const q = filterState.domainSearch.trim().toLowerCase();
      if (!(r.domain && r.domain.toLowerCase().includes(q)) && !(r.url && r.url.toLowerCase().includes(q))) return false;
    }
    return true;
  });
}

/** Timeline: session-wide only when "All sites" is selected; otherwise current summary site (or worst site). */
function getTimelineRequests() {
  const filtered = applyFilters(feedRequests);
  if (summarySelectedDomain === SUMMARY_SCOPE_ALL_SITES) return filtered;
  const site = getSummaryTimelineSiteKey();
  if (!site) return [];
  return filtered.filter((r) => (r.initiator_domain || '_direct') === site);
}

const TIMELINE_CAT_CSS = {
  behavioral: '--cat-behavioral',
  fingerprinting: '--cat-fingerprint',
  session_replay: '--cat-session-replay',
  ad_network: '--cat-ad-network',
  analytics: '--cat-analytics',
  legitimate: '--cat-legitimate',
  unclassified: '--cat-unclassified',
};

function getCategoryColorHex(cat) {
  const prop = TIMELINE_CAT_CSS[cat] || '--cat-unclassified';
  const s = getComputedStyle(document.documentElement).getPropertyValue(prop).trim();
  return s || '#888888';
}

let timelineRaf = null;
let timelineResizeObserver = null;

function scheduleTimelineRender() {
  if (typeof d3 === 'undefined') return;
  if (timelineRaf) cancelAnimationFrame(timelineRaf);
  timelineRaf = requestAnimationFrame(() => {
    timelineRaf = null;
    renderTimeline();
  });
}

function formatTimelineClock(ms) {
  const d = new Date(ms);
  return d.toLocaleTimeString(undefined, {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false,
  });
}

function timelineFindBinIndex(dataForStack, tMs) {
  for (let i = 0; i < dataForStack.length; i++) {
    const b = dataForStack[i];
    if (tMs >= b.x0 && tMs <= b.x1) return i;
  }
  let best = 0;
  let bestD = Infinity;
  for (let i = 0; i < dataForStack.length; i++) {
    const mid = (dataForStack[i].x0 + dataForStack[i].x1) / 2;
    const d = Math.abs(mid - tMs);
    if (d < bestD) {
      bestD = d;
      best = i;
    }
  }
  return best;
}

/** Hover + tooltip for timeline chart (transparent rect on top of chart). */
function bindTimelinePointerInteractions(g, innerW, innerH, x, dataForStack, stackKeys) {
  if (typeof d3 === 'undefined' || innerW < 2 || innerH < 2) return;
  const tooltipEl = document.getElementById('specter-tooltip');
  const crosshair = g
    .append('line')
    .attr('class', 'timeline-crosshair')
    .attr('y1', 0)
    .attr('y2', innerH)
    .attr('stroke', 'var(--border-strong)')
    .attr('stroke-width', 1)
    .style('opacity', 0)
    .style('pointer-events', 'none');

  const overlay = g
    .append('rect')
    .attr('width', innerW)
    .attr('height', innerH)
    .attr('fill', 'transparent')
    .style('cursor', 'crosshair')
    .style('pointer-events', 'all');

  overlay.on('mousemove', function (event) {
    const [mx] = d3.pointer(event);
    const tDate = x.invert(mx);
    const tMs = tDate.getTime();
    const idx = timelineFindBinIndex(dataForStack, tMs);
    const bin = dataForStack[idx];
    const cx = x(new Date((bin.x0 + bin.x1) / 2));
    crosshair.attr('x1', cx).attr('x2', cx).style('opacity', 1);

    if (tooltipEl) {
      const lines = [formatTimelineClock(bin.x0) + ' – ' + formatTimelineClock(bin.x1)];
      let any = false;
      for (const k of stackKeys) {
        const n = bin[k] || 0;
        if (n > 0) {
          lines.push(categoryLabel(k) + ': ' + n);
          any = true;
        }
      }
      if (!any) lines.push('No tracker events in this interval.');
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
  });

  overlay.on('mouseleave', function () {
    crosshair.style('opacity', 0);
    if (tooltipEl) {
      tooltipEl.classList.remove('is-visible');
      tooltipEl.setAttribute('aria-hidden', 'true');
    }
  });
}

function renderTimeline() {
  const root = document.getElementById('timeline-root');
  if (!root) return;

  if (typeof d3 === 'undefined') {
    root.innerHTML =
      '<p class="timeline-empty">Run <code>npm run bundle-libs</code> for the timeline.</p>';
    return;
  }

  const requests = getTimelineRequests();
  root.textContent = '';

  if (requests.length === 0) {
    const wrap = document.createElement('div');
    wrap.className = 'timeline-empty-state';
    const globalTimeline = summarySelectedDomain === SUMMARY_SCOPE_ALL_SITES;
    const anyFiltered = applyFilters(feedRequests).length > 0;
    let msg;
    if (feedRequests.length === 0) {
      msg = 'Start a session and browse to see the request timeline.';
    } else if (!globalTimeline && anyFiltered) {
      msg = 'No requests for the selected site match the current filters.';
    } else {
      msg = 'No requests match the current filters.';
    }
    wrap.innerHTML =
      '<svg class="timeline-empty-icon" viewBox="0 0 32 24" fill="none" stroke="currentColor" stroke-width="1.2" aria-hidden="true">' +
      '<rect x="1" y="14" width="5" height="9" rx="1"/>' +
      '<rect x="9" y="9" width="5" height="14" rx="1" opacity="0.6"/>' +
      '<rect x="17" y="5" width="5" height="18" rx="1" opacity="0.35"/>' +
      '<rect x="25" y="11" width="5" height="12" rx="1" opacity="0.5"/>' +
      '</svg>' +
      '<span class="timeline-empty-text">' + msg + '</span>';
    root.appendChild(wrap);
    return;
  }

  const times = requests.map((r) => r.captured_at).filter((t) => t != null && !Number.isNaN(t));
  if (times.length === 0) {
    const wrap = document.createElement('div');
    wrap.className = 'timeline-empty-state';
    wrap.innerHTML = '<span class="timeline-empty-text">No timing data for filtered requests.</span>';
    root.appendChild(wrap);
    return;
  }

  let tMin = d3.min(times);
  let tMax = d3.max(times);
  if (tMin === tMax) {
    tMin -= 800;
    tMax += 800;
  }

  const tlLayer = document.getElementById('dashboard-timeline-layer');
  const bottomStack = document.getElementById('dashboard-bottom-stack');
  let zoneMax = 260;
  if (bottomStack) {
    const raw = getComputedStyle(bottomStack).getPropertyValue('--bottom-zone-height').trim();
    const n = parseInt(raw, 10);
    if (!Number.isNaN(n) && n > 0) zoneMax = n;
  }

  // Reserve 20px at bottom for the category legend
  const legendH = 20;
  const boxW = Math.max(root.clientWidth || 0, tlLayer ? tlLayer.clientWidth : 0, 240);
  const boxH = Math.max(root.clientHeight || 0, tlLayer ? tlLayer.clientHeight : 0, 120);
  const margin = { top: 6, right: 12, bottom: 24, left: 34 };
  const width = Math.max(240, boxW);
  const height = Math.max(100, Math.min(zoneMax, boxH) - legendH);
  const innerW = Math.max(1, width - margin.left - margin.right);
  const innerH = Math.max(1, height - margin.top - margin.bottom);

  const binCount = Math.min(52, Math.max(12, Math.floor(innerW / 18)));
  const binGen = d3
    .bin()
    .domain([tMin, tMax])
    .thresholds(binCount)
    .value((d) => d.captured_at);
  const bins = binGen(requests);

  const stackKeys = CATEGORIES.slice();
  const dataForStack = bins.map((bin) => {
    const row = { x0: bin.x0, x1: bin.x1 };
    for (const k of stackKeys) row[k] = 0;
    for (const r of bin) {
      const c = r.category || 'unclassified';
      if (row[c] != null) row[c] += 1;
      else row.unclassified += 1;
    }
    return row;
  });

  const stackedLayers = d3.stack().keys(stackKeys)(dataForStack);
  const maxY = d3.max(stackedLayers, (lyr) => d3.max(lyr, (d) => d[1])) || 1;

  const x = d3
    .scaleTime()
    .domain([new Date(tMin), new Date(tMax)])
    .range([0, innerW]);
  const y = d3
    .scaleLinear()
    .domain([0, maxY])
    .nice()
    .range([innerH, 0]);

  const svg = d3
    .select(root)
    .append('svg')
    .attr('width', width)
    .attr('height', height)
    .attr('class', 'timeline-svg')
    .attr('role', 'img')
    .attr('aria-label', 'Stacked bar chart of tracker requests over time.');

  const g = svg.append('g').attr('transform', 'translate(' + margin.left + ',' + margin.top + ')');

  // Horizontal grid lines (integer count ticks only)
  const yTicks = y.ticks(4).filter((t) => Number.isInteger(t));
  const gridG = g.append('g').attr('class', 'timeline-grid').attr('pointer-events', 'none');
  gridG
    .selectAll('line')
    .data(yTicks)
    .enter()
    .append('line')
    .attr('x1', 0)
    .attr('x2', innerW)
    .attr('y1', (d) => y(d))
    .attr('y2', (d) => y(d))
    .attr('stroke', 'var(--border-subtle)')
    .attr('stroke-width', 1);

  // Stacked bars (rects) — cleaner than area paths
  const barGap = binCount > 30 ? 0 : 1;
  stackedLayers.forEach((lyr) => {
    const cat = lyr.key;
    const baseHex = getCategoryColorHex(cat);
    const col = d3.color(baseHex);
    if (col) col.opacity = 0.8;
    const fill = col ? col.formatRgb() : baseHex;
    g.selectAll(null)
      .data(lyr)
      .enter()
      .append('rect')
      .attr('class', 'timeline-bar')
      .attr('x', (d) => x(new Date(d.data.x0)) + barGap)
      .attr('width', (d) => Math.max(0, x(new Date(d.data.x1)) - x(new Date(d.data.x0)) - barGap * 2))
      .attr('y', (d) => y(d[1]))
      .attr('height', (d) => Math.max(0, y(d[0]) - y(d[1])))
      .attr('fill', fill)
      .attr('pointer-events', 'none');
  });

  // Session start marker (line only — no text label cluttering the chart)
  if (sessionStartTime != null && sessionStartTime >= tMin && sessionStartTime <= tMax) {
    const xS = x(new Date(sessionStartTime));
    g.append('line')
      .attr('x1', xS).attr('x2', xS)
      .attr('y1', 0).attr('y2', innerH)
      .attr('stroke', 'var(--text-ghost)')
      .attr('stroke-dasharray', '3 3')
      .attr('stroke-width', 1)
      .attr('pointer-events', 'none');
  }

  // X axis (time labels)
  const tf = d3.timeFormat('%H:%M:%S');
  const axisX = g
    .append('g')
    .attr('transform', 'translate(0,' + innerH + ')')
    .attr('class', 'timeline-axis-x')
    .call(d3.axisBottom(x).ticks(Math.min(5, binCount)).tickFormat(tf).tickSize(3));
  axisX.selectAll('text')
    .attr('fill', 'var(--text-muted)')
    .style('font-family', 'var(--font-mono)')
    .style('font-size', '10px');
  axisX.select('.domain').attr('stroke', 'var(--border-default)');
  axisX.selectAll('.tick line').attr('stroke', 'var(--border-default)');
  axisX.attr('pointer-events', 'none');

  // Y axis (request counts — integers only)
  const axisY = g.append('g').attr('class', 'timeline-axis-y')
    .call(d3.axisLeft(y).tickValues(yTicks).tickFormat(d3.format('d')).tickSize(3));
  axisY.selectAll('text')
    .attr('fill', 'var(--text-muted)')
    .style('font-family', 'var(--font-mono)')
    .style('font-size', '10px');
  axisY.select('.domain').attr('stroke', 'var(--border-default)');
  axisY.selectAll('.tick line').attr('stroke', 'var(--border-default)');
  axisY.attr('pointer-events', 'none');

  bindTimelinePointerInteractions(g, innerW, innerH, x, dataForStack, stackKeys);

  // Category legend — only show categories that have at least one request
  const activeCats = stackKeys.filter((k) => dataForStack.some((row) => row[k] > 0));
  if (activeCats.length > 0) {
    const legend = document.createElement('div');
    legend.className = 'timeline-legend';
    activeCats.forEach((cat) => {
      const item = document.createElement('span');
      item.className = 'timeline-legend-item';
      const swatch = document.createElement('span');
      swatch.className = 'timeline-legend-swatch';
      swatch.style.background = getCategoryColorHex(cat);
      const label = document.createElement('span');
      label.className = 'timeline-legend-label';
      label.textContent = categoryLabel(cat);
      item.appendChild(swatch);
      item.appendChild(label);
      legend.appendChild(item);
    });
    root.appendChild(legend);
  }
}

function initTimelineResizeObserver() {
  const root = document.getElementById('timeline-root');
  const layer = document.getElementById('dashboard-timeline-layer');
  if ((!root && !layer) || typeof ResizeObserver === 'undefined') return;
  if (timelineResizeObserver) timelineResizeObserver.disconnect();
  timelineResizeObserver = new ResizeObserver(() => scheduleTimelineRender());
  if (root) timelineResizeObserver.observe(root);
  if (layer) timelineResizeObserver.observe(layer);
}

function groupByDomainCategory(requests) {
  const map = new Map();
  for (const r of requests) {
    const key = (r.domain || '') + '\0' + (r.category || '');
    if (!map.has(key)) {
      map.set(key, { domain: r.domain, category: r.category, requests: [], id: r.id });
    }
    const g = map.get(key);
    g.requests.push(r);
    g.id = r.id;
  }
  return Array.from(map.values());
}

function trimFeedToCap() {
  if (feedRequests.length > FEED_CAP) {
    feedRequests = feedRequests.slice(-FEED_CAP);
  }
}

function updateTimerDisplay() {
  const el = document.getElementById('feed-header-timer');
  if (!el) return;
  if (!sessionStartTime) {
    el.textContent = '00:00';
    return;
  }
  const sec = Math.floor((Date.now() - sessionStartTime) / 1000);
  const m = Math.floor(sec / 60);
  const s = sec % 60;
  el.textContent = String(m).padStart(2, '0') + ':' + String(s).padStart(2, '0');
}

function startSessionTimer() {
  sessionStartTime = sessionStartTime || Date.now();
  if (timerInterval) clearInterval(timerInterval);
  timerInterval = setInterval(updateTimerDisplay, 1000);
  updateTimerDisplay();
}

function stopSessionTimer() {
  if (timerInterval) {
    clearInterval(timerInterval);
    timerInterval = null;
  }
}

function updateFeedHeaderDot() {
  const dot = document.getElementById('feed-header-dot');
  if (!dot) return;
  const active = currentSession && currentSession.active;
  dot.classList.toggle('pulse', active && !feedPaused);
  dot.classList.toggle('paused', !active);
  dot.classList.toggle('paused-active', active && feedPaused);
}

function updatePauseButton() {
  const btn = document.getElementById('pause-btn');
  if (!btn) return;
  const running = currentSession && currentSession.active;
  if (!running) {
    btn.style.display = 'none';
    return;
  }
  btn.style.display = '';
  if (feedPaused) {
    btn.textContent = '▶ RESUME';
    btn.classList.remove('running');
    btn.classList.add('paused');
    btn.setAttribute('aria-label', 'Resume feed');
  } else {
    btn.textContent = '⏸ PAUSE';
    btn.classList.remove('paused');
    btn.classList.add('running');
    btn.setAttribute('aria-label', 'Pause feed');
  }
}

function updateSessionButton(running) {
  const btn = document.getElementById('session-btn');
  if (!btn) return;
  if (running) {
    btn.textContent = '■ END SESSION';
    btn.classList.remove('stopped');
    btn.classList.add('running');
  } else {
    btn.textContent = '▶ NEW SESSION';
    btn.classList.remove('running');
    btn.classList.add('stopped');
  }
  updatePauseButton();
}

function renderFeedRows(filtered, animateLast) {
  const list = document.getElementById('feed-list');
  if (!list) return;
  list.textContent = '';
  const collapse = filterState.collapseDuplicates;
  let itemsToRender;
  if (collapse) {
    const groups = groupByDomainCategory(filtered);
    itemsToRender = groups.slice().reverse().slice(0, FEED_CAP);
  } else {
    itemsToRender = filtered.slice().reverse().slice(0, FEED_CAP);
  }
  const fragment = document.createDocumentFragment();
  itemsToRender.forEach((item, i) => {
    const isGroup = collapse && item.requests;
    const req = isGroup ? item.requests[0] : item;
    const g = isGroup ? item : { id: req.id, requests: [req] };
    const isNew = animateLast && i === 0;
    const conf = (req.confidence ?? 0);
    const confClass = conf >= 0.8 ? ' feed-row--high-conf' : conf < 0.35 ? ' feed-row--low-conf' : '';
    const row = document.createElement('div');
    row.className = 'feed-row' + (g.id === selectedRequestId ? ' feed-row--selected' : '') + confClass + (isNew ? ' feed-row-enter' : '');
    row.setAttribute('data-request-id', g.id);
    row.setAttribute('role', 'button');
    row.setAttribute('tabindex', '0');

    const confPct = (conf * 100).toFixed(0);
    const badgeClass = categoryToBadgeClass(req.category);
    const count = g.requests.length | 0;
    const key = (req.domain || '') + '\0' + (req.category || '');
    const prevCount = lastGroupCounts.get(key) || 0;
    /* Size: single value or sum for collapsed group; show KB or MB */
    let sizeStr = '—';
    if (g.requests.length > 0) {
      const sizes = g.requests.map((x) => x.response_size_bytes).filter((x) => x != null);
      if (sizes.length > 0) {
        const totalBytes = sizes.reduce((a, b) => a + b, 0);
        if (totalBytes >= 1024 * 1024) {
          sizeStr = (totalBytes / (1024 * 1024)).toFixed(1) + ' MB';
        } else {
          sizeStr = (totalBytes / 1024).toFixed(1) + ' KB';
        }
      }
    }
    const doFlash = count > 1 && count > prevCount;
    if (count > 1) lastGroupCounts.set(key, count);
    const countClass = doFlash ? ' feed-row-count flash' : ' feed-row-count';
    const countHtml = count > 1 ? '<span class="' + countClass.trim() + '">×' + count + '</span>' : '';

    const uniquePaths = [];
    const pathSet = new Set();
    for (const r of g.requests) {
      const p = getPathFromUrl(r.url);
      if (p != null && p !== '' && !pathSet.has(p)) {
        pathSet.add(p);
        uniquePaths.push(p);
      }
    }
    let urlDisplay;
    let urlFull;
    let urlCellClass = '';
    if (uniquePaths.length === 0) {
      urlDisplay = '—';
      urlFull = '';
    } else if (uniquePaths.length === 1) {
      urlDisplay = truncatePath(uniquePaths[0], 40);
      urlFull = uniquePaths[0];
    } else {
      urlDisplay = uniquePaths.length + ' paths';
      urlFull = uniquePaths.join('\n');
      urlCellClass = ' feed-cell-url--multiple';
    }

    const badgeTip = categoryTooltip(req.category) || (categoryLabel(req.category) + ' — category');
    const groupKey = (req.domain || '') + '\0' + (req.category || '');
    const isExpanded = isGroup && count > 1 && expandedGroups.has(groupKey);
    const expandBtnHtml = isGroup && count > 1
      ? '<button type="button" class="feed-row-expand-btn" aria-label="' + (isExpanded ? 'Collapse' : 'Expand') + ' group" data-group-key="' + escapeAttr(groupKey) + '">' + (isExpanded ? '▼' : '▶') + '</button>'
      : '';
    row.innerHTML =
      '<span class="feed-cell feed-cell-badge"><span class="feed-badge ' +
      badgeClass +
      '" data-tooltip="' +
      escapeAttr(badgeTip) +
      '"><span class="feed-badge-dot"></span>' +
      escapeAttr(categoryLabel(req.category)) +
      '</span></span>' +
      '<span class="feed-cell feed-cell-domain"' + (req.domain ? ' data-tooltip="' + escapeAttr(req.domain) + '"' : '') + '>' +
      escapeAttr(req.domain || '—') +
      countHtml +
      expandBtnHtml +
      '</span>' +
      '<span class="feed-cell feed-cell-url' + urlCellClass + '"' + (urlFull ? ' data-tooltip="' + escapeAttr(urlFull) + '"' : '') + '>' +
      escapeAttr(urlDisplay) +
      '</span>' +
      '<span class="feed-cell feed-cell-conf">' +
      confPct +
      '%</span>' +
      '<span class="feed-cell feed-cell-size">' +
      sizeStr +
      '</span>';

    if (doFlash) {
      const countEl = row.querySelector('.feed-row-count');
      if (countEl) setTimeout(() => countEl.classList.remove('flash'), 300);
    }
    row.addEventListener('click', () => selectRequest(g.id));
    row.addEventListener('keydown', (e) => {
      if (e.key === 'Enter' || e.key === ' ') {
        e.preventDefault();
        selectRequest(g.id);
      }
    });

    // Expand/collapse button — stop propagation so it doesn't also select the row
    const expandBtn = row.querySelector('.feed-row-expand-btn');
    if (expandBtn) {
      expandBtn.addEventListener('click', (e) => {
        e.stopPropagation();
        const k = expandBtn.getAttribute('data-group-key');
        if (expandedGroups.has(k)) expandedGroups.delete(k);
        else expandedGroups.add(k);
        renderFeed(false);
      });
    }

    fragment.appendChild(row);

    // Render expanded sub-rows
    if (isExpanded && isGroup) {
      const subItems = g.requests.slice().reverse();
      subItems.forEach((subReq) => {
        const subConf = (subReq.confidence ?? 0);
        const subConfPct = (subConf * 100).toFixed(0);
        const subConfClass = subConf >= 0.8 ? ' feed-row--high-conf' : subConf < 0.35 ? ' feed-row--low-conf' : '';
        const subRow = document.createElement('div');
        subRow.className = 'feed-row feed-row--sub' + (subReq.id === selectedRequestId ? ' feed-row--selected' : '') + subConfClass;
        subRow.setAttribute('data-request-id', subReq.id);
        subRow.setAttribute('role', 'button');
        subRow.setAttribute('tabindex', '0');
        const subPath = getPathFromUrl(subReq.url);
        const subPathDisplay = subPath ? truncatePath(subPath, 40) : '—';
        const subSize = subReq.response_size_bytes != null
          ? (subReq.response_size_bytes >= 1024 * 1024
              ? (subReq.response_size_bytes / (1024 * 1024)).toFixed(1) + ' MB'
              : (subReq.response_size_bytes / 1024).toFixed(1) + ' KB')
          : '—';
        subRow.innerHTML =
          '<span class="feed-cell feed-cell-badge feed-cell-badge--sub"></span>' +
          '<span class="feed-cell feed-cell-domain feed-cell-domain--sub" ' + (subReq.domain ? 'data-tooltip="' + escapeAttr(subReq.url || subReq.domain) + '"' : '') + '>' +
          '<span class="feed-sub-indent" aria-hidden="true">└</span>' +
          escapeAttr(subPathDisplay) +
          '</span>' +
          '<span class="feed-cell feed-cell-url" style="color:var(--text-ghost);font-size:var(--text-2xs)">' +
          escapeAttr(subReq.method || '—') +
          '</span>' +
          '<span class="feed-cell feed-cell-conf">' + subConfPct + '%</span>' +
          '<span class="feed-cell feed-cell-size">' + subSize + '</span>';
        subRow.addEventListener('click', () => selectRequest(subReq.id));
        subRow.addEventListener('keydown', (e) => {
          if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); selectRequest(subReq.id); }
        });
        fragment.appendChild(subRow);
      });
    }
  });
  list.appendChild(fragment);

  const container = document.getElementById('feed-container');
  if (animateLast && filtered.length > 0 && settings.autoscroll_feed && !scrollState.userScrolledUp && container) {
    requestAnimationFrame(() => { container.scrollTop = 0; });
  }
}

function renderFeed(animateLast = false) {
  try {
    const filtered = applyFilters(feedRequests);
    const list = document.getElementById('feed-list');
    const emptyEl = document.getElementById('feed-empty');
    const emptyText = document.getElementById('feed-empty-text');

    const noRequests = feedRequests.length === 0;
    const noMatch = filtered.length === 0;

    /* Show empty only when there’s nothing to show; keep feed visible when stopped if we have data */
    if (noRequests) {
      if (list) list.style.display = 'none';
      if (emptyEl) emptyEl.style.display = 'flex';
      if (emptyText) emptyText.textContent = 'Start a session from the Specter popup to begin capturing requests.';
      updateNewPill(false);
      return;
    }

    if (noMatch) {
      if (list) list.style.display = 'none';
      if (emptyEl) emptyEl.style.display = 'flex';
      if (emptyText) emptyText.textContent = 'NO TRACKERS MATCH';
      updateNewPill(false);
      return;
    }

    if (emptyEl) emptyEl.style.display = 'none';
    if (list) list.style.display = 'flex';
    const pillEl = document.getElementById('feed-new-pill');
    const pillCountEl = document.getElementById('feed-new-pill-count');
    if (pillEl && pillCountEl) {
      if (pendingNewCount > 0) {
        pillEl.hidden = false;
        pillCountEl.textContent = String(pendingNewCount);
      } else {
        pillEl.hidden = true;
      }
    }
    renderFeedRows(filtered, animateLast);
  } finally {
    scheduleTimelineRender();
  }
}

function updateNewPill(show) {
  const pillEl = document.getElementById('feed-new-pill');
  const pillCountEl = document.getElementById('feed-new-pill-count');
  if (!pillEl || !pillCountEl) return;
  if (show && pendingNewCount > 0) {
    pillEl.hidden = false;
    pillCountEl.textContent = String(pendingNewCount);
  } else if (!show) {
    pillEl.hidden = true;
  }
}

function selectRequest(id) {
  selectedRequestId = id;
  const panel = document.getElementById('panel-detail');
  const grid = document.querySelector('.dashboard-grid');
  if (panel && grid) {
    panel.classList.remove('panel-detail--collapsed');
    grid.classList.add('panel-detail-open');
  }
  // Always switch site summary to the selected request's origin site.
  // summaryAutoSelected tracks that this was request-driven (not user dropdown),
  // so closing the detail panel can reset back to All Sites.
  const req = feedRequests.find((r) => r.id === id);
  const site = req && req.initiator_domain;
  if (site && siteScores[site]) {
    summarySelectedDomain = site;
    summaryAutoSelected = true;
    renderSiteSummary();
  }
  renderDetailPanel();
  renderFeed(false);
}

function closeDetailPanel() {
  selectedRequestId = null;
  const panel = document.getElementById('panel-detail');
  const grid = document.querySelector('.dashboard-grid');
  if (panel && grid) {
    panel.classList.add('panel-detail--collapsed');
    grid.classList.remove('panel-detail-open');
  }
  // Reset summary back to "All sites" if it was auto-set by a request click.
  if (summaryAutoSelected) {
    summarySelectedDomain = SUMMARY_SCOPE_ALL_SITES;
    summaryAutoSelected = false;
    renderSiteSummary();
  }
  clearVtCountdown();
  renderFeed(false);
}

function escapeHtml(s) {
  if (s == null) return '';
  return String(s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function formatBytes(n) {
  if (n == null || n === 0) return '0 B';
  if (n >= 1024 * 1024) return (n / (1024 * 1024)).toFixed(1) + ' MB';
  if (n >= 1024) return (n / 1024).toFixed(1) + ' KB';
  return n + ' B';
}

function renderDetailPanel() {
  const contentEl = document.getElementById('detail-content');
  if (!contentEl) return;

  if (!selectedRequestId) {
    contentEl.innerHTML = '<div class="detail-empty">Select a request to view details.</div>';
    return;
  }

  const req = feedRequests.find((r) => r.id === selectedRequestId);
  if (!req) {
    contentEl.innerHTML = '<div class="detail-empty">Request not found.</div>';
    return;
  }

  // --- Classification hero ---
  const badgeClass = categoryToBadgeClass(req.category);
  const badgeLabel = categoryLabel(req.category);
  const confRaw = (req.confidence ?? 0);
  const confPct = (confRaw * 100).toFixed(0) + '%';
  const confColorCls = confRaw >= 0.8 ? 'detail-conf--high' : confRaw >= 0.5 ? 'detail-conf--mid' : 'detail-conf--low';
  const domain = req.domain || '';

  const classifierHtml =
    '<div class="detail-section">' +
    '<div class="detail-classifier-hero">' +
    '<span class="feed-badge ' + badgeClass + ' detail-badge-lg"><span class="feed-badge-dot"></span>' + escapeHtml(badgeLabel) + '</span>' +
    '<div class="detail-conf-block">' +
    '<span class="detail-conf ' + confColorCls + '">' + confPct + '</span>' +
    '<span class="detail-conf-label">confidence</span>' +
    '</div>' +
    '</div>' +
    '<div class="detail-domain-row">' +
    '<span class="detail-domain-label">Domain</span>' +
    '<span class="detail-domain-val">' + escapeHtml(domain || '—') + '</span>' +
    '</div>' +
    '</div>';

  // --- URL + meta (always visible) ---
  const fullUrl = req.url || '';
  const status = req.response_status || '—';
  const size = formatBytes(req.response_size_bytes);
  const ctype = req.content_type || '—';
  const method = req.method || '—';

  // Parse URL into components for structured display
  const PARAM_INITIAL_CAP = 5;
  let parsedOrigin = '', parsedPath = '', parsedParams = [];
  try {
    const u = new URL(fullUrl);
    parsedOrigin = u.origin;
    parsedPath = u.pathname;
    parsedParams = Array.from(u.searchParams.entries());
  } catch {
    parsedOrigin = fullUrl;
  }

  const visibleParams = parsedParams.slice(0, PARAM_INITIAL_CAP);
  const hiddenParams = parsedParams.slice(PARAM_INITIAL_CAP);
  const paramRowsHtml = (params) => params.map(([k, v]) =>
    '<div class="detail-param-row">' +
    '<span class="detail-param-key">' + escapeHtml(k) + '</span>' +
    '<span class="detail-param-sep" aria-hidden="true">=</span>' +
    '<span class="detail-param-val">' + escapeHtml(v) + '</span>' +
    '</div>'
  ).join('');

  const urlMetaHtml =
    '<div class="detail-section">' +
    '<div class="detail-section-hd">REQUEST</div>' +
    '<div class="detail-meta-grid">' +
    '<span class="detail-meta-label">Method</span><span class="detail-meta-val">' + escapeHtml(method) + '</span>' +
    '<span class="detail-meta-label">Status</span><span class="detail-meta-val">' + escapeHtml(String(status)) + '</span>' +
    '<span class="detail-meta-label">Size</span><span class="detail-meta-val">' + escapeHtml(size) + '</span>' +
    '<span class="detail-meta-label">Type</span><span class="detail-meta-val detail-meta-val--wrap">' + escapeHtml(ctype) + '</span>' +
    '</div>' +
    '<div class="detail-url-parsed">' +
    '<div class="detail-url-parsed-header">' +
    '<div class="detail-url-segments">' +
    '<div class="detail-url-segment">' +
    '<span class="detail-url-seg-label">BASE</span>' +
    '<span class="detail-url-seg-val detail-url-seg-val--origin">' + escapeHtml(parsedOrigin) + '</span>' +
    '</div>' +
    (parsedPath && parsedPath !== '/' ? '<div class="detail-url-segment">' +
    '<span class="detail-url-seg-label">PATH</span>' +
    '<span class="detail-url-seg-val">' + escapeHtml(parsedPath) + '</span>' +
    '</div>' : '') +
    '</div>' +
    '<button class="detail-copy-btn" id="detail-url-copy" type="button" data-tooltip="Copy full URL to clipboard">COPY</button>' +
    '</div>' +
    (parsedParams.length > 0
      ? '<div class="detail-param-list">' +
        '<div class="detail-param-section-label">QUERY <span class="detail-param-count">(' + parsedParams.length + ')</span></div>' +
        '<div class="detail-param-rows" id="detail-param-visible">' + paramRowsHtml(visibleParams) + '</div>' +
        (hiddenParams.length > 0
          ? '<div class="detail-param-rows detail-param-rows--hidden" id="detail-param-hidden" hidden>' + paramRowsHtml(hiddenParams) + '</div>' +
            '<button type="button" class="detail-param-more-btn" id="detail-param-more">+ ' + hiddenParams.length + ' more</button>'
          : '') +
        '</div>'
      : '') +
    '</div>' +
    '</div>';

  // --- VirusTotal (always visible) ---
  const vtHtml =
    '<div class="detail-section" id="detail-vt-section">' +
    '<div class="detail-section-hd">DOMAIN REPUTATION</div>' +
    '<button class="detail-vt-btn" id="detail-vt-btn" type="button" data-tooltip="Look up domain reputation on VirusTotal">FETCH REPUTATION</button>' +
    '<div class="detail-vt-result" id="detail-vt-result" aria-live="polite"></div>' +
    '</div>';

  // --- Feature importances (collapsible) ---
  const fis = Array.isArray(req.feature_importances) ? req.feature_importances : [];
  let fiInnerHtml = '';
  if (fis.length > 0) {
    const maxImp = Math.max(...fis.map((f) => f.importance), 0.001);
    fiInnerHtml = '<div class="detail-fi-list">' + fis.map((f) => {
      const barW = Math.round((f.importance / maxImp) * 100);
      return (
        '<div class="detail-fi-row">' +
        '<span class="detail-fi-label">' + escapeHtml(f.feature) + '</span>' +
        '<div class="detail-fi-track"><div class="detail-fi-bar" style="width:' + barW + '%"></div></div>' +
        '<span class="detail-fi-val">' + escapeHtml(f.importance.toFixed(2)) + '</span>' +
        '</div>'
      );
    }).join('') + '</div>';
  }
  const fiHtml = fis.length === 0 ? '' :
    '<div class="detail-section detail-section--collapsible">' +
    '<button type="button" class="detail-section-toggle" data-target="detail-fi-body">' +
    '<span class="detail-section-hd detail-section-hd--toggle">FEATURE IMPORTANCE <span class="detail-section-count">(' + fis.length + ')</span></span>' +
    '<span class="detail-toggle-arrow" aria-hidden="true">▶</span>' +
    '</button>' +
    '<div class="detail-collapsible-body" id="detail-fi-body" hidden>' + fiInnerHtml + '</div>' +
    '</div>';

  // --- Headers (collapsible) ---
  function buildCollapsibleHeaders(title, headersObj, bodyId) {
    const entries = Object.entries(headersObj || {});
    if (entries.length === 0) return '';
    const rows = entries.map(([k, v]) =>
      '<div class="detail-kv-row">' +
      '<span class="detail-kv-key">' + escapeHtml(k) + '</span>' +
      '<span class="detail-kv-val">' + escapeHtml(v) + '</span>' +
      '</div>'
    ).join('');
    return (
      '<div class="detail-section detail-section--collapsible">' +
      '<button type="button" class="detail-section-toggle" data-target="' + bodyId + '">' +
      '<span class="detail-section-hd detail-section-hd--toggle">' + title + ' <span class="detail-section-count">(' + entries.length + ')</span></span>' +
      '<span class="detail-toggle-arrow" aria-hidden="true">▶</span>' +
      '</button>' +
      '<div class="detail-collapsible-body" id="' + bodyId + '" hidden>' +
      '<div class="detail-kv-list">' + rows + '</div>' +
      '</div>' +
      '</div>'
    );
  }

  const reqHeadersHtml = buildCollapsibleHeaders('REQUEST HEADERS', req.request_headers, 'detail-req-headers-body');
  const resHeadersHtml = buildCollapsibleHeaders('RESPONSE HEADERS', req.response_headers, 'detail-res-headers-body');

  contentEl.innerHTML = classifierHtml + urlMetaHtml + vtHtml + fiHtml + reqHeadersHtml + resHeadersHtml;

  // Bind "show more params" toggle
  const moreBtn = document.getElementById('detail-param-more');
  if (moreBtn) {
    moreBtn.addEventListener('click', () => {
      const hidden = document.getElementById('detail-param-hidden');
      if (!hidden) return;
      hidden.hidden = false;
      moreBtn.hidden = true;
    });
  }

  // Bind collapse toggles
  contentEl.querySelectorAll('.detail-section-toggle').forEach((btn) => {
    btn.addEventListener('click', () => {
      const targetId = btn.getAttribute('data-target');
      const body = document.getElementById(targetId);
      const arrow = btn.querySelector('.detail-toggle-arrow');
      if (!body) return;
      const isOpen = !body.hidden;
      body.hidden = isOpen;
      if (arrow) arrow.textContent = isOpen ? '▶' : '▼';
    });
  });

  // Bind copy button
  const copyBtn = document.getElementById('detail-url-copy');
  if (copyBtn && fullUrl) {
    copyBtn.addEventListener('click', () => {
      navigator.clipboard.writeText(fullUrl).then(() => {
        copyBtn.textContent = 'COPIED';
        setTimeout(() => { copyBtn.textContent = 'COPY'; }, 1500);
      });
    });
  }

  // Bind VT button
  const vtBtn = document.getElementById('detail-vt-btn');
  if (vtBtn && domain) {
    const now = Date.now();
    const remaining = vtLastRequestTime > 0 ? Math.ceil((vtLastRequestTime + 15000 - now) / 1000) : 0;
    if (remaining > 0) {
      vtBtn.disabled = true;
      startVtCountdown(remaining);
    }
    vtBtn.addEventListener('click', () => fetchVirusTotal(domain));
  }
}

function clearVtCountdown() {
  if (vtCountdownInterval) {
    clearInterval(vtCountdownInterval);
    vtCountdownInterval = null;
  }
}

function startVtCountdown(seconds) {
  clearVtCountdown();
  let remaining = seconds;
  const btn = document.getElementById('detail-vt-btn');
  const resultEl = document.getElementById('detail-vt-result');
  if (btn) btn.disabled = true;
  if (resultEl) {
    resultEl.className = 'detail-vt-result detail-vt-countdown';
    resultEl.textContent = 'Rate limited — try again in ' + remaining + 's';
  }
  vtCountdownInterval = setInterval(() => {
    remaining -= 1;
    if (remaining <= 0) {
      clearVtCountdown();
      const b = document.getElementById('detail-vt-btn');
      const r = document.getElementById('detail-vt-result');
      if (b) b.disabled = false;
      if (r) r.textContent = '';
    } else {
      const r = document.getElementById('detail-vt-result');
      if (r) r.textContent = 'Rate limited — try again in ' + remaining + 's';
    }
  }, 1000);
}

async function fetchVirusTotal(domain) {
  const btn = document.getElementById('detail-vt-btn');
  const resultEl = document.getElementById('detail-vt-result');
  if (!resultEl) return;

  const { settings: s } = await chrome.storage.local.get('settings');
  const apiKey = s?.virustotal_api_key || '';
  if (!apiKey) {
    resultEl.className = 'detail-vt-result detail-vt-result--no-key';
    resultEl.textContent = 'No API key configured. Add your VirusTotal key in Settings.';
    return;
  }

  if (btn) btn.disabled = true;
  resultEl.className = 'detail-vt-result detail-vt-result--loading';
  resultEl.textContent = 'Fetching…';

  try {
    const resp = await fetch('https://www.virustotal.com/api/v3/domains/' + encodeURIComponent(domain), {
      headers: { 'x-apikey': apiKey },
    });

    if (resp.status === 429) {
      vtLastRequestTime = Date.now();
      startVtCountdown(60);
      return;
    }

    if (!resp.ok) {
      resultEl.className = 'detail-vt-result detail-vt-result--error';
      resultEl.textContent = 'Error: ' + resp.status + ' ' + resp.statusText;
      if (btn) btn.disabled = false;
      return;
    }

    vtLastRequestTime = Date.now();
    const data = await resp.json();
    const stats = data?.data?.attributes?.last_analysis_stats || {};
    const malicious = stats.malicious ?? 0;
    const harmless = stats.harmless ?? 0;
    const suspicious = stats.suspicious ?? 0;
    const total = Object.values(stats).reduce((a, b) => a + b, 0);

    resultEl.className = 'detail-vt-result';
    resultEl.innerHTML =
      '<div class="detail-vt-score-row">' +
      '<div class="detail-vt-score">' +
      '<span class="detail-vt-score-label">Malicious</span>&nbsp;' +
      '<span class="detail-vt-score-val--malicious">' + malicious + '</span>' +
      '</div>' +
      '<div class="detail-vt-score">' +
      '<span class="detail-vt-score-label">Suspicious</span>&nbsp;' +
      '<span class="detail-vt-score-val--malicious">' + suspicious + '</span>' +
      '</div>' +
      '<div class="detail-vt-score">' +
      '<span class="detail-vt-score-label">Harmless</span>&nbsp;' +
      '<span class="detail-vt-score-val--harmless">' + harmless + '</span>' +
      '</div>' +
      '</div>' +
      '<div style="color:var(--text-muted);margin-top:4px;">' + total + ' engines checked</div>';

    // Re-enable after VT rate limit window (15s for free tier ~4 req/min)
    setTimeout(() => {
      const b = document.getElementById('detail-vt-btn');
      if (b) b.disabled = false;
    }, 15000);

  } catch (err) {
    resultEl.className = 'detail-vt-result detail-vt-result--error';
    resultEl.textContent = 'Request failed. Check your connection.';
    if (btn) btn.disabled = false;
  }
}

/** Sync all category checkboxes inside a panel element to filterState. */
function syncCategoryCheckboxes(panel) {
  panel.querySelectorAll('input[data-category]').forEach((cb) => {
    cb.checked = filterState.categories.has(cb.getAttribute('data-category'));
  });
}

function buildFilterBar() {
  const filterBar = document.getElementById('feed-filters');
  const toolbar = document.getElementById('feed-toolbar');
  if (!filterBar) return;

  const row1 = document.createElement('div');
  row1.className = 'feed-filter-row';
  const dropdownWrap = document.createElement('div');
  dropdownWrap.className = 'feed-filter-dropdown';
  dropdownWrap.id = 'feed-category-dropdown';
  dropdownWrap.setAttribute('data-open', 'false');
  const trigger = document.createElement('button');
  trigger.type = 'button';
  trigger.className = 'feed-filter-dropdown-trigger';
  trigger.setAttribute('aria-haspopup', 'listbox');
  trigger.setAttribute('aria-expanded', 'false');
  const triggerLabel = document.createElement('span');
  triggerLabel.className = 'feed-filter-dropdown-label';
  triggerLabel.id = 'feed-filter-category-label';
  triggerLabel.textContent = 'Filter: ALL';
  const triggerChevron = document.createElement('span');
  triggerChevron.className = 'feed-filter-dropdown-chevron';
  triggerChevron.setAttribute('aria-hidden', 'true');
  triggerChevron.textContent = '▼';
  trigger.appendChild(triggerLabel);
  trigger.appendChild(triggerChevron);

  const panel = document.createElement('div');
  panel.className = 'feed-filter-dropdown-panel';
  panel.setAttribute('role', 'listbox');

  // Select All / Clear row
  const bulkRow = document.createElement('div');
  bulkRow.className = 'feed-filter-bulk-row';
  const selectAllBtn = document.createElement('button');
  selectAllBtn.type = 'button';
  selectAllBtn.className = 'feed-filter-bulk-btn';
  selectAllBtn.textContent = 'SELECT ALL';
  selectAllBtn.addEventListener('click', () => {
    CATEGORIES.forEach((c) => filterState.categories.add(c));
    syncCategoryCheckboxes(panel);
    updateCategoryDropdownLabel();
    updateActiveFilterChips();
    renderFeed(false);
  });
  const clearAllBtn = document.createElement('button');
  clearAllBtn.type = 'button';
  clearAllBtn.className = 'feed-filter-bulk-btn feed-filter-bulk-btn--clear';
  clearAllBtn.textContent = 'CLEAR';
  clearAllBtn.addEventListener('click', () => {
    filterState.categories.clear();
    syncCategoryCheckboxes(panel);
    updateCategoryDropdownLabel();
    updateActiveFilterChips();
    renderFeed(false);
  });
  bulkRow.appendChild(selectAllBtn);
  bulkRow.appendChild(clearAllBtn);
  panel.appendChild(bulkRow);

  CATEGORIES.forEach((cat) => {
    const label = document.createElement('label');
    label.className = 'feed-filter-dropdown-option';
    const tip = categoryTooltip(cat);
    if (tip) label.setAttribute('data-tooltip', tip);
    const checkbox = document.createElement('input');
    checkbox.type = 'checkbox';
    checkbox.setAttribute('data-category', cat);
    checkbox.checked = filterState.categories.has(cat);
    checkbox.addEventListener('change', () => {
      if (checkbox.checked) filterState.categories.add(cat);
      else filterState.categories.delete(cat);
      updateCategoryDropdownLabel();
      updateActiveFilterChips();
      renderFeed(false);
    });
    const span = document.createElement('span');
    span.textContent = categoryLabel(cat);
    label.appendChild(checkbox);
    label.appendChild(span);
    panel.appendChild(label);
  });

  function updateCategoryDropdownLabel() {
    const el = document.getElementById('feed-filter-category-label');
    if (!el) return;
    if (filterState.categories.size === 0) {
      el.textContent = 'Filter: ALL';
    } else {
      const names = Array.from(filterState.categories).map(categoryLabel).sort();
      el.textContent = names.length <= 2 ? 'Filter: ' + names.join(', ') : 'Filter: ' + names.length + ' selected';
    }
  }

  function setPanelOpen(open) {
    panel.classList.toggle('is-open', open);
    dropdownWrap.setAttribute('data-open', open ? 'true' : 'false');
    trigger.setAttribute('aria-expanded', String(open));
  }

  trigger.addEventListener('click', (e) => {
    e.stopPropagation();
    const isOpen = panel.classList.contains('is-open');
    setPanelOpen(!isOpen);
  });

  document.addEventListener('click', (e) => {
    if (!dropdownWrap.contains(e.target)) {
      setPanelOpen(false);
    }
  });

  dropdownWrap.appendChild(trigger);
  dropdownWrap.appendChild(panel);
  row1.appendChild(dropdownWrap);
  filterBar.appendChild(row1);

  const activeFiltersRow = document.createElement('div');
  activeFiltersRow.className = 'feed-filter-row feed-filter-row--active-chips';
  activeFiltersRow.id = 'feed-active-filters-row';
  activeFiltersRow.hidden = true;
  const activeFiltersContainer = document.createElement('div');
  activeFiltersContainer.className = 'feed-active-filters';
  activeFiltersContainer.id = 'feed-active-filters';
  activeFiltersRow.appendChild(activeFiltersContainer);
  filterBar.appendChild(activeFiltersRow);

  const row2 = document.createElement('div');
  row2.className = 'feed-filter-row';
  const tabDropdownWrap = document.createElement('div');
  tabDropdownWrap.className = 'feed-filter-dropdown';
  tabDropdownWrap.id = 'feed-tab-dropdown';
  tabDropdownWrap.setAttribute('data-open', 'false');
  const tabTrigger = document.createElement('button');
  tabTrigger.type = 'button';
  tabTrigger.className = 'feed-filter-dropdown-trigger';
  tabTrigger.setAttribute('aria-haspopup', 'listbox');
  tabTrigger.setAttribute('aria-expanded', 'false');
  tabTrigger.setAttribute('aria-label', 'Filter by tab');
  const tabTriggerLabel = document.createElement('span');
  tabTriggerLabel.className = 'feed-filter-dropdown-label';
  tabTriggerLabel.id = 'feed-tab-trigger-label';
  tabTriggerLabel.textContent = 'Tab: All tabs';
  const tabTriggerChevron = document.createElement('span');
  tabTriggerChevron.className = 'feed-filter-dropdown-chevron';
  tabTriggerChevron.setAttribute('aria-hidden', 'true');
  tabTriggerChevron.textContent = '▼';
  tabTrigger.appendChild(tabTriggerLabel);
  tabTrigger.appendChild(tabTriggerChevron);

  const tabPanel = document.createElement('div');
  tabPanel.className = 'feed-filter-dropdown-panel';
  tabPanel.setAttribute('role', 'listbox');

  function updateTabTriggerLabel() {
    const el = document.getElementById('feed-tab-trigger-label');
    if (!el) return;
    if (filterState.tabFilter !== 'current' || currentTabId == null) {
      el.textContent = 'Tab: All tabs';
      return;
    }
    const selected = tabPanel.querySelector('.feed-filter-dropdown-option[data-value="' + String(currentTabId) + '"]');
    el.textContent = selected ? 'Tab: ' + (selected.textContent || '').trim() : 'Tab: Current tab';
  }

  function populateTabPanel() {
    tabPanel.textContent = '';
    const dashboardUrl = chrome.runtime.getURL('dashboard.html');
    const base = dashboardUrl.split('?')[0];
    chrome.tabs.query({ currentWindow: true }, (tabs) => {
      const contentTabs = tabs.filter((tab) => tab.url && !tab.url.startsWith(base));
      const tabIds = new Set(contentTabs.map((t) => t.id));
      if (filterState.tabFilter === 'current' && currentTabId != null && !tabIds.has(currentTabId)) {
        filterState.tabFilter = 'all';
        currentTabId = null;
      }
      const allOpt = document.createElement('div');
      allOpt.className = 'feed-filter-dropdown-option';
      allOpt.setAttribute('role', 'option');
      allOpt.setAttribute('data-value', '');
      allOpt.textContent = 'All tabs';
      allOpt.addEventListener('click', () => {
        filterState.tabFilter = 'all';
        currentTabId = null;
        setTabPanelOpen(false);
        updateTabTriggerLabel();
        updateActiveFilterChips();
        renderFeed(false);
      });
      tabPanel.appendChild(allOpt);
      contentTabs.forEach((tab) => {
        const opt = document.createElement('div');
        opt.className = 'feed-filter-dropdown-option';
        opt.setAttribute('role', 'option');
        opt.setAttribute('data-value', String(tab.id));
        const title = tab.title || tab.url || 'Tab ' + tab.id;
        opt.textContent = title.length > 32 ? title.slice(0, 29) + '…' : title;
        opt.title = tab.url;
        opt.addEventListener('click', () => {
          filterState.tabFilter = 'current';
          currentTabId = tab.id;
          setTabPanelOpen(false);
          updateTabTriggerLabel();
          updateActiveFilterChips();
          renderFeed(false);
        });
        tabPanel.appendChild(opt);
      });
      updateTabTriggerLabel();
    });
  }

  function setTabPanelOpen(open) {
    tabPanel.classList.toggle('is-open', open);
    tabDropdownWrap.setAttribute('data-open', open ? 'true' : 'false');
    tabTrigger.setAttribute('aria-expanded', String(open));
  }

  tabTrigger.addEventListener('click', (e) => {
    e.stopPropagation();
    if (tabPanel.classList.contains('is-open')) {
      setTabPanelOpen(false);
    } else {
      populateTabPanel();
      setTabPanelOpen(true);
    }
  });

  document.addEventListener('click', (e) => {
    if (!tabDropdownWrap.contains(e.target)) {
      setTabPanelOpen(false);
    }
  });

  tabDropdownWrap.appendChild(tabTrigger);
  tabDropdownWrap.appendChild(tabPanel);
  row2.appendChild(tabDropdownWrap);
  populateTabPanel();

  const confidenceWrap = document.createElement('div');
  confidenceWrap.className = 'feed-confidence-wrap';
  const confidenceLabel = document.createElement('label');
  confidenceLabel.className = 'feed-confidence-label';
  confidenceLabel.textContent = 'Min confidence %';
  confidenceLabel.htmlFor = 'feed-min-confidence';
  const confidenceInput = document.createElement('input');
  confidenceInput.type = 'number';
  confidenceInput.min = 0;
  confidenceInput.max = 100;
  confidenceInput.step = 5;
  confidenceInput.value = String(filterState.minConfidence);
  confidenceInput.className = 'feed-confidence-input';
  confidenceInput.id = 'feed-min-confidence';
  confidenceInput.setAttribute('aria-label', 'Minimum confidence percentage (0–100)');
  confidenceInput.addEventListener('change', () => {
    const v = Math.max(0, Math.min(100, Number(confidenceInput.value) || 0));
    filterState.minConfidence = v;
    confidenceInput.value = String(v);
    updateActiveFilterChips();
    renderFeed(false);
  });
  confidenceInput.addEventListener('input', () => {
    const v = Math.max(0, Math.min(100, Number(confidenceInput.value) || 0));
    filterState.minConfidence = v;
    updateActiveFilterChips();
    renderFeed(false);
  });
  confidenceWrap.appendChild(confidenceLabel);
  confidenceWrap.appendChild(confidenceInput);
  row2.appendChild(confidenceWrap);
  filterBar.appendChild(row2);

  const row3 = document.createElement('div');
  row3.className = 'feed-filter-row feed-filter-row--domain';
  const domainInput = document.createElement('input');
  domainInput.type = 'text';
  domainInput.className = 'feed-filter-input feed-filter-input--full';
  domainInput.placeholder = 'Domain search…';
  domainInput.id = 'filter-domain';
  domainInput.addEventListener('input', () => {
    filterState.domainSearch = domainInput.value;
    updateActiveFilterChips();
    renderFeed(false);
  });
  row3.appendChild(domainInput);
  filterBar.appendChild(row3);

  const collapseWrap = document.createElement('label');
  collapseWrap.className = 'feed-collapse-wrap';
  collapseWrap.title = 'Group requests by domain and category so the same domain appears as one row with a count';
  collapseWrap.innerHTML =
    '<input type="checkbox" class="feed-collapse-toggle" id="feed-collapse-toggle" checked aria-label="Group by domain and category">' +
    '<span class="feed-collapse-switch" aria-hidden="true"><span class="feed-collapse-thumb"></span></span>' +
    '<span class="feed-collapse-label">Group by domain</span>';
  const collapseToggle = collapseWrap.querySelector('#feed-collapse-toggle');
  collapseToggle.addEventListener('change', () => {
    filterState.collapseDuplicates = collapseToggle.checked;
    renderFeed(false);
  });

  const clearBtn = document.createElement('button');
  clearBtn.type = 'button';
  clearBtn.className = 'feed-filter-clear';
  clearBtn.textContent = 'Clear all';
  clearBtn.addEventListener('click', () => {
    feedRequests = [];
    requestCount = 0;
    pendingNewCount = 0;
    lastGroupCounts.clear();
    expandedGroups.clear();
    if (currentSession && currentSession.id) {
      chrome.storage.local.set({ ['requests:' + currentSession.id]: [] });
    }
    updateStatus(requestCount ? 'Requests: ' + requestCount : (currentSession && currentSession.active ? 'Recording' : 'Stopped'));
    refreshSiteSummary();
    filterState.categories.clear();
    filterState.tabFilter = 'all';
    currentTabId = null;
    filterState.minConfidence = 0;
    filterState.domainSearch = '';
    filterState.collapseDuplicates = true;
    const domainEl = document.getElementById('filter-domain');
    if (domainEl) domainEl.value = '';
    const confidenceInputEl = document.getElementById('feed-min-confidence');
    if (confidenceInputEl) {
      confidenceInputEl.value = '0';
    }
    const tabLabelEl = document.getElementById('feed-tab-trigger-label');
    if (tabLabelEl) tabLabelEl.textContent = 'Tab: All tabs';
    const collapseCheckbox = document.getElementById('feed-collapse-toggle');
    if (collapseCheckbox) collapseCheckbox.checked = true;
    renderFilterChips();
    renderFeed(false);
  });

  if (toolbar) {
    toolbar.appendChild(collapseWrap);
    toolbar.appendChild(clearBtn);
  }

  const container = document.getElementById('feed-container');
  if (container) {
    container.addEventListener('scroll', () => {
      const threshold = 20;
      scrollState.userScrolledUp = container.scrollTop > threshold;
      if (!scrollState.userScrolledUp) {
        pendingNewCount = 0;
        updateNewPill(false);
      }
    });
    container.addEventListener('click', (e) => {
      if (e.target.closest('.feed-row')) return;
      if (feedPaused) return;
      feedPaused = true;
      if (currentSession && currentSession.active && sessionStartTime) {
        frozenElapsedSeconds = Math.floor((Date.now() - sessionStartTime) / 1000);
        stopSessionTimer();
      }
      const overlay = document.getElementById('feed-pause-overlay');
      if (overlay) overlay.hidden = false;
      updateFeedHeaderDot();
      updatePauseButton();
    });
  }
  const pauseOverlay = document.getElementById('feed-pause-overlay');
  if (pauseOverlay) {
    pauseOverlay.addEventListener('click', () => {
      feedPaused = false;
      if (currentSession && currentSession.active) {
        sessionStartTime = Date.now() - frozenElapsedSeconds * 1000;
        startSessionTimer();
        chrome.runtime.sendMessage({ type: 'resume_session' });
      }
      pauseOverlay.hidden = true;
      updateFeedHeaderDot();
      updatePauseButton();
      renderFeed(false);
    });
  }
  const pauseBtn = document.getElementById('pause-btn');
  if (pauseBtn) {
    pauseBtn.addEventListener('click', () => {
      if (!currentSession || !currentSession.active) return;
      if (feedPaused) {
        feedPaused = false;
        sessionStartTime = Date.now() - frozenElapsedSeconds * 1000;
        startSessionTimer();
        chrome.runtime.sendMessage({ type: 'resume_session' });
        const overlay = document.getElementById('feed-pause-overlay');
        if (overlay) overlay.hidden = true;
        updateFeedHeaderDot();
        updatePauseButton();
        renderFeed(false);
      } else {
        frozenElapsedSeconds = Math.floor((Date.now() - sessionStartTime) / 1000);
        feedPaused = true;
        stopSessionTimer();
        chrome.runtime.sendMessage({ type: 'pause_session', elapsed_seconds: frozenElapsedSeconds });
        updateFeedHeaderDot();
        updatePauseButton();
      }
    });
  }
  const newPill = document.getElementById('feed-new-pill');
  if (newPill) {
    newPill.addEventListener('click', () => {
      pendingNewCount = 0;
      updateNewPill(false);
      if (container) container.scrollTop = 0;
      scrollState.userScrolledUp = false;
      renderFeed(false);
    });
  }
}

function renderFilterChips() {
  const tabLabelEl = document.getElementById('feed-tab-trigger-label');
  if (tabLabelEl) {
    if (filterState.tabFilter !== 'current' || currentTabId == null) {
      tabLabelEl.textContent = 'Tab: All tabs';
    } else {
      const tabPanelEl = document.querySelector('#feed-tab-dropdown .feed-filter-dropdown-panel');
      const selected = tabPanelEl ? tabPanelEl.querySelector('.feed-filter-dropdown-option[data-value="' + String(currentTabId) + '"]') : null;
      tabLabelEl.textContent = selected ? 'Tab: ' + (selected.textContent || '').trim() : 'Tab: Current tab';
    }
  }
  const categoryLabelEl = document.getElementById('feed-filter-category-label');
  if (categoryLabelEl) {
    if (filterState.categories.size === 0) {
      categoryLabelEl.textContent = 'Filter: ALL';
    } else {
      const names = Array.from(filterState.categories).map(categoryLabel).sort();
      categoryLabelEl.textContent = names.length <= 2 ? 'Filter: ' + names.join(', ') : 'Filter: ' + names.length + ' selected';
    }
  }
  const dropdown = document.getElementById('feed-category-dropdown');
  if (dropdown) {
    dropdown.querySelectorAll('.feed-filter-dropdown-option input[data-category]').forEach((cb) => {
      const cat = cb.getAttribute('data-category');
      cb.checked = filterState.categories.has(cat);
    });
  }
  updateActiveFilterChips();
}

function updateActiveFilterChips() {
  const row = document.getElementById('feed-active-filters-row');
  const container = document.getElementById('feed-active-filters');
  if (!row || !container) return;

  const hasCategory = filterState.categories.size > 0;
  const hasMinConf = filterState.minConfidence > 0;
  const hasDomain = filterState.domainSearch.trim() !== '';
  const hasAny = hasCategory || hasMinConf || hasDomain;

  container.textContent = '';
  row.hidden = !hasAny;
  if (!hasAny) return;

  if (hasCategory) {
    filterState.categories.forEach((cat) => {
      const chip = document.createElement('span');
      chip.className = 'feed-active-chip';
      chip.innerHTML = '<span class="feed-active-chip-label">' + escapeAttr(categoryLabel(cat)) + '</span><button type="button" class="feed-active-chip-remove" data-tooltip="Remove filter" aria-label="Remove filter">×</button>';
      const removeBtn = chip.querySelector('.feed-active-chip-remove');
      removeBtn.addEventListener('click', () => {
        filterState.categories.delete(cat);
        renderFilterChips();
        renderFeed(false);
      });
      container.appendChild(chip);
    });
  }
  if (hasMinConf) {
    const chip = document.createElement('span');
    chip.className = 'feed-active-chip';
    chip.innerHTML = '<span class="feed-active-chip-label">Min ' + filterState.minConfidence + '%</span><button type="button" class="feed-active-chip-remove" aria-label="Remove filter">×</button>';
    chip.querySelector('.feed-active-chip-remove').addEventListener('click', () => {
      filterState.minConfidence = 0;
      const el = document.getElementById('feed-min-confidence');
      if (el) el.value = '0';
      updateActiveFilterChips();
      renderFeed(false);
    });
    container.appendChild(chip);
  }
  if (hasDomain) {
    const q = filterState.domainSearch.trim();
    const label = q.length > 18 ? q.slice(0, 17) + '…' : q;
    const chip = document.createElement('span');
    chip.className = 'feed-active-chip';
    chip.innerHTML = '<span class="feed-active-chip-label">domain: ' + escapeAttr(label) + '</span><button type="button" class="feed-active-chip-remove" aria-label="Remove filter">×</button>';
    chip.querySelector('.feed-active-chip-remove').addEventListener('click', () => {
      filterState.domainSearch = '';
      const el = document.getElementById('filter-domain');
      if (el) el.value = '';
      updateActiveFilterChips();
      renderFeed(false);
    });
    container.appendChild(chip);
  }
}

function hideSessionConfirmBar() {
  const confirmEl = document.getElementById('session-confirm');
  if (confirmEl) confirmEl.hidden = true;
}

function setupTooltips() {
  const tooltipEl = document.getElementById('specter-tooltip');
  if (!tooltipEl) return;
  let showTimeout = null;
  const delayMs = 400;

  document.body.addEventListener('mouseenter', (e) => {
    const target = e.target.closest('[data-tooltip]');
    if (!target) return;
    const text = target.getAttribute('data-tooltip');
    if (!text) return;
    showTimeout = setTimeout(() => {
      tooltipEl.textContent = text;
      tooltipEl.setAttribute('aria-hidden', 'false');
      tooltipEl.classList.add('is-visible');
      requestAnimationFrame(() => {
        const rect = target.getBoundingClientRect();
        const tw = tooltipEl.offsetWidth;
        const th = tooltipEl.offsetHeight;
        let left = rect.left + rect.width / 2 - tw / 2;
        const top = rect.bottom + 6;
        left = Math.max(8, Math.min(left, window.innerWidth - tw - 8));
        if (top + th > window.innerHeight - 8) {
          tooltipEl.style.top = (rect.top - th - 6) + 'px';
        } else {
          tooltipEl.style.top = top + 'px';
        }
        tooltipEl.style.left = left + 'px';
      });
    }, delayMs);
  }, true);

  document.body.addEventListener('mouseleave', (e) => {
    const target = e.target.closest('[data-tooltip]');
    if (!target) return;
    if (showTimeout) clearTimeout(showTimeout);
    showTimeout = null;
    tooltipEl.classList.remove('is-visible');
    tooltipEl.setAttribute('aria-hidden', 'true');
  }, true);
}

function init() {
  setupTooltips();
  setupFingerprintDrawer();
  buildFilterBar();
  initHistoryOverlay();
  initSettingsOverlay();
  initCrawlOverlay();
  pruneOldSessions();

  hideSessionConfirmBar();

  const detailCloseBtn = document.getElementById('detail-close');
  if (detailCloseBtn) {
    detailCloseBtn.addEventListener('click', () => closeDetailPanel());
  }
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
      if (fingerprintDrawerOpen) {
        setFingerprintDrawerOpen(false);
        return;
      }
      const siteSummaryPanel = document.querySelector('#site-summary-dropdown .feed-filter-dropdown-panel');
      const categoryPanel = document.querySelector('#feed-category-dropdown .feed-filter-dropdown-panel');
      const tabPanelEl = document.querySelector('#feed-tab-dropdown .feed-filter-dropdown-panel');
      if (siteSummaryPanel && siteSummaryPanel.classList.contains('is-open')) {
        siteSummaryPanel.classList.remove('is-open');
        const wrap = document.getElementById('site-summary-dropdown');
        if (wrap) wrap.setAttribute('data-open', 'false');
        const trig = wrap && wrap.querySelector('.feed-filter-dropdown-trigger');
        if (trig) trig.setAttribute('aria-expanded', 'false');
      } else if (categoryPanel && categoryPanel.classList.contains('is-open')) {
        categoryPanel.classList.remove('is-open');
        const wrap = document.getElementById('feed-category-dropdown');
        if (wrap) wrap.setAttribute('data-open', 'false');
        const trig = wrap && wrap.querySelector('.feed-filter-dropdown-trigger');
        if (trig) trig.setAttribute('aria-expanded', 'false');
      } else if (tabPanelEl && tabPanelEl.classList.contains('is-open')) {
        tabPanelEl.classList.remove('is-open');
        const wrap = document.getElementById('feed-tab-dropdown');
        if (wrap) wrap.setAttribute('data-open', 'false');
        const trig = wrap && wrap.querySelector('.feed-filter-dropdown-trigger');
        if (trig) trig.setAttribute('aria-expanded', 'false');
      } else if (settingsOverlayOpen()) {
        closeSettingsOverlay();
        const settingsBtn = document.getElementById('settings-nav-btn');
        if (settingsBtn) settingsBtn.classList.remove('active');
      } else if (historyOverlayOpen()) {
        closeHistoryOverlay();
        const histBtn = document.getElementById('history-nav-btn');
        if (histBtn) histBtn.classList.remove('active');
      } else if (crawlOverlayOpen()) {
        closeCrawlOverlay();
        const crawlBtn = document.getElementById('crawl-nav-btn');
        if (crawlBtn) crawlBtn.classList.remove('active');
      } else {
        closeDetailPanel();
      }
    }
  });

  /* Session starts stopped on load: empty feed, START button, 00:00 */
  currentSession = null;
  feedRequests = [];
  requestCount = 0;
  sessionStartTime = null;
  stopSessionTimer();
  updateTimerDisplay();
  updateFeedHeaderDot();
  updateStatus('Stopped');
  updateSessionButton(false);
  initTimelineResizeObserver();
  updateBottomViewToggleLabel();
  renderFeed(false);
  requestAnimationFrame(() => {
    requestAnimationFrame(() => scheduleTimelineRender());
  });

  // When user switches tabs, refresh site summary to the newly active tab's site (if not manually selected).
  chrome.tabs.onActivated.addListener(() => {
    if (!summaryAutoSelected && summarySelectedDomain !== SUMMARY_SCOPE_ALL_SITES) {
      refreshSiteSummary();
    }
  });

  chrome.tabs.onUpdated.addListener((tabId, changeInfo) => {
    if (changeInfo.status === 'complete' && !summaryAutoSelected && summarySelectedDomain !== SUMMARY_SCOPE_ALL_SITES) {
      refreshSiteSummary();
    }
  });

  chrome.storage.onChanged.addListener((changes, areaName) => {
    if (areaName !== 'local') return;
    if (changes['session:current']) hideSessionConfirmBar();
  });

  chrome.storage.local.get(['session:current', 'session:paused', 'session:elapsed_frozen'], (data) => {
    const session = data['session:current'];
    hideSessionConfirmBar();
    if (session && session.active) {
      currentSession = { id: session.id, active: true };
      sessionStartTime = session.started_at;
      const paused = !!data['session:paused'];
      if (paused) {
        feedPaused = true;
        frozenElapsedSeconds = Math.max(0, Number(data['session:elapsed_frozen']) || 0);
        const overlay = document.getElementById('feed-pause-overlay');
        if (overlay) overlay.hidden = false;
      } else {
        feedPaused = false;
        frozenElapsedSeconds = 0;
        startSessionTimer();
      }
      updateFeedHeaderDot();
      updateStatus('Recording');
      updateSessionButton(true);
      updatePauseButton();
      updateTimerDisplay();
      chrome.storage.local.get(['requests:' + session.id, 'scores:' + session.id], (res) => {
        const loaded = res['requests:' + session.id];
        if (Array.isArray(loaded) && loaded.length > 0) {
          feedRequests = loaded;
          requestCount = feedRequests.length;
          updateStatus('Requests: ' + requestCount);
          renderFeed(false);
        }
        siteScores = res['scores:' + session.id] || {};
        refreshSiteSummary();
        requestAnimationFrame(() => requestAnimationFrame(() => scheduleTimelineRender()));
      });
    } else {
      siteScores = {};
      currentSiteDomain = null;
      refreshSiteSummary();
      requestAnimationFrame(() => requestAnimationFrame(() => scheduleTimelineRender()));
    }
  });

  const sessionBtn = document.getElementById('session-btn');
  if (sessionBtn) {
    sessionBtn.addEventListener('click', () => {
      if (sessionBtn.classList.contains('stopped')) {
        if (currentSession?.active) return;
        if (feedRequests.length > 0) {
          const confirmEl = document.getElementById('session-confirm');
          const countEl = document.getElementById('session-confirm-count');
          if (confirmEl && countEl) {
            countEl.textContent = String(feedRequests.length);
            confirmEl.hidden = false;
          }
        } else {
          chrome.runtime.sendMessage({ type: 'start_session' });
        }
      } else {
        chrome.runtime.sendMessage({ type: 'stop_session' });
      }
    });
  }

  const confirmClear = document.getElementById('session-confirm-clear');
  const confirmKeep = document.getElementById('session-confirm-keep');
  const confirmEl = document.getElementById('session-confirm');
  if (confirmClear) {
    confirmClear.addEventListener('click', () => {
      hideSessionConfirmBar();
      chrome.runtime.sendMessage({ type: 'start_session', keep_rows: false });
    });
  }
  if (confirmKeep) {
    confirmKeep.addEventListener('click', () => {
      hideSessionConfirmBar();
      chrome.runtime.sendMessage({ type: 'start_session', keep_rows: true });
    });
  }

  chrome.storage.local.get(['settings'], (data) => {
    Object.assign(settings, data.settings || {});
    const confidenceInput = document.getElementById('feed-min-confidence');
    if (confidenceInput && settings.min_confidence != null) {
      filterState.minConfidence = Math.max(0, Math.min(100, Number(settings.min_confidence) || 0));
      confidenceInput.value = String(filterState.minConfidence);
    }
  });

  chrome.runtime.onMessage.addListener((message) => {
    if (message.type === 'request_update') {
      if (!currentSession || !currentSession.active || feedPaused) return;
      requestCount += 1;
      feedRequests.push(message.request);
      trimFeedToCap();
      updateStatus('Requests: ' + requestCount);
      if (scrollState.userScrolledUp) {
        pendingNewCount += 1;
        updateNewPill(true);
      }
      renderFeed(true);
      if (fingerprintDrawerOpen) {
        if (summarySelectedDomain === SUMMARY_SCOPE_ALL_SITES) {
          renderFingerprintingAlerts();
        } else if (
          currentSiteDomain &&
          siteScores[currentSiteDomain] &&
          (message.request.initiator_domain || '_direct') === currentSiteDomain
        ) {
          renderFingerprintingAlerts();
        }
      }
    } else if (message.type === 'score_update') {
      if (message.domain != null && message.score != null) {
        siteScores[message.domain] = message.score;
        if (summarySelectedDomain === SUMMARY_SCOPE_ALL_SITES) {
          renderSiteSummary();
        } else if (message.domain === currentSiteDomain) {
          renderSiteSummary();
        } else {
          getCurrentSiteDomain((domain) => {
            if (domain !== currentSiteDomain) {
              currentSiteDomain = domain;
              renderSiteSummary();
            }
          });
        }
      }
    } else if (message.type === 'session_started') {
      hideSessionConfirmBar();
      feedPaused = false;
      frozenElapsedSeconds = 0;
      if (!message.keep_rows) {
        feedRequests = [];
        requestCount = 0;
        pendingNewCount = 0;
        lastGroupCounts.clear();
        expandedGroups.clear();
      }
      sessionStartTime = Date.now();
      currentSession = { id: message.session_id, active: true };
      siteScores = {};
      summarySelectedDomain = null;
      lastRenderedScore = null;
      setFingerprintDrawerOpen(false);
      startSessionTimer();
      updateFeedHeaderDot();
      updateStatus('Recording');
      updateSessionButton(true);
      renderFeed(false);
      refreshSiteSummary();
    } else if (message.type === 'session_stopped') {
      hideSessionConfirmBar();
      feedPaused = false;
      currentSession = currentSession ? { ...currentSession, active: false } : null;
      stopSessionTimer();
      const overlay = document.getElementById('feed-pause-overlay');
      if (overlay) overlay.hidden = true;
      updateFeedHeaderDot();
      updateStatus('Stopped (total: ' + requestCount + ')');
      updateSessionButton(false);
      renderFeed(false);
    } else if (message.type === 'feed_paused') {
      feedPaused = true;
      if (message.elapsed_seconds != null) frozenElapsedSeconds = message.elapsed_seconds;
      else if (currentSession && sessionStartTime) frozenElapsedSeconds = Math.floor((Date.now() - sessionStartTime) / 1000);
      stopSessionTimer();
      const overlay = document.getElementById('feed-pause-overlay');
      if (overlay) overlay.hidden = false;
      updateFeedHeaderDot();
      updatePauseButton();
      updateTimerDisplay();
    } else if (message.type === 'feed_resumed') {
      feedPaused = false;
      if (currentSession && currentSession.active) {
        sessionStartTime = Date.now() - frozenElapsedSeconds * 1000;
        startSessionTimer();
      }
      const overlay = document.getElementById('feed-pause-overlay');
      if (overlay) overlay.hidden = true;
      updateFeedHeaderDot();
      updatePauseButton();
      updateTimerDisplay();
      renderFeed(false);
    }
  });
}

// ─── History overlay ──────────────────────────────────────────────────────────

function historyOverlayOpen() {
  const el = document.getElementById('history-overlay');
  return el ? el.classList.contains('history-overlay--open') : false;
}

function openHistoryOverlay() {
  const el = document.getElementById('history-overlay');
  if (!el) return;
  el.classList.add('history-overlay--open');
  el.setAttribute('aria-hidden', 'false');
  renderHistoryOverlay();
}

function closeHistoryOverlay() {
  const el = document.getElementById('history-overlay');
  if (!el) return;
  el.classList.remove('history-overlay--open');
  el.setAttribute('aria-hidden', 'true');
}

function formatHistoryDate(ts) {
  if (!ts) return '—';
  const d = new Date(ts);
  return d.toLocaleDateString(undefined, { month: 'short', day: 'numeric', year: 'numeric' })
    + ' ' + d.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit' });
}

function formatHistoryDuration(startTs, stopTs) {
  if (!startTs || !stopTs) return '—';
  const ms = stopTs - startTs;
  if (ms < 0) return '—';
  const totalSec = Math.floor(ms / 1000);
  const h = Math.floor(totalSec / 3600);
  const m = Math.floor((totalSec % 3600) / 60);
  const s = totalSec % 60;
  if (h > 0) return `${h}h ${m}m`;
  if (m > 0) return `${m}m ${s}s`;
  return `${s}s`;
}

async function renderHistoryOverlay() {
  const body = document.getElementById('history-overlay-body');
  if (!body) return;

  const result = await chrome.storage.local.get('sessions:history');
  const sessions = (result['sessions:history'] || []).slice().reverse(); // newest first

  if (sessions.length === 0) {
    body.innerHTML = `
      <div class="history-empty">
        <div class="history-empty-icon">⧗</div>
        <div class="history-empty-title">NO SESSIONS YET</div>
        <div class="history-empty-hint">Complete a session to see it recorded here.</div>
      </div>`;
    return;
  }

  const rows = sessions.map((s, i) => {
    const worstScore = s.worst_score ?? 100;
    const worstClass = worstScore < 40 ? ' history-td-worst--bad' : '';
    const worstLabel = s.worst_domain
      ? `${s.worst_domain} (${worstScore})`
      : `${worstScore}/100`;
    const trackerCount = s.tracker_count ?? '—';
    return `
      <tr data-session-idx="${i}" data-session-id="${s.id}">
        <td class="history-td-date">${formatHistoryDate(s.started_at)}</td>
        <td class="history-td-duration">${formatHistoryDuration(s.started_at, s.stopped_at)}</td>
        <td class="history-td-sites td-right">${s.sites_visited ?? '—'}</td>
        <td class="history-td-trackers td-right">${trackerCount}</td>
        <td class="history-td-worst${worstClass}" title="${s.worst_domain || ''}">${worstLabel}</td>
        <td>
          <div class="history-row-actions">
            <button type="button" class="history-action-btn history-export-btn" data-idx="${i}" title="Export summary JSON">SUMMARY</button>
            <button type="button" class="history-action-btn history-full-export-btn" data-idx="${i}" title="Export full session data (requests + scores)">FULL</button>
            <button type="button" class="history-action-btn history-action-btn--danger history-delete-btn" data-idx="${i}" title="Delete this session">DELETE</button>
          </div>
        </td>
      </tr>`;
  }).join('');

  body.innerHTML = `
    <table class="history-table">
      <thead>
        <tr>
          <th>DATE / TIME</th>
          <th>DURATION</th>
          <th class="th-right">SITES</th>
          <th class="th-right">TRACKERS</th>
          <th>WORST DOMAIN</th>
          <th></th>
        </tr>
      </thead>
      <tbody id="history-table-body">
        ${rows}
      </tbody>
    </table>`;

  // Bind summary export buttons
  body.querySelectorAll('.history-export-btn').forEach((btn) => {
    btn.addEventListener('click', () => {
      const idx = parseInt(btn.dataset.idx, 10);
      const session = sessions[idx];
      if (!session) return;
      const blob = new Blob([JSON.stringify(session, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `specter-summary-${session.id}.json`;
      a.click();
      URL.revokeObjectURL(url);
    });
  });

  // Bind full export buttons (summary + requests + scores)
  body.querySelectorAll('.history-full-export-btn').forEach((btn) => {
    btn.addEventListener('click', async () => {
      const idx = parseInt(btn.dataset.idx, 10);
      const session = sessions[idx];
      if (!session) return;

      btn.textContent = '…';
      btn.disabled = true;

      try {
        const res = await chrome.storage.local.get([
          'requests:' + session.id,
          'scores:' + session.id,
        ]);
        const payload = {
          summary: session,
          requests: res['requests:' + session.id] || [],
          scores: res['scores:' + session.id] || {},
        };
        const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `specter-full-${session.id}.json`;
        a.click();
        URL.revokeObjectURL(url);
      } finally {
        btn.textContent = 'FULL';
        btn.disabled = false;
      }
    });
  });

  // Bind delete buttons (inline confirm pattern)
  body.querySelectorAll('.history-delete-btn').forEach((btn) => {
    btn.addEventListener('click', async () => {
      if (btn.dataset.confirm === 'pending') {
        // Confirmed — delete
        const idx = parseInt(btn.dataset.idx, 10);
        const target = sessions[idx];
        if (!target) return;
        const res = await chrome.storage.local.get('sessions:history');
        const all = res['sessions:history'] || [];
        const updated = all.filter((s) => s.id !== target.id);
        await chrome.storage.local.set({ 'sessions:history': updated });
        // Also remove associated request/score data to free space
        await chrome.storage.local.remove([
          'requests:' + target.id,
          'scores:' + target.id,
        ]);
        renderHistoryOverlay();
      } else {
        // First click — show confirm state
        btn.textContent = 'CONFIRM?';
        btn.dataset.confirm = 'pending';
        btn.classList.add('history-action-btn--confirm');
        btn.classList.remove('history-action-btn--danger');
        // Auto-revert after 3s
        setTimeout(() => {
          if (btn.dataset.confirm === 'pending') {
            btn.textContent = 'DELETE';
            btn.dataset.confirm = '';
            btn.classList.remove('history-action-btn--confirm');
            btn.classList.add('history-action-btn--danger');
          }
        }, 3000);
      }
    });
  });
}

// ─── Settings overlay ──────────────────────────────────────────────────────

function settingsOverlayOpen() {
  const el = document.getElementById('settings-overlay');
  return el ? el.classList.contains('settings-overlay--open') : false;
}

function openSettingsOverlay() {
  const el = document.getElementById('settings-overlay');
  if (!el) return;
  el.classList.add('settings-overlay--open');
  el.setAttribute('aria-hidden', 'false');
  renderSettingsOverlay();
}

function closeSettingsOverlay() {
  const el = document.getElementById('settings-overlay');
  if (!el) return;
  el.classList.remove('settings-overlay--open');
  el.setAttribute('aria-hidden', 'true');
}

async function saveSettingField(key, value) {
  const { settings: stored } = await chrome.storage.local.get('settings');
  const next = { ...(stored || {}), [key]: value };
  await chrome.storage.local.set({ settings: next });
  settings[key] = value;
}

async function pruneOldSessions() {
  const { settings: s } = await chrome.storage.local.get('settings');
  const days = Number(s?.data_retention_days ?? 30);
  if (!days || days <= 0) return; // 0 = never prune
  const cutoff = Date.now() - days * 24 * 60 * 60 * 1000;
  const result = await chrome.storage.local.get('sessions:history');
  const history = result['sessions:history'] || [];
  const expired = history.filter((h) => h.stopped_at && h.stopped_at < cutoff);
  if (expired.length === 0) return;
  const kept = history.filter((h) => !h.stopped_at || h.stopped_at >= cutoff);
  const keysToRemove = expired.flatMap((h) => ['requests:' + h.id, 'scores:' + h.id]);
  await chrome.storage.local.set({ 'sessions:history': kept });
  if (keysToRemove.length > 0) await chrome.storage.local.remove(keysToRemove);
}

async function renderSettingsOverlay() {
  const body = document.getElementById('settings-overlay-body');
  if (!body) return;

  const { settings: stored } = await chrome.storage.local.get('settings');
  const s = { autoscroll_feed: true, data_retention_days: 30, virustotal_api_key: '', ...(stored || {}) };

  const retentionOptions = [
    { value: 7,  label: '7 days'  },
    { value: 14, label: '14 days' },
    { value: 30, label: '30 days' },
    { value: 90, label: '90 days' },
    { value: 0,  label: 'Never'   },
  ];
  const retentionSelect = retentionOptions
    .map((o) => `<option value="${o.value}"${Number(s.data_retention_days) === o.value ? ' selected' : ''}>${o.label}</option>`)
    .join('');

  body.innerHTML = `
    <div class="settings-section">
      <div class="settings-section-title">FEED</div>

      <div class="settings-row">
        <div class="settings-row-label">
          <div class="settings-row-title">Autoscroll</div>
          <div class="settings-row-hint">Keep the feed scrolled to the latest request</div>
        </div>
        <label class="settings-toggle" aria-label="Autoscroll feed">
          <input type="checkbox" id="setting-autoscroll"${s.autoscroll_feed ? ' checked' : ''}>
          <span class="settings-toggle-track"></span>
        </label>
      </div>

      <div class="settings-row">
        <div class="settings-row-label">
          <div class="settings-row-title">Data retention</div>
          <div class="settings-row-hint">Automatically delete sessions older than this</div>
        </div>
        <select id="setting-retention" class="settings-select">
          ${retentionSelect}
        </select>
      </div>
    </div>

    <div class="settings-section">
      <div class="settings-section-title">INTEGRATIONS</div>

      <div class="settings-row">
        <div class="settings-row-label">
          <div class="settings-row-title">VirusTotal API key</div>
          <div class="settings-row-hint">Used to look up domain reputation in request detail</div>
        </div>
        <div class="settings-vt-wrap">
          <div class="settings-vt-input-row">
            <input
              type="password"
              id="setting-vt-key"
              class="settings-input"
              value="${s.virustotal_api_key ? s.virustotal_api_key.replace(/./g, '●') : ''}"
              data-real-value="${s.virustotal_api_key || ''}"
              placeholder="Paste API key…"
              autocomplete="off"
              spellcheck="false"
            >
            <button type="button" class="settings-test-btn" id="settings-vt-test">TEST</button>
          </div>
          <span class="settings-vt-status" id="settings-vt-status"></span>
        </div>
      </div>
    </div>

    <div class="settings-danger-zone">
      <div class="settings-danger-label">
        <div class="settings-danger-label-title">Clear all session data</div>
        <div class="settings-danger-label-hint">Permanently deletes all recorded sessions, requests, and scores</div>
      </div>
      <button type="button" class="settings-danger-btn" id="settings-clear-data">CLEAR ALL DATA</button>
    </div>`;

  // Autoscroll toggle
  document.getElementById('setting-autoscroll').addEventListener('change', (e) => {
    saveSettingField('autoscroll_feed', e.target.checked);
    settings.autoscroll_feed = e.target.checked;
  });

  // Retention select
  document.getElementById('setting-retention').addEventListener('change', (e) => {
    saveSettingField('data_retention_days', Number(e.target.value));
  });

  // VT key — clear placeholder on first focus so user can type a real key
  const vtInput = document.getElementById('setting-vt-key');
  vtInput.addEventListener('focus', () => {
    if (vtInput.dataset.realValue != null) {
      vtInput.type = 'text';
      vtInput.value = vtInput.dataset.realValue;
    }
  });
  vtInput.addEventListener('blur', async () => {
    const key = vtInput.value.trim();
    vtInput.dataset.realValue = key;
    vtInput.type = 'password';
    vtInput.value = key ? key.replace(/./g, '●') : '';
    await saveSettingField('virustotal_api_key', key);
  });

  // VT test button
  const vtStatus = document.getElementById('settings-vt-status');
  const testBtn = document.getElementById('settings-vt-test');
  testBtn.addEventListener('click', async () => {
    const key = vtInput.dataset.realValue || vtInput.value.replace(/●/g, '').trim();
    if (!key) {
      vtStatus.textContent = 'Enter a key first';
      vtStatus.className = 'settings-vt-status settings-vt-status--error';
      return;
    }
    testBtn.textContent = '…';
    testBtn.disabled = true;
    vtStatus.textContent = '';
    vtStatus.className = 'settings-vt-status';
    try {
      const resp = await fetch('https://www.virustotal.com/api/v3/domains/example.com', {
        headers: { 'x-apikey': key },
      });
      if (resp.ok) {
        vtStatus.textContent = 'Valid ✓';
        vtStatus.className = 'settings-vt-status settings-vt-status--ok';
        await saveSettingField('virustotal_api_key', key);
      } else if (resp.status === 401 || resp.status === 403) {
        vtStatus.textContent = 'Invalid key';
        vtStatus.className = 'settings-vt-status settings-vt-status--error';
      } else {
        vtStatus.textContent = 'Error ' + resp.status;
        vtStatus.className = 'settings-vt-status settings-vt-status--error';
      }
    } catch {
      vtStatus.textContent = 'Network error';
      vtStatus.className = 'settings-vt-status settings-vt-status--error';
    } finally {
      testBtn.textContent = 'TEST';
      testBtn.disabled = false;
    }
  });

  // Clear all data
  const clearBtn = document.getElementById('settings-clear-data');
  clearBtn.addEventListener('click', async () => {
    if (clearBtn.dataset.confirm === 'pending') {
      clearBtn.disabled = true;
      try {
        const all = await chrome.storage.local.get(null);
        const keysToRemove = Object.keys(all).filter(
          (k) => k.startsWith('requests:') || k.startsWith('scores:') || k === 'sessions:history'
        );
        if (keysToRemove.length > 0) await chrome.storage.local.remove(keysToRemove);
        // Reset active session state
        await chrome.storage.local.set({
          'session:current': null,
          'session:paused': false,
          'session:elapsed_frozen': 0,
        });
        clearBtn.textContent = 'CLEARED ✓';
        clearBtn.className = 'settings-danger-btn settings-danger-btn--success';
        clearBtn.dataset.confirm = '';
        setTimeout(() => {
          clearBtn.textContent = 'CLEAR ALL DATA';
          clearBtn.className = 'settings-danger-btn';
          clearBtn.disabled = false;
        }, 2500);
      } catch {
        clearBtn.textContent = 'CLEAR ALL DATA';
        clearBtn.className = 'settings-danger-btn';
        clearBtn.dataset.confirm = '';
        clearBtn.disabled = false;
      }
    } else {
      clearBtn.textContent = 'CONFIRM — CANNOT UNDO';
      clearBtn.dataset.confirm = 'pending';
      clearBtn.className = 'settings-danger-btn settings-danger-btn--confirm';
      setTimeout(() => {
        if (clearBtn.dataset.confirm === 'pending') {
          clearBtn.textContent = 'CLEAR ALL DATA';
          clearBtn.dataset.confirm = '';
          clearBtn.className = 'settings-danger-btn';
        }
      }, 3500);
    }
  });
}

function initSettingsOverlay() {
  const navBtn = document.getElementById('settings-nav-btn');
  if (navBtn) {
    navBtn.addEventListener('click', () => {
      if (settingsOverlayOpen()) {
        closeSettingsOverlay();
        navBtn.classList.remove('active');
      } else {
        // Close history if open
        if (historyOverlayOpen()) {
          closeHistoryOverlay();
          const histBtn = document.getElementById('history-nav-btn');
          if (histBtn) histBtn.classList.remove('active');
        }
        openSettingsOverlay();
        navBtn.classList.add('active');
      }
    });
  }
  const backBtn = document.getElementById('settings-back-btn');
  if (backBtn) {
    backBtn.addEventListener('click', () => {
      closeSettingsOverlay();
      if (navBtn) navBtn.classList.remove('active');
    });
  }
}

function initHistoryOverlay() {
  const navBtn = document.getElementById('history-nav-btn');
  if (navBtn) {
    navBtn.addEventListener('click', () => {
      if (historyOverlayOpen()) {
        closeHistoryOverlay();
        navBtn.classList.remove('active');
      } else {
        openHistoryOverlay();
        navBtn.classList.add('active');
      }
    });
  }
  const backBtn = document.getElementById('history-back-btn');
  if (backBtn) {
    backBtn.addEventListener('click', () => {
      closeHistoryOverlay();
      if (navBtn) navBtn.classList.remove('active');
    });
  }
}

// ── Training Crawl ────────────────────────────────────────────────────────────

let CRAWL_SITES = [];

async function loadCrawlSites() {
  if (CRAWL_SITES.length > 0) return;
  try {
    const res  = await fetch(chrome.runtime.getURL('data/sites.txt'));
    const text = await res.text();
    CRAWL_SITES = text.split('\n')
      .map(l => l.trim())
      .filter(l => l && !l.startsWith('#'));
  } catch (e) {
    console.warn('[Specter] Failed to load sites.txt:', e);
  }
}

const CRAWL_DWELL_MS = 6000;
let crawlRunning      = false;
let crawlStartedAt    = 0;
let crawlReqCount     = 0;
let crawlTrackerCount = 0;
let crawlVisited      = []; // URLs visited so far, most recent first
/** Sites in the current/last crawl (custom or default); synced from start + service worker messages */
let crawlUrlCount = 0;
let crawlProgressIndex = 0;
let crawlCurrentUrl = '';

function fmtDuration(ms) {
  if (ms <= 0) return '—';
  const s = Math.round(ms / 1000);
  const m = Math.floor(s / 60);
  const h = Math.floor(m / 60);
  if (h > 0)  return `${h}h ${m % 60}m`;
  if (m > 0)  return `${m}m ${s % 60}s`;
  return `${s}s`;
}

function crawlOverlayOpen() {
  const el = document.getElementById('crawl-overlay');
  return el ? el.classList.contains('crawl-overlay--open') : false;
}
function openCrawlOverlay() {
  const el = document.getElementById('crawl-overlay');
  if (el) { el.classList.add('crawl-overlay--open'); el.removeAttribute('aria-hidden'); }
  renderCrawlPanel({
    running: crawlRunning,
    index: crawlProgressIndex,
    total: crawlUrlCount || CRAWL_SITES.length,
    url: crawlCurrentUrl,
  });
}
function closeCrawlOverlay() {
  const el = document.getElementById('crawl-overlay');
  if (el) { el.classList.remove('crawl-overlay--open'); el.setAttribute('aria-hidden', 'true'); }
}

function renderCrawlPanel({ running, index, total, url, done, doneTotal }) {
  const body = document.getElementById('crawl-overlay-body');
  if (!body) return;

  const pct = total > 0 ? Math.round((index / total) * 100) : 0;

  if (done) {
    const totalTime = crawlStartedAt ? fmtDuration(Date.now() - crawlStartedAt) : '—';
    const trackerRate = crawlReqCount > 0 ? ((crawlTrackerCount / crawlReqCount) * 100).toFixed(1) : '0.0';
    body.innerHTML = `
      <p class="crawl-done-msg">✓ Crawl complete — ${doneTotal} sites visited in ${totalTime}.</p>
      <div class="crawl-stats-row">
        <div class="crawl-stat">
          <div class="crawl-stat-value">${crawlReqCount.toLocaleString()}</div>
          <div class="crawl-stat-label">REQUESTS</div>
        </div>
        <div class="crawl-stat">
          <div class="crawl-stat-value crawl-stat-value--accent">${crawlTrackerCount.toLocaleString()}</div>
          <div class="crawl-stat-label">TRACKERS</div>
        </div>
        <div class="crawl-stat">
          <div class="crawl-stat-value">${trackerRate}%</div>
          <div class="crawl-stat-label">TRACKER RATE</div>
        </div>
      </div>
      <p class="crawl-info">Stop your Specter session and use the FULL EXPORT button in Session History to save the training data.</p>
      ${crawlVisited.length > 0 ? `
      <div class="crawl-visited-wrap">
        <div class="crawl-visited-label">SITES VISITED <span class="crawl-visited-count">${crawlVisited.length}</span></div>
        <div class="crawl-visited-list">
          ${crawlVisited.map(u => `<div class="crawl-visited-item">${u}</div>`).join('')}
        </div>
      </div>` : ''}
      <button class="crawl-start-btn" id="crawl-start-btn">START NEW CRAWL</button>`;
    body.querySelector('#crawl-start-btn').addEventListener('click', () => startCrawl());
    return;
  }

  if (running) {
    const now = Date.now();
    const elapsed = crawlStartedAt ? fmtDuration(now - crawlStartedAt) : '—';
    const etaMs = crawlStartedAt && index > 0
      ? ((now - crawlStartedAt) / index) * (total - index)
      : null;
    const eta = etaMs != null ? '~' + fmtDuration(etaMs) : '—';

    body.innerHTML = `
      <div class="crawl-progress-wrap">
        <div class="crawl-progress-label">
          <span>PROGRESS</span>
          <span>${index} / ${total} <span class="crawl-pct">${pct}%</span></span>
        </div>
        <div class="crawl-progress-track"><div class="crawl-progress-fill" style="width:${pct}%"></div></div>
      </div>
      <div class="crawl-current-url" id="crawl-current-url">${url || '—'}</div>
      <div class="crawl-stats-row">
        <div class="crawl-stat">
          <div class="crawl-stat-value" id="crawl-stat-elapsed">${elapsed}</div>
          <div class="crawl-stat-label">ELAPSED</div>
        </div>
        <div class="crawl-stat">
          <div class="crawl-stat-value" id="crawl-stat-eta">${eta}</div>
          <div class="crawl-stat-label">ETA</div>
        </div>
        <div class="crawl-stat">
          <div class="crawl-stat-value" id="crawl-stat-requests">${crawlReqCount.toLocaleString()}</div>
          <div class="crawl-stat-label">REQUESTS</div>
        </div>
        <div class="crawl-stat">
          <div class="crawl-stat-value crawl-stat-value--accent" id="crawl-stat-trackers">${crawlTrackerCount.toLocaleString()}</div>
          <div class="crawl-stat-label">TRACKERS</div>
        </div>
      </div>
      <button class="crawl-stop-btn" id="crawl-stop-btn">■ STOP CRAWL</button>
      ${crawlVisited.length > 0 ? `
      <div class="crawl-visited-wrap">
        <div class="crawl-visited-label">VISITED <span class="crawl-visited-count">${crawlVisited.length}</span></div>
        <div class="crawl-visited-list" id="crawl-visited-list">
          ${crawlVisited.map(u => `<div class="crawl-visited-item">${u}</div>`).join('')}
        </div>
      </div>` : ''}`;
    body.querySelector('#crawl-stop-btn').addEventListener('click', () => stopCrawl());
    return;
  }

  // idle state — check if session is active
  chrome.storage.local.get('session:current').then((r) => {
    const sessionActive = r['session:current']?.active;
    body.innerHTML = `
      ${!sessionActive ? `<p class="crawl-warning">⚠ No active session — start a Specter session before crawling so requests are recorded.</p>` : ''}
      <p class="crawl-info">A background tab is opened and navigated automatically — webRequest captures all traffic normally.</p>
      <div class="crawl-sites-wrap">
        <div class="crawl-sites-header">
          <span class="crawl-sites-label">SITES TO VISIT</span>
          <span class="crawl-sites-hint" id="crawl-sites-hint">default list · ${CRAWL_SITES.length} sites</span>
        </div>
        <textarea class="crawl-textarea" id="crawl-sites-input"
          placeholder="Leave blank to use the default list (${CRAWL_SITES.length} sites)&#10;&#10;Or enter URLs to crawl, one per line:&#10;https://example.com&#10;https://another-site.com"></textarea>
      </div>
      <button class="crawl-start-btn" id="crawl-start-btn">▶ START CRAWL</button>`;
    const ta   = body.querySelector('#crawl-sites-input');
    const hint = body.querySelector('#crawl-sites-hint');
    ta.addEventListener('input', () => {
      const urls = ta.value.trim().split('\n').map(l => l.trim()).filter(l => l && !l.startsWith('#'));
      if (ta.value.trim()) {
        hint.textContent = `custom · ${urls.length} site${urls.length !== 1 ? 's' : ''}`;
        hint.className = 'crawl-sites-hint crawl-sites-hint--custom';
      } else {
        hint.textContent = `default list · ${CRAWL_SITES.length} sites`;
        hint.className = 'crawl-sites-hint';
      }
    });
    body.querySelector('#crawl-start-btn').addEventListener('click', () => startCrawl());
  });
}

function normalizeCrawlUrl(u) {
  return /^https?:\/\//i.test(u) ? u : 'https://' + u;
}
function startCrawl() {
  const ta = document.getElementById('crawl-sites-input');
  const customText = ta ? ta.value.trim() : '';
  const urls = customText
    ? customText.split('\n').map(l => l.trim()).filter(l => l && !l.startsWith('#')).map(normalizeCrawlUrl)
    : CRAWL_SITES;
  if (urls.length === 0) return;
  crawlRunning      = true;
  crawlStartedAt    = Date.now();
  crawlReqCount     = 0;
  crawlTrackerCount = 0;
  crawlVisited      = [];
  crawlUrlCount     = urls.length;
  crawlProgressIndex = 0;
  crawlCurrentUrl   = '';
  renderCrawlPanel({ running: true, index: 0, total: urls.length, url: '' });
  chrome.runtime.sendMessage({ type: 'start_crawl', urls, dwell_ms: CRAWL_DWELL_MS });
}

function stopCrawl() {
  crawlRunning = false;
  chrome.runtime.sendMessage({ type: 'stop_crawl' });
  crawlProgressIndex = 0;
  crawlCurrentUrl = '';
  renderCrawlPanel({
    running: false,
    index: 0,
    total: crawlUrlCount || CRAWL_SITES.length,
    url: '',
  });
}

/**
 * After dashboard reload, in-memory crawl flags are lost but the service worker
 * keeps `crawl:state` in session storage while a crawl runs. Restore flags so
 * `request_update` can keep incrementing crawl stat counters.
 */
async function restoreCrawlStateFromSession() {
  try {
    const r = await chrome.storage.session.get('crawl:state');
    const state = r['crawl:state'];
    if (!state || !state.active || !Array.isArray(state.urls) || state.urls.length === 0) return;

    crawlRunning = true;
    crawlUrlCount = state.urls.length;
    crawlStartedAt =
      typeof state.startedAt === 'number' && Number.isFinite(state.startedAt) ? state.startedAt : Date.now();
    if (typeof state.index === 'number' && Number.isFinite(state.index) && state.index >= 0) {
      crawlProgressIndex = state.index;
    }
    const n = Math.min(state.index, state.urls.length);
    const chronological = state.urls.slice(0, n);
    crawlVisited = chronological.slice().reverse();
    const lastI = n - 1;
    crawlCurrentUrl = lastI >= 0 ? normalizeCrawlUrl(state.urls[lastI]) : '';
  } catch (e) {
    console.warn('[Specter] restoreCrawlStateFromSession:', e);
  }
}

async function initCrawlOverlay() {
  await loadCrawlSites();
  await restoreCrawlStateFromSession();
  const navBtn  = document.getElementById('crawl-nav-btn');
  const backBtn = document.getElementById('crawl-back-btn');

  if (navBtn) {
    navBtn.addEventListener('click', () => {
      if (crawlOverlayOpen()) {
        closeCrawlOverlay();
        navBtn.classList.remove('active');
      } else {
        openCrawlOverlay();
        navBtn.classList.add('active');
      }
    });
  }
  if (backBtn) {
    backBtn.addEventListener('click', () => {
      closeCrawlOverlay();
      if (navBtn) navBtn.classList.remove('active');
    });
  }

  // Listen for crawl broadcast messages from SW
  chrome.runtime.onMessage.addListener((message) => {
    if (message.type === 'crawl_started') {
      crawlRunning = true;
      if (typeof message.total === 'number' && Number.isFinite(message.total) && message.total >= 0) {
        crawlUrlCount = message.total;
      }
      if (!crawlStartedAt) crawlStartedAt = Date.now();
    }
    if (message.type === 'crawl_progress') {
      if (message.startedAt) crawlStartedAt = message.startedAt;
      if (typeof message.total === 'number' && Number.isFinite(message.total) && message.total >= 0) {
        crawlUrlCount = message.total;
      }
      if (typeof message.index === 'number' && Number.isFinite(message.index) && message.index >= 0) {
        crawlProgressIndex = message.index;
      }
      if (typeof message.url === 'string' && message.url) {
        crawlVisited.unshift(message.url);
        crawlCurrentUrl = message.url;
      }
      if (crawlOverlayOpen()) {
        const totalUi = Math.max(1, crawlUrlCount || CRAWL_SITES.length || 1);
        renderCrawlPanel({
          running: true,
          index: crawlProgressIndex,
          total: totalUi,
          url: crawlCurrentUrl,
        });
      }
    }
    if (message.type === 'crawl_done') {
      crawlRunning = false;
      if (typeof message.total === 'number' && Number.isFinite(message.total) && message.total >= 0) {
        crawlUrlCount = message.total;
      }
      if (crawlOverlayOpen()) {
        const doneTotal =
          typeof message.total === 'number' && Number.isFinite(message.total) && message.total >= 0
            ? message.total
            : crawlUrlCount;
        renderCrawlPanel({ done: true, doneTotal: Math.max(0, doneTotal || 0) });
      }
    }
    if (message.type === 'crawl_stopped') {
      crawlRunning = false;
      crawlProgressIndex = 0;
      crawlCurrentUrl = '';
      if (crawlOverlayOpen()) {
        renderCrawlPanel({
          running: false,
          index: 0,
          total: crawlUrlCount || CRAWL_SITES.length,
          url: '',
        });
      }
    }
    // Count requests + trackers live — update in-place so no full re-render per request
    if (message.type === 'request_update' && crawlRunning) {
      crawlReqCount++;
      const cat = message.request?.category;
      if (cat && cat !== 'legitimate' && cat !== 'unclassified') crawlTrackerCount++;
      const reqEl = document.getElementById('crawl-stat-requests');
      const trkEl = document.getElementById('crawl-stat-trackers');
      const elEl  = document.getElementById('crawl-stat-elapsed');
      if (reqEl) reqEl.textContent = crawlReqCount.toLocaleString();
      if (trkEl) trkEl.textContent = crawlTrackerCount.toLocaleString();
      if (elEl && crawlStartedAt) elEl.textContent = fmtDuration(Date.now() - crawlStartedAt);
    }
  });
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', init);
} else {
  init();
}
