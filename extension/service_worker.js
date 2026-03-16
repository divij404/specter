/* Specter — service worker: rule-based classifier + blocklist (no ONNX in SW) */

// ONNX Runtime fails in extension service workers (WASM init errors). We use a rule-based
// classifier instead. Same API as before so you can swap in ONNX or TensorFlow.js later
// (e.g. in an offscreen document or dashboard page).

let blocklistDomains = new Set();

async function initModel() {
  // No-op: no ONNX in service worker. Rule-based classify() used below.
  console.log('Specter: using rule-based classifier (no ONNX in service worker)');
}

async function initBlocklist() {
  try {
    const url = chrome.runtime.getURL('data/blocklist.json');
    const res = await fetch(url);
    const list = await res.json();
    blocklistDomains = new Set(Array.isArray(list) ? list : []);
  } catch (e) {
    console.warn('Specter: blocklist not loaded, using empty set', e);
    blocklistDomains = new Set();
  }
}

function getHeader(headers, name) {
  if (!headers) return null;
  const lower = name.toLowerCase();
  const entry = headers.find((h) => (h.name || h).toLowerCase?.() === lower);
  return entry ? (entry.value ?? entry) : null;
}

function getResponseSize(headers) {
  const contentLength = getHeader(headers, 'content-length');
  if (contentLength) return parseInt(contentLength, 10) || 0;
  return 0;
}

function headersToObject(headers) {
  if (!headers || !headers.length) return {};
  const out = {};
  for (const h of headers) {
    const name = (h.name || h).toLowerCase?.();
    const value = h.value ?? h;
    if (name) out[name] = value;
  }
  return out;
}

const NAV_START_CACHE = new Map();
function getNavStartTime(tabId) {
  return NAV_START_CACHE.get(tabId) ?? 0;
}

function extractETLDPlusOne(hostname) {
  if (!hostname) return '';
  const parts = hostname.split('.');
  if (parts.length <= 2) return hostname;
  return parts.slice(-2).join('.');
}

function extractFeatures(details) {
  let url;
  try {
    url = new URL(details.url);
  } catch {
    return null;
  }
  const trackingParams = ['fbclid', 'gclid', '_ga', 'uid', 'cid', 'sid', 'fp', 'visitor_id', 'tracking_id'];
  const params = [...url.searchParams.keys()];
  const initiatorDomain = details.initiator
    ? (() => {
        try {
          return extractETLDPlusOne(new URL(details.initiator).hostname);
        } catch {
          return '';
        }
      })()
    : '';

  return {
    url: details.url,
    domain: extractETLDPlusOne(url.hostname),
    method: details.method || 'GET',
    initiator_domain: initiatorDomain,
    tab_id: details.tabId,
    query_param_count: params.length,
    has_tracking_params: params.some((p) => trackingParams.includes(p)),
    url_length: details.url.length,
    response_status: details.statusCode || 0,
    response_size_bytes: getResponseSize(details.responseHeaders),
    content_type: (getHeader(details.responseHeaders, 'content-type') || '').split(';')[0].trim(),
    has_set_cookie: !!getHeader(details.responseHeaders, 'set-cookie'),
    has_no_cache: (getHeader(details.responseHeaders, 'cache-control') || '').includes('no-store'),
    has_cors_header: !!getHeader(details.responseHeaders, 'access-control-allow-origin'),
    ms_since_nav_start: details.timeStamp - getNavStartTime(details.tabId),
    request_headers: headersToObject(details.requestHeaders || []),
    response_headers: headersToObject(details.responseHeaders || []),
  };
}

const CATEGORIES = ['behavioral', 'fingerprinting', 'session_replay', 'ad_network', 'analytics', 'legitimate'];
const FEATURE_NAMES = [
  'query_param_count', 'has_tracking_params', 'url_length', 'response_status',
  'response_size_bytes', 'has_set_cookie', 'has_no_cache', 'has_cors_header',
  'ms_since_nav_start', 'content_type', 'has_referer', 'has_origin',
  'path_segment_count', 'domain_parts', 'url_length_log', 'response_status_ok',
];

function getTopFeatureImportances(features, topN) {
  const scores = [];
  if (features.has_tracking_params) scores.push({ feature: 'has_tracking_params', importance: 0.4 });
  if (features.response_size_bytes <= 100 && (features.content_type || '').includes('image')) scores.push({ feature: 'response_size_bytes', importance: 0.35 });
  if (features.has_set_cookie) scores.push({ feature: 'has_set_cookie', importance: 0.3 });
  if (features.query_param_count > 3) scores.push({ feature: 'query_param_count', importance: 0.25 });
  if (blocklistDomains.has(features.domain)) scores.push({ feature: 'blocklist_domain', importance: 0.5 });
  scores.sort((a, b) => b.importance - a.importance);
  return scores.slice(0, topN);
}

/**
 * Rule-based classifier: same output shape as ML (category, confidence, feature_importances).
 * Uses blocklist + URL/header heuristics. No WASM/ONNX required.
 */
function classifyRuleBased(features) {
  if (!features) return { category: 'unclassified', confidence: 0.0, feature_importances: [] };
  const url = (features.url || '').toLowerCase();
  const path = url.split('?')[0].toLowerCase();
  const ct = (features.content_type || '').toLowerCase();
  const size = features.response_size_bytes ?? 0;
  const inBlocklist = blocklistDomains.has(features.domain);

  // Session replay: known paths (FullStory, Hotjar, Clarity, LogRocket)
  if (/\/rec\/|\/record|\/session|\/clarity|\/hotjar|\/logrocket|\/fs\.js/.test(path)) {
    return { category: 'session_replay', confidence: 0.92, feature_importances: getTopFeatureImportances(features, 3) };
  }
  // Analytics: ga, gtag, analytics, segment, mixpanel
  if (/\/ga\.js|\/gtag|\/analytics|\/segment|\/mixpanel|\/mp\.js|\/collect\b/.test(path) || /google-analytics|googletagmanager/.test(url)) {
    return { category: 'analytics', confidence: 0.88, feature_importances: getTopFeatureImportances(features, 3) };
  }
  // Fingerprinting: fp, fingerprint, canvas, fingerprintjs
  if (/fingerprint|fp\.js|\/canvas|\/fingerprintjs|evercookie/.test(path)) {
    return { category: 'fingerprinting', confidence: 0.9, feature_importances: getTopFeatureImportances(features, 3) };
  }
  // Blocklist match -> ad_network or behavioral
  if (inBlocklist) {
    return { category: 'ad_network', confidence: 0.85, feature_importances: getTopFeatureImportances(features, 3) };
  }
  // Tracking params + small response (e.g. pixel)
  if (features.has_tracking_params && size <= 200 && (ct.includes('image') || ct.includes('gif') || !ct)) {
    return { category: 'behavioral', confidence: 0.82, feature_importances: getTopFeatureImportances(features, 3) };
  }
  // Tracking params only
  if (features.has_tracking_params) {
    return { category: 'behavioral', confidence: 0.75, feature_importances: getTopFeatureImportances(features, 3) };
  }
  // CDN / fonts / known benign
  if (/\.(woff2?|ttf|otf|css|js)$/.test(path) || /cdn\.|cloudflare|googleapis|gstatic|jsdelivr|unpkg/.test(url)) {
    return { category: 'legitimate', confidence: 0.9, feature_importances: getTopFeatureImportances(features, 3) };
  }
  // Cross-origin third-party with cookies
  if (features.has_set_cookie && features.initiator_domain && features.domain !== features.initiator_domain) {
    return { category: 'analytics', confidence: 0.5, feature_importances: getTopFeatureImportances(features, 3) };
  }

  return { category: 'legitimate', confidence: 0.5, feature_importances: getTopFeatureImportances(features, 3) };
}

async function classify(features) {
  return classifyRuleBased(features);
}

self.addEventListener('install', () => {
  initModel();
  initBlocklist();
});

self.addEventListener('activate', () => {
  initModel();
  initBlocklist();
});
