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

// --- Phase 4: session, storage, interception ---

const DEFAULT_SETTINGS = {
  virustotal_api_key: '',
  autoscroll_feed: true,
  min_confidence: 0.0,
  data_retention_days: 30,
  onboarding_complete: false,
};

let requestBuffer = [];
let sessionTrackerCount = 0;

function updateBadgeCount() {
  chrome.action.setBadgeText({ text: String(sessionTrackerCount) });
  chrome.action.setBadgeBackgroundColor({ color: '#22C55E' });
}

async function ensureSettings() {
  const { settings } = await chrome.storage.local.get('settings');
  if (!settings || typeof settings !== 'object') {
    await chrome.storage.local.set({ settings: DEFAULT_SETTINGS });
  }
}

async function startSession() {
  await ensureSettings();
  sessionTrackerCount = 0;
  const id = 'session_' + Date.now();
  const session = {
    id,
    started_at: Date.now(),
    stopped_at: null,
    active: true,
  };
  await chrome.storage.local.set({
    'session:current': session,
    'session:paused': false,
    'session:elapsed_frozen': 0,
  });
  chrome.action.setBadgeBackgroundColor({ color: '#22C55E' });
  chrome.action.setBadgeText({ text: '0' });
  return session;
}

async function flushBuffer() {
  if (requestBuffer.length === 0) return;
  const sessionId = requestBuffer[0].session_id;
  const key = 'requests:' + sessionId;
  const result = await chrome.storage.local.get(key);
  const existing = result[key] || [];
  await chrome.storage.local.set({ [key]: existing.concat(requestBuffer) });
  requestBuffer = [];
}

async function stopSession() {
  await flushBuffer();
  const result = await chrome.storage.local.get('session:current');
  const session = result['session:current'];
  if (!session || !session.active) return;

  const updates = {
    'session:current': {
      ...session,
      stopped_at: Date.now(),
      active: false,
    },
    'session:paused': false,
    'session:elapsed_frozen': 0,
  };
  const reqKey = 'requests:' + session.id;
  const scoresKey = 'scores:' + session.id;
  const [reqResult, scoresResult] = await Promise.all([
    chrome.storage.local.get(reqKey),
    chrome.storage.local.get(scoresKey),
  ]);
  const requests = reqResult[reqKey] || [];
  const scores = scoresResult[scoresKey] || {};
  const scoreEntries = Object.values(scores);
  const total_requests = requests.length;
  const sites_visited = scoreEntries.length;
  let worst_score = 100;
  let worst_domain = '';
  for (const s of scoreEntries) {
    if (s.privacy_score < worst_score) {
      worst_score = s.privacy_score;
      worst_domain = s.domain || '';
    }
  }
  const summary = {
    id: session.id,
    started_at: session.started_at,
    stopped_at: updates['session:current'].stopped_at,
    total_requests,
    sites_visited,
    worst_domain: worst_domain || null,
    worst_score,
  };
  const histResult = await chrome.storage.local.get('sessions:history');
  const history = histResult['sessions:history'] || [];
  updates['sessions:history'] = history.concat(summary);
  await chrome.storage.local.set(updates);
  chrome.action.setBadgeText({ text: '' });
}

function broadcastToDashboard(message) {
  chrome.runtime.sendMessage(message).catch(() => {});
}

async function updateSiteScore(initiatorDomain, requestDomain, category) {
  const siteDomain = initiatorDomain || '_direct';
  const sessionResult = await chrome.storage.local.get('session:current');
  const session = sessionResult['session:current'];
  if (!session || !session.active) return;
  const scoresKey = 'scores:' + session.id;
  const scoresResult = await chrome.storage.local.get(scoresKey);
  const scores = scoresResult[scoresKey] || {};
  let entry = scores[siteDomain];
  if (!entry) {
    entry = {
      domain: siteDomain,
      privacy_score: 100,
      total_requests: 0,
      tracker_requests: 0,
      has_session_replay: false,
      has_fingerprinting: false,
      unique_tracker_domains: 0,
      unique_behavioral: [],
      unique_fingerprinting: [],
      unique_ad_network: [],
      unique_analytics: [],
      last_updated: Date.now(),
    };
    scores[siteDomain] = entry;
  }
  entry.total_requests += 1;
  if (category !== 'legitimate' && category !== 'unclassified') {
    entry.tracker_requests += 1;
    if (category === 'session_replay') entry.has_session_replay = true;
    if (category === 'fingerprinting') entry.has_fingerprinting = true;
    if (category === 'behavioral' && !entry.unique_behavioral.includes(requestDomain)) entry.unique_behavioral.push(requestDomain);
    if (category === 'fingerprinting' && !entry.unique_fingerprinting.includes(requestDomain)) entry.unique_fingerprinting.push(requestDomain);
    if (category === 'ad_network' && !entry.unique_ad_network.includes(requestDomain)) entry.unique_ad_network.push(requestDomain);
    if (category === 'analytics' && !entry.unique_analytics.includes(requestDomain)) entry.unique_analytics.push(requestDomain);
  }
  let deduction = 0;
  deduction += (entry.unique_behavioral?.length || 0) * 4;
  deduction += (entry.unique_fingerprinting?.length || 0) * 5;
  if (entry.has_session_replay) deduction += 25;
  deduction += (entry.unique_ad_network?.length || 0) * 2;
  deduction += (entry.unique_analytics?.length || 0) * 1;
  if (entry.tracker_requests > 50) deduction += 5;
  if (entry.tracker_requests > 100) deduction += 5;
  entry.unique_tracker_domains =
    (entry.unique_behavioral?.length || 0) +
    (entry.unique_fingerprinting?.length || 0) +
    (entry.unique_ad_network?.length || 0) +
    (entry.unique_analytics?.length || 0) +
    (entry.has_session_replay ? 1 : 0);
  entry.privacy_score = Math.max(0, 100 - deduction);
  entry.last_updated = Date.now();
  await chrome.storage.local.set({ [scoresKey]: scores });
}

async function batchWrite(request) {
  requestBuffer.push(request);
  if (requestBuffer.length >= 10) await flushBuffer();
}

chrome.webRequest.onBeforeRequest.addListener(
  (details) => {
    if (details.type === 'main_frame') NAV_START_CACHE.set(details.tabId, details.timeStamp);
  },
  { urls: ['<all_urls>'], types: ['main_frame'] }
);

chrome.webRequest.onCompleted.addListener(
  async (details) => {
    if (!details.url || (!details.url.startsWith('http:') && !details.url.startsWith('https:'))) return;
    const { 'session:current': session } = await chrome.storage.local.get('session:current');
    if (!session || !session.active) return;
    const features = extractFeatures(details);
    if (!features) return;
    const classification = await classify(features);
    const request = {
      id: 'req_' + details.timeStamp + '_' + details.requestId,
      session_id: session.id,
      captured_at: details.timeStamp,
      ...features,
      category: classification.category,
      confidence: classification.confidence,
      feature_importances: classification.feature_importances,
    };
    await batchWrite(request);
    if (classification.category !== 'legitimate' && classification.category !== 'unclassified') {
      sessionTrackerCount += 1;
      updateBadgeCount();
    }
    await updateSiteScore(features.initiator_domain, features.domain, classification.category);
    broadcastToDashboard({ type: 'request_update', request });
  },
  { urls: ['<all_urls>'] },
  ['responseHeaders', 'extraHeaders']
);

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (message.type === 'start_session') {
    startSession().then((session) => {
      broadcastToDashboard({ type: 'session_started', session_id: session.id });
      sendResponse({ ok: true, session_id: session.id });
    });
    return true;
  }
  if (message.type === 'stop_session') {
    chrome.storage.local.get('session:current').then((r) => {
      const sessionId = r['session:current']?.id;
      stopSession().then(() => {
        if (sessionId) broadcastToDashboard({ type: 'session_stopped', session_id: sessionId });
        sendResponse({ ok: true });
      });
    });
    return true;
  }
  if (message.type === 'pause_session') {
    const elapsed = message.elapsed_seconds ?? 0;
    chrome.storage.local.set({ 'session:paused': true, 'session:elapsed_frozen': elapsed }).then(() => {
      broadcastToDashboard({ type: 'feed_paused', elapsed_seconds: elapsed });
      sendResponse({ ok: true });
    });
    return true;
  }
  if (message.type === 'resume_session') {
    chrome.storage.local.set({ 'session:paused': false, 'session:elapsed_frozen': 0 }).then(() => {
      broadcastToDashboard({ type: 'feed_resumed' });
      sendResponse({ ok: true });
    });
    return true;
  }
  if (message.type === 'get_session_data') {
    const sid = message.session_id;
    flushBuffer()
      .then(() => chrome.storage.local.get(['session:current', 'requests:' + sid, 'scores:' + sid]))
      .then((result) => {
        sendResponse({
          session: result['session:current'],
          requests: result['requests:' + sid] || [],
          scores: result['scores:' + sid],
        });
      })
      .catch((err) => {
        console.warn('Specter get_session_data:', err);
        sendResponse({ session: null, requests: [], scores: {} });
      });
    return true;
  }
  sendResponse({ ok: false });
});

self.addEventListener('install', () => {
  initModel();
  initBlocklist();
  ensureSettings();
});

self.addEventListener('activate', () => {
  initModel();
  initBlocklist();
});
