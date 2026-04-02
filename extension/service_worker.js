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

// Maps tabId → eTLD+1 of the top-level page — used to correctly attribute
// requests from embedded iframes (e.g. ext-twitch.tv, googlesyndication.com)
// back to the actual page the user is on.
const TAB_URL_CACHE = new Map();

// ── Crawl state (persisted in session storage so SW restarts don't lose it) ───
let crawlState = null;

async function loadCrawlState() {
  if (crawlState) return crawlState;
  const r = await chrome.storage.session.get('crawl:state');
  crawlState = r['crawl:state'] || null;
  return crawlState;
}
async function saveCrawlState(state) {
  crawlState = state;
  if (state) await chrome.storage.session.set({ 'crawl:state': state });
  else        await chrome.storage.session.remove('crawl:state');
}

// Restore crawl state on SW wake-up (zero-cost if no crawl is running)
chrome.storage.session.get('crawl:state').then((r) => { crawlState = r['crawl:state'] || null; });
chrome.tabs.onRemoved.addListener((tabId) => {
  TAB_URL_CACHE.delete(tabId);
  NAV_START_CACHE.delete(tabId);
});

// Known second-level TLDs that require 3 parts for a valid eTLD+1
// e.g. bbci.co.uk → ['bbci','co','uk'] → slice(-3) = 'bbci.co.uk'
const MULTI_PART_TLDS = new Set([
  'co.uk','org.uk','me.uk','net.uk','ltd.uk','plc.uk','sch.uk',
  'com.au','net.au','org.au','edu.au','gov.au',
  'co.nz','net.nz','org.nz',
  'co.jp','ne.jp','or.jp','ac.jp',
  'co.in','net.in','org.in',
  'co.za','org.za','net.za',
  'com.br','net.br','org.br',
  'co.kr','or.kr','ne.kr',
  'com.mx','net.mx','org.mx',
  'co.id','net.id','or.id',
  'com.sg','net.sg','org.sg',
  'com.hk','net.hk','org.hk',
  'com.tw','net.tw','org.tw',
  'com.ar','net.ar','org.ar',
]);

function extractETLDPlusOne(hostname) {
  if (!hostname) return '';
  const parts = hostname.split('.');
  if (parts.length <= 2) return hostname;
  const lastTwo = parts.slice(-2).join('.');
  if (MULTI_PART_TLDS.has(lastTwo) && parts.length > 2) return parts.slice(-3).join('.');
  return lastTwo;
}

// Expanded tracking param list (~40 known params)
const TRACKING_PARAMS = new Set([
  'fbclid', 'gclid', 'gbraid', 'wbraid', 'msclkid', 'ttclid', 'twclid', 'li_fat_id',
  '_ga', '_gid', '_fbp', '_fbc', '_gcl_au', '_gcl_aw', 'utm_source', 'utm_medium',
  'utm_campaign', 'utm_term', 'utm_content', 'utm_id', 'dclid', 'epik',
  'uid', 'cid', 'sid', 'vid', 'pid', 'rid', 'aid', 'fp',
  'visitor_id', 'tracking_id', 'session_id', 'user_id', 'client_id',
  '__hssc', '__hstc', '__hsfp', 'hubspotutk',
  'mc_cid', 'mc_eid',
  'igshid', 'rdt_cid',
]);

// Known CDN / infrastructure domains — strong legitimate signal
const CDN_PATTERN = /cloudflare|fastly|akamai|akamaized|cloudfront|jsdelivr|unpkg|cdnjs|staticfiles|gstatic|googleapis|bootstrapcdn|cloudinary|amazonaws|ytimg|googlevideo|ggpht|ttvnw|jtvnw|twimg|fbcdn|cdninstagram|steamstatic|rbxcdn|discordapp/i;

// Brand-owned CDN domains (e.g. spotifycdn.com, wfcdn.com, macysassets.com)
// These are first-party asset hosts that don't match the generic CDN pattern above.
const BRAND_CDN_DOMAIN = /cdn|assets?|images?|img|static|media|content/i;

// Known tracker subdomains
const TRACKER_SUBDOMAIN_PATTERN = /^(ads?|track(ing)?|pixel|beacon|analytics?|metrics?|collect|log|stat(s)?|telemetry|event(s)?|monitor|probe)\./i;

// Known tracker path segments
const TRACKER_PATH_PATTERN = /\/beacon|\/pixel|\/event(s)?|\/track(ing)?|\/collect|\/hit|\/ping|\/log|\/telemetry|\/probe|\/imp(ression)?|\/clk|\/click/i;

// Session replay domains/paths
const SESSION_REPLAY_DOMAIN = /fullstory|hotjar|logrocket|clarity\.ms|mouseflow|smartlook|inspectlet|luckyorange|crazyegg/i;
const SESSION_REPLAY_PATH = /\/rec\/|\/recording|\/replay|\/fs\.js|\/hotjar|\/logrocket|\/clarity|\/hj\.|\/lr-/i;

// Analytics domains/paths
const ANALYTICS_DOMAIN = /google-analytics|googletagmanager|segment\.io|mixpanel|amplitude|heap(analytics)?|rudderstack|posthog|plausible|fathom|matomo|piwik|kissmetrics|woopra|chartbeat/i;
const ANALYTICS_PATH = /\/ga\.js|\/gtag|\/analytics\.js|\/segment\.min|\/mixpanel|\/amplitude|\/heap|\/mp\.js|\/collect\b|\/j\.mp\b/i;

// Fingerprinting paths
const FINGERPRINT_PATH = /fingerprintjs|fingerprint\.js|fp\.js|fpjs|evercookie|\/canvas\b|\/webgl\b|\/audio_fp|clientjs/i;

// Ad network domains/paths
const AD_PATH = /\/ads?\/|\/adserver|\/openrtb|\/prebid|\/banner|\/adview|\/impression|\/dfp\//i;

function extractFeatures(details) {
  let url;
  try {
    url = new URL(details.url);
  } catch {
    return null;
  }

  // Prefer the tab's top-level URL over the raw initiator field.
  // The initiator reflects the immediate frame origin, which for embedded
  // iframes (ext-twitch.tv, googlesyndication.com, recaptcha.net, etc.) is
  // the iframe host — not the page the user is actually on.
  const rawInitiator = details.initiator
    ? (() => {
        try { return extractETLDPlusOne(new URL(details.initiator).hostname); } catch { return ''; }
      })()
    : '';
  const initiatorDomain = TAB_URL_CACHE.get(details.tabId) || rawInitiator;

  const domain = extractETLDPlusOne(url.hostname);
  const subdomain = url.hostname.replace(domain, '').replace(/\.$/, '');
  const path = url.pathname;
  const params = [...url.searchParams.keys()];
  const ct = (getHeader(details.responseHeaders, 'content-type') || '').split(';')[0].trim().toLowerCase();
  const size = getResponseSize(details.responseHeaders);
  const reqHeaders = headersToObject(details.requestHeaders || []);
  const resHeaders = headersToObject(details.responseHeaders || []);
  const trackingParamCount = params.filter((p) => TRACKING_PARAMS.has(p.toLowerCase())).length;

  return {
    // Identity
    url: details.url,
    domain,
    method: details.method || 'GET',
    initiator_domain: initiatorDomain,
    tab_id: details.tabId,

    // Response
    response_status: details.statusCode || 0,
    response_size_bytes: size,
    content_type: ct,

    // Header flags
    has_set_cookie: !!getHeader(details.responseHeaders, 'set-cookie'),
    has_no_cache: (getHeader(details.responseHeaders, 'cache-control') || '').includes('no-store'),
    has_cors_header: !!getHeader(details.responseHeaders, 'access-control-allow-origin'),
    has_referer_header: !!reqHeaders['referer'],
    has_origin_header: !!reqHeaders['origin'],

    // URL signals
    url_length: details.url.length,
    query_param_count: params.length,
    tracking_param_count: trackingParamCount,
    has_tracking_params: trackingParamCount > 0,
    path_depth: path.split('/').filter(Boolean).length,
    has_encoded_params: [...url.searchParams.values()].some(
      (v) => v.length > 40 && /^[A-Za-z0-9+/=_-]{20,}$/.test(v)
    ),

    // Derived boolean signals (computed once, used by scorer)
    is_third_party: !!initiatorDomain && domain !== initiatorDomain,
    is_same_domain: !!initiatorDomain && domain === initiatorDomain,
    subdomain_is_tracker: TRACKER_SUBDOMAIN_PATTERN.test(subdomain + '.'),
    path_is_tracker: TRACKER_PATH_PATTERN.test(path),
    is_tiny_response: size > 0 && size < 50,
    is_small_image: size <= 500 && (ct.includes('image') || ct.includes('gif')),
    loads_as_script: ct.includes('javascript') || ct.includes('ecmascript') || /\.(js|mjs)(\?|$)/i.test(path),
    domain_is_cdn: CDN_PATTERN.test(url.hostname),
    is_font_or_style: ct.includes('font') || ct.includes('css') || /\.(woff2?|ttf|otf|css)(\?|$)/i.test(path),
    domain_matches_session_replay: SESSION_REPLAY_DOMAIN.test(url.hostname),
    path_matches_session_replay: SESSION_REPLAY_PATH.test(path),
    domain_matches_analytics: ANALYTICS_DOMAIN.test(url.hostname),
    path_matches_analytics: ANALYTICS_PATH.test(path),
    path_matches_fingerprint: FINGERPRINT_PATH.test(path),
    path_matches_ad: AD_PATH.test(path),
    in_blocklist: blocklistDomains.has(domain),

    // Timing
    ms_since_nav_start: details.timeStamp - getNavStartTime(details.tabId),

    // Raw headers for detail panel
    request_headers: reqHeaders,
    response_headers: resHeaders,
  };
}

const CATEGORIES = ['behavioral', 'fingerprinting', 'session_replay', 'ad_network', 'analytics', 'legitimate', 'unclassified'];

/**
 * Weighted multi-signal scorer.
 *
 * Each rule pushes { category, signal, weight } into `contributions`.
 * All rules run — no early exit. The category with the highest total score wins.
 * Confidence is derived from the margin between winner and runner-up.
 * feature_importances returns the actual signals that fired, sorted by weight.
 */
function classifyRuleBased(features) {
  if (!features) return { category: 'unclassified', confidence: 0.0, feature_importances: [] };

  const contributions = []; // { category, signal, weight }

  function add(category, signal, weight) {
    contributions.push({ category, signal, weight });
  }

  // ── Session Replay ──────────────────────────────────────────────────────
  if (features.domain_matches_session_replay)   add('session_replay', 'session_replay_domain',  0.90);
  if (features.path_matches_session_replay)     add('session_replay', 'session_replay_path',    0.85);

  // ── Fingerprinting ──────────────────────────────────────────────────────
  if (features.path_matches_fingerprint)        add('fingerprinting', 'fingerprint_path',       0.90);
  if (features.subdomain_is_tracker && features.loads_as_script && features.is_third_party)
                                                add('fingerprinting', 'tracker_subdomain_script', 0.40);
  if (features.has_cors_header && features.loads_as_script && features.is_third_party)
                                                add('fingerprinting', 'cors_third_party_script', 0.20);

  // ── Analytics ───────────────────────────────────────────────────────────
  if (features.domain_matches_analytics)        add('analytics', 'analytics_domain',            0.88);
  if (features.path_matches_analytics)          add('analytics', 'analytics_path',              0.82);
  if (features.has_set_cookie && features.is_third_party && features.tracking_param_count >= 2)
                                                add('analytics', 'cookie_third_party_tracked',  0.50);
  if (features.has_set_cookie && features.is_third_party && features.has_referer_header)
                                                add('analytics', 'cookie_with_referer',         0.35);

  // ── Ad Network ──────────────────────────────────────────────────────────
  if (features.in_blocklist)                    add('ad_network',  'blocklist_domain',           0.85);
  if (features.path_matches_ad)                 add('ad_network',  'ad_path',                   0.70);
  if (features.path_is_tracker && features.is_third_party && features.is_tiny_response)
                                                add('ad_network',  'tracker_path_pixel',         0.65);
  if (features.subdomain_is_tracker && features.has_tracking_params)
                                                add('ad_network',  'tracker_subdomain_params',   0.50);

  // ── Behavioral ──────────────────────────────────────────────────────────
  if (features.tracking_param_count >= 3)       add('behavioral',  'many_tracking_params',       0.75);
  if (features.tracking_param_count >= 1 && features.is_tiny_response)
                                                add('behavioral',  'tracking_params_pixel',      0.80);
  if (features.tracking_param_count >= 1 && features.is_small_image)
                                                add('behavioral',  'tracking_params_image',      0.70);
  if (features.path_is_tracker && features.has_referer_header)
                                                add('behavioral',  'tracker_path_referer',       0.55);
  if (features.has_set_cookie && features.is_third_party && features.path_depth >= 3)
                                                add('behavioral',  'deep_third_party_cookie',    0.40);
  if (features.tracking_param_count >= 1 && features.is_third_party)
                                                add('behavioral',  'tracking_params_third_party', 0.45);
  if (features.has_encoded_params && features.is_third_party)
                                                add('behavioral',  'encoded_params_third_party', 0.40);

  // ── Legitimate ──────────────────────────────────────────────────────────
  if (features.is_same_domain)                  add('legitimate',  'same_domain_resource',       0.70);
  if (features.domain_is_cdn)                   add('legitimate',  'cdn_domain',                 0.80);
  if (features.is_font_or_style && !features.is_third_party)
                                                add('legitimate',  'first_party_style_font',     0.65);
  if (features.is_font_or_style && features.domain_is_cdn)
                                                add('legitimate',  'cdn_style_font',             0.75);
  if (features.response_status === 200 && features.is_same_domain)
                                                add('legitimate',  'ok_same_domain',             0.30);
  // Brand-owned CDN: third-party asset host whose domain name contains CDN-like
  // keywords but has no tracking signals — outweighs cors_third_party_script alone.
  if (features.is_third_party && BRAND_CDN_DOMAIN.test(features.domain)
      && !features.has_tracking_params && !features.subdomain_is_tracker
      && !features.path_is_tracker)             add('legitimate',  'brand_cdn_domain',           0.60);
  // Catch-all: no tracking indicators present → weakly legitimate.
  // Covers generic third-party JS/images/API calls that don't match any
  // specific pattern (widgets, embeds, social buttons, etc.).
  if (!features.has_tracking_params && !features.path_is_tracker
      && !features.subdomain_is_tracker && !features.path_matches_ad
      && !features.path_matches_analytics && !features.path_matches_fingerprint
      && !features.domain_matches_analytics && !features.domain_matches_session_replay
      && !features.in_blocklist)                add('legitimate',  'no_tracking_signals',        0.25);

  // ── Aggregate scores ────────────────────────────────────────────────────
  const totals = {};
  for (const { category, weight } of contributions) {
    totals[category] = (totals[category] || 0) + weight;
  }

  const sorted = Object.entries(totals).sort((a, b) => b[1] - a[1]);

  // No signals fired → shouldn't happen after no_tracking_signals catch-all,
  // but guard anyway with a low-confidence legitimate rather than unclassified.
  if (sorted.length === 0) {
    return { category: 'legitimate', confidence: 0.35, feature_importances: [{ feature: 'no_signals', importance: 1.0 }] };
  }

  const [winnerCat, winnerScore] = sorted[0];
  const runnerUpScore = sorted[1]?.[1] ?? 0;
  const margin = winnerScore - runnerUpScore;
  const confidence = Math.min(0.97, 0.50 + (margin / (winnerScore + 0.01)) * 0.47);

  // Feature importances: signals that contributed to the winning category, by weight
  const importances = contributions
    .filter((c) => c.category === winnerCat)
    .sort((a, b) => b.weight - a.weight)
    .slice(0, 5)
    .map((c) => ({ feature: c.signal, importance: +(c.weight.toFixed(2)) }));

  return { category: winnerCat, confidence: +confidence.toFixed(3), feature_importances: importances };
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
  try {
    const result = await chrome.storage.local.get(key);
    const existing = result[key] || [];
    await chrome.storage.local.set({ [key]: existing.concat(requestBuffer) });
    requestBuffer = [];
  } catch (err) {
    console.error('[Specter] flushBuffer failed:', err?.message || err);
    // Don't clear buffer on failure so next flush retries
  }
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
  const tracker_count = requests.filter(
    (r) => r.category && r.category !== 'legitimate' && r.category !== 'unclassified'
  ).length;
  const summary = {
    id: session.id,
    started_at: session.started_at,
    stopped_at: updates['session:current'].stopped_at,
    total_requests,
    tracker_count,
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
  broadcastToDashboard({ type: 'score_update', domain: siteDomain, score: entry });
}

async function batchWrite(request) {
  requestBuffer.push(request);
  if (requestBuffer.length >= 10) await flushBuffer();
}

chrome.webRequest.onBeforeRequest.addListener(
  (details) => {
    if (details.type === 'main_frame') {
      NAV_START_CACHE.set(details.tabId, details.timeStamp);
      try {
        TAB_URL_CACHE.set(details.tabId, extractETLDPlusOne(new URL(details.url).hostname));
      } catch {}
    }
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

// ── Crawl: dwell-alarm fires → navigate to next URL ──────────────────────────
//
// The alarm is the sole controller of crawl advancement.
// tabs.onUpdated is intentionally NOT used for this — many sites fire multiple
// status:'complete' events per visit (JS redirects, SPA route changes, consent
// overlays, etc.), which would cause the index to advance multiple times per
// site and the crawl to terminate prematurely.
chrome.alarms.onAlarm.addListener(async (alarm) => {
  if (alarm.name !== 'crawl_dwell') return;
  const state = await loadCrawlState();
  if (!state?.active) return;

  // All sites visited → done
  if (state.index >= state.urls.length) {
    broadcastToDashboard({ type: 'crawl_done', total: state.urls.length });
    chrome.tabs.remove(state.tabId).catch(() => {});
    await saveCrawlState(null);
    return;
  }

  // Navigate to next URL, advance index
  const rawUrl  = state.urls[state.index];
  const nextUrl = /^https?:\/\//i.test(rawUrl) ? rawUrl : 'https://' + rawUrl;
  state.index++;

  // Wrap in try/catch so navigation failures don't kill the alarm chain.
  // If tabs.create fails, clear tabId so the next dwell does not reuse a dead id.
  try {
    let navigated = false;
    if (state.tabId != null) {
      try {
        const tab = await chrome.tabs.get(state.tabId);
        if (tab.discarded) throw new Error('discarded');
        await chrome.tabs.update(state.tabId, { url: nextUrl });
        navigated = true;
      } catch {
        /* tab missing, discarded, or update failed — create below */
      }
    }
    if (!navigated) {
      const newTab = await chrome.tabs.create({ url: nextUrl, active: false });
      state.tabId = newTab.id;
    }
  } catch (err) {
    console.warn('[Specter] crawl: could not navigate to', nextUrl, err);
    state.tabId = null;
  }

  await saveCrawlState(state);
  broadcastToDashboard({ type: 'crawl_progress', index: state.index, total: state.urls.length, url: nextUrl, startedAt: state.startedAt });

  // Use Math.max to guarantee at least 10 s — avoids sub-second clamping edge
  // cases in Chrome MV3 while still respecting the configured dwell time.
  const delayMinutes = Math.max(10 / 60, state.dwellMs / 60000);
  chrome.alarms.create('crawl_dwell', { delayInMinutes: delayMinutes });
});

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
  if (message.type === 'start_session') {
    startSession().then((session) => {
      broadcastToDashboard({ type: 'session_started', session_id: session.id, keep_rows: message.keep_rows ?? false });
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
    chrome.storage.local.get(['session:current', 'session:elapsed_frozen']).then((r) => {
      const session = r['session:current'];
      const frozenSec = Number(r['session:elapsed_frozen']) || 0;
      const updates = {
        'session:paused': false,
        'session:elapsed_frozen': 0,
      };
      // Shift started_at forward so Date.now() - started_at == elapsed active time,
      // not wall-clock time (which would include the pause duration).
      if (session) {
        updates['session:current'] = {
          ...session,
          started_at: Date.now() - frozenSec * 1000,
        };
      }
      chrome.storage.local.set(updates).then(() => {
        broadcastToDashboard({ type: 'feed_resumed' });
        sendResponse({ ok: true });
      });
    });
    return true;
  }
  if (message.type === 'start_crawl') {
    loadCrawlState().then(async (existing) => {
      if (existing?.active) { sendResponse({ ok: false, error: 'crawl already running' }); return; }
      const urls    = message.urls || [];
      const dwellMs = message.dwell_ms || 6000;
      if (urls.length === 0) { sendResponse({ ok: false, error: 'no urls' }); return; }
      // index: 1 = we've navigated to urls[0]; alarm will navigate to urls[1], urls[2], ...
      const state = { active: true, urls, index: 1, dwellMs, tabId: null, startedAt: Date.now() };
      await saveCrawlState(state);
      const tab = await chrome.tabs.create({ url: urls[0], active: false });
      state.tabId = tab.id;
      await saveCrawlState(state);
      broadcastToDashboard({ type: 'crawl_started', total: urls.length });
      broadcastToDashboard({ type: 'crawl_progress', index: 1, total: urls.length, url: urls[0], startedAt: state.startedAt });
      chrome.alarms.create('crawl_dwell', { delayInMinutes: Math.max(10 / 60, dwellMs / 60000) });
      sendResponse({ ok: true, tabId: tab.id });
    });
    return true;
  }
  if (message.type === 'stop_crawl') {
    loadCrawlState().then(async (state) => {
      if (state?.tabId) chrome.tabs.remove(state.tabId).catch(() => {});
      chrome.alarms.clear('crawl_dwell');
      await saveCrawlState(null);
      broadcastToDashboard({ type: 'crawl_stopped' });
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
