/* Specter — Adaptive Blocking Engine (v1.2, MV3/DNR-only)
 *
 * Loaded by service_worker.js via importScripts('blocking.js').
 *
 * MV3 constraint: webRequestBlocking is NOT available to regular extensions.
 * All blocking and URL rewriting is done via chrome.declarativeNetRequest.
 *
 * Two DNR rulesets:
 *   1. Static ruleset "specter_blocking"  — seed list of known bad domains (blocking_rules.json)
 *   2. Dynamic rules                      — domains promoted at runtime by the classifier
 *      Rule ID space:
 *        1–999      reserved for static ruleset
 *        1000–5499  domain block rules (DNR_BLOCK_OFFSET, max DNR_MAX_BLOCK domains)
 *        5500–5799  param-strip redirect rules (DNR_STRIP_OFFSET, one rule per tracked param)
 *        5800–5849  param-strip cleanup redirects (DNR_STRIP_CLEANUP_OFFSET)
 *
 * Provides (all are globals, importScripts style):
 *   initBlocking()
 *   applySettingsUpdate(newSettings)
 *   handlePostClassify(features, classification, sessionId) → { action, reason }
 *   allowDomain(domain, site)
 *   rebuildDNRRules()
 *   flushBlockStats(sessionId)
 *   getBlockingStats(sessionId)
 *   setTabUrlCacheRef(tabId, domain)
 *   deleteTabUrlCacheRef(tabId)
 */

// ── Constants ─────────────────────────────────────────────────────────────────

const DNR_BLOCK_OFFSET = 1000;
const DNR_STRIP_OFFSET = 5500;
const DNR_STRIP_CLEANUP_OFFSET = 5800;
const DNR_MAX_BLOCK    = 4500; // leaves headroom under Chrome's 5000 dynamic rule cap

const DNR_STRIP_RESOURCE_TYPES = [
  'main_frame', 'sub_frame', 'script', 'xmlhttprequest',
  'image', 'stylesheet', 'font', 'media', 'other',
];

// Tracking params to strip via DNR redirect rules.
// DNR regexSubstitution strips individual params by matching the full query string.
// We use one rule per param — simpler than a mega-regex and easy to update.
const STRIP_PARAMS = [
  'fbclid','gclid','gbraid','wbraid','msclkid','ttclid','twclid','li_fat_id',
  '_ga','_gid','_fbp','_fbc','_gcl_au','_gcl_aw',
  'utm_source','utm_medium','utm_campaign','utm_term','utm_content','utm_id',
  'dclid','epik',
  '__hssc','__hstc','__hsfp','hubspotutk',
  'mc_cid','mc_eid','igshid','rdt_cid',
];

// ── State ─────────────────────────────────────────────────────────────────────

let blockingEnabled     = false;
let blockingMode        = 'smart';
let blockThreshold      = 0.85;
let stripThreshold      = 0.55;
let blockSessionReplay  = true;
let blockFingerprinting = true;
let blockBehavioral     = true;
let blockAdNetwork      = true;
let blockAnalytics      = false;

const dynamicBlockedDomains = new Set();
const siteAllowlist         = new Set();
const blockStatsCache       = new Map();

// Tab URL cache reference — kept in sync by service_worker.js
const TAB_URL_CACHE_BLOCKING = new Map();

// ── Init ──────────────────────────────────────────────────────────────────────

async function initBlocking() {
  const r = await chrome.storage.local.get([
    'settings',
    'blocking:dynamic_domains',
    'blocking:allowlist',
  ]);

  const s = r['settings'] || {};
  blockingEnabled     = s.blocking_enabled     ?? false;
  blockingMode        = s.blocking_mode        ?? 'smart';
  blockThreshold      = s.block_threshold      ?? 0.85;
  stripThreshold      = s.strip_threshold      ?? 0.55;
  blockSessionReplay  = s.block_session_replay ?? true;
  blockFingerprinting = s.block_fingerprinting ?? true;
  blockBehavioral     = s.block_behavioral     ?? true;
  blockAdNetwork      = s.block_ad_network     ?? true;
  blockAnalytics      = s.block_analytics      ?? false;

  for (const d of (r['blocking:dynamic_domains'] || [])) dynamicBlockedDomains.add(d);
  for (const k of (r['blocking:allowlist']       || [])) siteAllowlist.add(k);
}

function applySettingsUpdate(s) {
  if (s.blocking_enabled     != null) blockingEnabled     = s.blocking_enabled;
  if (s.blocking_mode        != null) blockingMode        = s.blocking_mode;
  if (s.block_threshold      != null) blockThreshold      = s.block_threshold;
  if (s.strip_threshold      != null) stripThreshold      = s.strip_threshold;
  if (s.block_session_replay != null) blockSessionReplay  = s.block_session_replay;
  if (s.block_fingerprinting != null) blockFingerprinting = s.block_fingerprinting;
  if (s.block_behavioral     != null) blockBehavioral     = s.block_behavioral;
  if (s.block_ad_network     != null) blockAdNetwork      = s.block_ad_network;
  if (s.block_analytics      != null) blockAnalytics      = s.block_analytics;

  // Toggle static ruleset
  chrome.declarativeNetRequest.updateEnabledRulesets({
    enableRulesetIds:  blockingEnabled ? ['specter_blocking'] : [],
    disableRulesetIds: blockingEnabled ? [] : ['specter_blocking'],
  }).catch(() => {});

  rebuildDNRRules();
}

// ── Decision logic ────────────────────────────────────────────────────────────

function shouldBlock(features, classification) {
  if (!blockingEnabled) return { action: 'observe' };

  const { category, confidence } = classification;
  const initiator = features.initiator_domain || '';
  const domain    = features.domain;

  // Allow-list check
  if (siteAllowlist.has(initiator + ':' + domain) || siteAllowlist.has('*:' + domain)) {
    return { action: 'observe' };
  }

  // Strip-only mode
  if (blockingMode === 'strip_only') {
    return features.has_tracking_params
      ? { action: 'strip_params', reason: 'strip_only_mode' }
      : { action: 'observe' };
  }

  // Always-block categories
  if (category === 'session_replay' && blockSessionReplay)  return { action: 'block', reason: 'session_replay' };
  if (category === 'fingerprinting' && blockFingerprinting) return { action: 'block', reason: 'fingerprinting' };

  // Strict mode
  if (blockingMode === 'strict' && features.is_third_party && !features.domain_is_cdn) {
    return { action: 'block', reason: 'strict_mode_third_party' };
  }

  // Smart mode — confidence-based
  if (category === 'behavioral'  && blockBehavioral  && confidence >= blockThreshold) return { action: 'block', reason: 'high_confidence_behavioral' };
  if (category === 'ad_network'  && blockAdNetwork   && confidence >= blockThreshold) return { action: 'block', reason: 'high_confidence_ad_network' };
  if (category === 'analytics'   && blockAnalytics   && confidence >= blockThreshold) return { action: 'block', reason: 'high_confidence_analytics' };

  // Medium confidence — note the decision (param stripping already handled by DNR)
  if (features.is_third_party && category !== 'legitimate' && category !== 'unclassified' && confidence >= stripThreshold) {
    return features.has_tracking_params
      ? { action: 'strip_params', reason: 'medium_confidence_tracked' }
      : { action: 'warn', reason: 'medium_confidence_' + category };
  }

  if (features.has_tracking_params) return { action: 'strip_params', reason: 'tracking_params_present' };

  return { action: 'observe' };
}

// ── Post-classify handler ─────────────────────────────────────────────────────

async function handlePostClassify(features, classification, sessionId) {
  const decision = shouldBlock(features, classification);

  if (decision.action === 'block') {
    await addDynamicBlockRule(features.domain);
    await incrementBlockStat(sessionId, 'blocked');
  } else if (decision.action === 'strip_params') {
    // Param-strip DNR rules are always active when blocking is on.
    // We just record the stat — the actual stripping already happened via DNR.
    await incrementBlockStat(sessionId, 'stripped');
  } else if (decision.action === 'warn') {
    await incrementBlockStat(sessionId, 'warned');
  }

  return decision;
}

// ── Allow-list ────────────────────────────────────────────────────────────────

async function allowDomain(domain, site = '*') {
  const key = site + ':' + domain;
  siteAllowlist.add(key);

  const r = await chrome.storage.local.get('blocking:allowlist');
  const list = new Set(r['blocking:allowlist'] || []);
  list.add(key);
  await chrome.storage.local.set({ 'blocking:allowlist': [...list] });

  // Remove from dynamic block rules
  if (dynamicBlockedDomains.has(domain)) {
    dynamicBlockedDomains.delete(domain);
    const rr = await chrome.storage.local.get('blocking:dynamic_domains');
    const domains = (rr['blocking:dynamic_domains'] || []).filter(d => d !== domain);
    await chrome.storage.local.set({ 'blocking:dynamic_domains': domains });
    await rebuildDNRRules();
  }
}

// ── DNR rule management ───────────────────────────────────────────────────────

async function addDynamicBlockRule(domain) {
  if (!domain || dynamicBlockedDomains.has(domain)) return;

  // LRU eviction
  if (dynamicBlockedDomains.size >= DNR_MAX_BLOCK) {
    const oldest = dynamicBlockedDomains.values().next().value;
    dynamicBlockedDomains.delete(oldest);
  }

  dynamicBlockedDomains.add(domain);

  const r = await chrome.storage.local.get('blocking:dynamic_domains');
  const updated = [...new Set([...(r['blocking:dynamic_domains'] || []), domain])].slice(-DNR_MAX_BLOCK);
  await chrome.storage.local.set({ 'blocking:dynamic_domains': updated });

  await rebuildDNRRules();
}

/**
 * Build param-strip redirect rules using DNR's regexFilter + regexSubstitution.
 *
 * Each rule matches any URL containing "?param=" or "&param=" and rewrites it
 * to remove that param. Chrome supports up to 1000 regex rules; STRIP_PARAMS
 * has ~28 entries, well within limits.
 *
 * Pattern: ^(.*[?&])PARAM=[^&]*&?(.*)$
 *   Group 1: everything up to and including the ? or & before the param
 *   Group 2: everything after param=value and its optional trailing &
 *   Substitution \\1\\2 reconnects without leaving a dangling & or double ??
 *
 * Note: DNR regex rules use RE2 syntax (no lookaheads).
 * Chrome's regexSubstitution uses \1, \2 back-references.
 */
function buildParamStripRules() {
  if (!blockingEnabled || blockingMode === 'strip_only' || dynamicBlockedDomains.size === 0) {
    // Always build strip rules when blocking is on — they apply globally, not per-domain
  }
  if (!blockingEnabled) return [];

  return STRIP_PARAMS.map((param, i) => {
    // Matches: ...?PARAM=value&rest  or  ...&PARAM=value&rest  or  ...&PARAM=value (end)
    // Capture group 1: everything up to and including ? or & before the param
    // Capture group 2: everything after param=value
    // RE2-compatible — no lookaheads needed
    const escaped = param.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    return {
      id: DNR_STRIP_OFFSET + i,
      priority: 2,
      action: {
        type: 'redirect',
        redirect: {
          regexSubstitution: '\\1\\2',
        },
      },
      condition: {
        // Matches URLs that contain this tracking param.
        // Group 1: everything up to and including the separator before this param (? or &)
        // Group 2: everything after param=value and its trailing &
        // The trailing & is consumed by [^&]*&? so \\1\\2 reconnects cleanly.
        // Edge: if param is last, trailing & is absent, group 2 is empty → no dangling &
        regexFilter: `^(.*[?&])${escaped}=[^&]*&?(.*)$`,
        resourceTypes: DNR_STRIP_RESOURCE_TYPES,
        // Only strip from non-allowlisted requests — we can't reference the
        // allow-list in DNR directly, so strip rules apply globally when enabled.
        // The allow-list is enforced post-classify in handlePostClassify stats.
      },
    };
  });
}

/**
 * Cleanup redirects for query-string artifacts left by param-strip rules.
 * Lower priority than strip rules so tracking params are removed first; Chrome
 * re-evaluates rules after each redirect, so ?& / && / trailing & get fixed next.
 */
function buildParamStripCleanupRules() {
  if (!blockingEnabled || blockingMode === 'strict') return [];

  const cond = { resourceTypes: DNR_STRIP_RESOURCE_TYPES };
  return [
    {
      id: DNR_STRIP_CLEANUP_OFFSET,
      priority: 1,
      action: { type: 'redirect', redirect: { regexSubstitution: '\\1&\\2' } },
      condition: { ...cond, regexFilter: '^(.*)&&+(.*)$' },
    },
    {
      id: DNR_STRIP_CLEANUP_OFFSET + 1,
      priority: 1,
      action: { type: 'redirect', redirect: { regexSubstitution: '\\1?\\2' } },
      condition: { ...cond, regexFilter: '^(.*)\\?&+(.*)$' },
    },
    {
      id: DNR_STRIP_CLEANUP_OFFSET + 2,
      priority: 1,
      action: { type: 'redirect', redirect: { regexSubstitution: '\\1' } },
      condition: { ...cond, regexFilter: '^(.*)&$' },
    },
  ];
}

async function rebuildDNRRules() {
  let rulesToAdd = [];

  if (blockingEnabled) {
    // Domain block rules
    const domains = [...dynamicBlockedDomains];
    const blockRules = domains.map((domain, i) => ({
      id: DNR_BLOCK_OFFSET + i,
      priority: 2,
      action: { type: 'block' },
      condition: {
        requestDomains: [domain],
        resourceTypes: ['script', 'image', 'xmlhttprequest', 'sub_frame', 'stylesheet', 'other'],
      },
    }));
    rulesToAdd = [...blockRules];

    // Param strip rules (only in smart or strip_only mode, not strict)
    if (blockingMode !== 'strict') {
      // Note: regexSubstitution rules require the 'declarativeNetRequest' permission
      // and Chrome 88+. We add them but catch if the browser doesn't support them.
      const stripRules = buildParamStripRules();
      const cleanupRules = buildParamStripCleanupRules();
      rulesToAdd = [...rulesToAdd, ...stripRules, ...cleanupRules];
    }
  }

  try {
    const existing = await chrome.declarativeNetRequest.getDynamicRules();
    const existingIds = existing.map(r => r.id);
    await chrome.declarativeNetRequest.updateDynamicRules({
      removeRuleIds: existingIds,
      addRules: rulesToAdd,
    });
  } catch (e) {
    // If regex rules fail (older Chrome, or regex too complex), fall back to block-only
    console.warn('[Specter] rebuildDNRRules failed, retrying without strip rules:', e?.message);
    try {
      const blockOnlyRules = rulesToAdd.filter(r => r.action.type === 'block');
      const existing = await chrome.declarativeNetRequest.getDynamicRules();
      await chrome.declarativeNetRequest.updateDynamicRules({
        removeRuleIds: existing.map(r => r.id),
        addRules: blockOnlyRules,
      });
    } catch (e2) {
      console.warn('[Specter] rebuildDNRRules block-only fallback also failed:', e2?.message);
    }
  }
}

// ── Stats ─────────────────────────────────────────────────────────────────────

async function incrementBlockStat(sessionId, field) {
  if (!sessionId) return;
  const key = 'blocking:stats:' + sessionId;
  if (!blockStatsCache.has(sessionId)) {
    const r = await chrome.storage.local.get(key);
    blockStatsCache.set(sessionId, r[key] || { blocked: 0, stripped: 0, warned: 0 });
  }
  const stats = blockStatsCache.get(sessionId);
  stats[field] = (stats[field] || 0) + 1;
  if ((stats.blocked + stats.stripped + stats.warned) % 20 === 0) {
    await chrome.storage.local.set({ [key]: stats });
  }
}

async function flushBlockStats(sessionId) {
  if (!sessionId || !blockStatsCache.has(sessionId)) return;
  await chrome.storage.local.set({ ['blocking:stats:' + sessionId]: blockStatsCache.get(sessionId) });
}

async function getBlockingStats(sessionId) {
  if (!sessionId) return { blocked: 0, stripped: 0, warned: 0 };
  if (blockStatsCache.has(sessionId)) return blockStatsCache.get(sessionId);
  const r = await chrome.storage.local.get('blocking:stats:' + sessionId);
  return r['blocking:stats:' + sessionId] || { blocked: 0, stripped: 0, warned: 0 };
}

// ── Tab URL cache helpers (called by service_worker.js) ───────────────────────

function setTabUrlCacheRef(tabId, domain) {
  TAB_URL_CACHE_BLOCKING.set(tabId, domain);
}

function deleteTabUrlCacheRef(tabId) {
  TAB_URL_CACHE_BLOCKING.delete(tabId);
}

// ── handleOnBeforeRequest — NO-OP in MV3 ─────────────────────────────────────
// Kept as a stub so service_worker.js doesn't need to change if it calls this.
// In MV3, webRequestBlocking is unavailable; all work is done via DNR.
function handleOnBeforeRequest(_details) {
  return {};
}
