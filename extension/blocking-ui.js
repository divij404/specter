/* Specter — Blocking UI Module (v1.2)
 *
 * Imported by dashboard.html via <script src="blocking-ui.js"> before dashboard.js.
 * Provides:
 *   renderBlockingSettingsSection(settings)  — returns HTML string for the Settings panel
 *   bindBlockingSettingsEvents(saveFn)       — attaches event listeners after HTML is injected
 *   renderBlockingBadge(blockAction, reason) — returns badge HTML for feed rows
 *   initBlockingUI(sessionId)               — loads + displays blocking stats
 *   onBlockActionMessage(msg)               — call from dashboard message handler
 */

// ── Blocking stats state ──────────────────────────────────────────────────────
let blockingStats = { blocked: 0, stripped: 0, warned: 0 };
let currentBlockingSessionId = null;
let blockingStatsFetchId = 0;

function mergeBlockingStats(fetched, local) {
  const f = fetched || {};
  const l = local || {};
  return {
    blocked:  Math.max(f.blocked  || 0, l.blocked  || 0),
    stripped: Math.max(f.stripped || 0, l.stripped || 0),
    warned:   Math.max(f.warned   || 0, l.warned   || 0),
  };
}

async function initBlockingUI(sessionId) {
  currentBlockingSessionId = sessionId;
  if (!sessionId) {
    blockingStats = { blocked: 0, stripped: 0, warned: 0 };
    renderBlockingStatsBadges();
    return;
  }
  blockingStats = { blocked: 0, stripped: 0, warned: 0 };
  renderBlockingStatsBadges();
  const fetchId = ++blockingStatsFetchId;
  const sessionForFetch = sessionId;
  chrome.runtime.sendMessage({ type: 'get_blocking_stats', session_id: sessionId }, (r) => {
    if (fetchId !== blockingStatsFetchId) return;
    if (currentBlockingSessionId !== sessionForFetch) return;
    if (!r?.ok) return;
    blockingStats = mergeBlockingStats(r.stats, blockingStats);
    renderBlockingStatsBadges();
  });
}

function onBlockActionMessage(msg) {
  if (msg.action === 'block') blockingStats.blocked++;
  if (msg.action === 'strip_params') blockingStats.stripped++;
  if (msg.action === 'warn') blockingStats.warned++;
  renderBlockingStatsBadges();
}

function renderBlockingStatsBadges() {
  const el = document.getElementById('blocking-stats-bar');
  if (!el) return;
  const { blocked, stripped, warned } = blockingStats;
  const total = blocked + stripped + warned;
  if (total === 0) {
    el.innerHTML = `<span class="bstat-label">No actions this session</span>`;
    el.className = 'blocking-stats-bar';
  } else {
    const warnedHtml = warned > 0
      ? `<span class="bstat-sep"></span><span class="bstat bstat--warned">${warned} flagged</span>`
      : '';
    el.innerHTML =
      `<span class="bstat bstat--blocked">
        <svg width="9" height="9" viewBox="0 0 9 9" fill="none" aria-hidden="true">
          <circle cx="4.5" cy="4.5" r="4" stroke="currentColor" stroke-width="1.2"/>
          <line x1="2.5" y1="4.5" x2="6.5" y2="4.5" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/>
        </svg>
        ${blocked} blocked
      </span>` +
      `<span class="bstat-sep"></span>` +
      `<span class="bstat bstat--stripped">
        <svg width="9" height="9" viewBox="0 0 9 9" fill="none" aria-hidden="true">
          <path d="M1.5 2.5h6M1.5 4.5h4.5M1.5 6.5h3" stroke="currentColor" stroke-width="1.3" stroke-linecap="round"/>
        </svg>
        ${stripped} stripped
      </span>` +
      warnedHtml;
    el.className = 'blocking-stats-bar blocking-stats-bar--active';
  }
}

// ── Feed badge ────────────────────────────────────────────────────────────────

function renderBlockingBadge(blockAction, blockReason) {
  if (!blockAction || blockAction === 'observe') return '';
  const label = blockAction === 'block'        ? 'BLOCKED'
              : blockAction === 'strip_params'  ? 'STRIPPED'
              : 'FLAGGED';
  const cls   = blockAction === 'block'        ? 'block-badge--blocked'
              : blockAction === 'strip_params'  ? 'block-badge--stripped'
              : 'block-badge--warned';
  const tooltip = blockReason ? blockReason.replace(/_/g, ' ') : '';
  return `<span class="block-badge ${cls}" title="${tooltip}">${label}</span>`;
}

// ── Settings HTML ─────────────────────────────────────────────────────────────

function renderBlockingSettingsSection(s) {
  const enabled = !!s.blocking_enabled;
  const disAttr = enabled ? '' : ' disabled';
  const disClass = enabled ? '' : ' settings-row--disabled';

  const modeOptions = [
    ['smart',      'Smart — ML-driven (recommended)'],
    ['strict',     'Strict — block all third-party'],
    ['strip_only', 'Param strip only'],
  ].map(([val, label]) =>
    `<option value="${val}"${s.blocking_mode === val ? ' selected' : ''}>${label}</option>`
  ).join('');

  return `
<div class="settings-section settings-section--blocking${enabled ? ' settings-section--blocking-armed' : ''}" id="settings-blocking">

  <div class="settings-section-header">
    <span class="settings-section-title">BLOCKING</span>
  </div>

  <!-- Master toggle + inline session stats -->
  <div class="settings-row settings-row--blocking-master">
    <div class="settings-row-label">
      <div class="settings-row-title">Enable blocking</div>
      <div class="settings-row-hint">
        Block and strip trackers based on classifier output.
        Off by default — enable once you're comfortable with the results.
      </div>
    </div>
    <div class="settings-row-side">
      <div id="blocking-stats-bar" class="blocking-stats-bar">
        <span class="bstat-label">No actions this session</span>
      </div>
      <label class="settings-toggle" aria-label="Enable blocking">
        <input type="checkbox" id="setting-blocking-enabled"${enabled ? ' checked' : ''}>
        <span class="settings-toggle-track"></span>
      </label>
    </div>
  </div>

  <!-- Mode selector -->
  <div class="settings-row${disClass}" id="blocking-mode-row">
    <div class="settings-row-label">
      <div class="settings-row-title">Blocking mode</div>
      <div class="settings-row-hint settings-row-hint--mode" id="blocking-mode-hint"></div>
    </div>
    <select id="setting-blocking-mode" class="settings-select"${disAttr}>
      ${modeOptions}
    </select>
  </div>

  <!-- Confidence threshold -->
  <div class="settings-row${disClass}" id="blocking-threshold-row">
    <div class="settings-row-label">
      <div class="settings-row-title">
        Block threshold
        <span class="settings-threshold-value" id="block-threshold-label">${Math.round((s.block_threshold ?? 0.85) * 100)}%</span>
      </div>
      <div class="settings-row-hint">Requests classified above this confidence are blocked in Smart mode.</div>
    </div>
    <div class="settings-slider-wrap">
      <input type="range" id="setting-block-threshold"
        class="settings-slider"
        min="0.5" max="1.0" step="0.05"
        value="${s.block_threshold ?? 0.85}"${disAttr}>
    </div>
  </div>

  <!-- Session replay -->
  <div class="settings-row settings-row--nested${disClass}">
    <div class="settings-row-label">
      <div class="settings-row-title">Session replay</div>
      <div class="settings-row-hint">Hotjar, FullStory, LogRocket, Mouseflow…</div>
    </div>
    <label class="settings-toggle" aria-label="Always block session replay">
      <input type="checkbox" id="setting-block-session-replay"${s.block_session_replay !== false ? ' checked' : ''}${disAttr}>
      <span class="settings-toggle-track"></span>
    </label>
  </div>

  <!-- Fingerprinting -->
  <div class="settings-row settings-row--nested${disClass}">
    <div class="settings-row-label">
      <div class="settings-row-title">Fingerprinting</div>
      <div class="settings-row-hint">FingerprintJS, device fingerprint scripts…</div>
    </div>
    <label class="settings-toggle" aria-label="Always block fingerprinting">
      <input type="checkbox" id="setting-block-fingerprinting"${s.block_fingerprinting !== false ? ' checked' : ''}${disAttr}>
      <span class="settings-toggle-track"></span>
    </label>
  </div>

  <!-- Behavioral -->
  <div class="settings-row settings-row--nested${disClass}">
    <div class="settings-row-label">
      <div class="settings-row-title">Behavioral trackers</div>
    </div>
    <label class="settings-toggle" aria-label="Block behavioral trackers">
      <input type="checkbox" id="setting-block-behavioral"${s.block_behavioral !== false ? ' checked' : ''}${disAttr}>
      <span class="settings-toggle-track"></span>
    </label>
  </div>

  <!-- Ad networks -->
  <div class="settings-row settings-row--nested${disClass}">
    <div class="settings-row-label">
      <div class="settings-row-title">Ad networks</div>
    </div>
    <label class="settings-toggle" aria-label="Block ad networks">
      <input type="checkbox" id="setting-block-ad-network"${s.block_ad_network !== false ? ' checked' : ''}${disAttr}>
      <span class="settings-toggle-track"></span>
    </label>
  </div>

  <!-- Analytics (off by default, warning) -->
  <div class="settings-row settings-row--nested${disClass}">
    <div class="settings-row-label">
      <div class="settings-row-title">Analytics
        <span class="settings-row-tag settings-row-tag--caution">may break sites</span>
      </div>
      <div class="settings-row-hint">Google Analytics, Mixpanel, Segment…</div>
    </div>
    <label class="settings-toggle" aria-label="Block analytics">
      <input type="checkbox" id="setting-block-analytics"${s.block_analytics ? ' checked' : ''}${disAttr}>
      <span class="settings-toggle-track"></span>
    </label>
  </div>

  <!-- Allow-list -->
  <div class="settings-row">
    <div class="settings-row-label">
      <div class="settings-row-title">Allow-list</div>
      <div class="settings-row-hint">Domains exempted from blocking. Add entries via the request detail panel.</div>
    </div>
    <div class="settings-row-side">
      <button type="button" class="settings-ghost-btn" id="settings-export-allowlist">
        Export
      </button>
      <button type="button" class="settings-ghost-btn" id="settings-view-allowlist">
        View list
      </button>
    </div>
  </div>

  <!-- Session stats -->
  <div class="settings-row${disClass}">
    <div class="settings-row-label">
      <div class="settings-row-title">Session blocking stats</div>
      <div class="settings-row-hint">Blocked, stripped, and flagged counts for the current session.</div>
    </div>
    <button type="button" class="settings-ghost-btn" id="settings-clear-blocking-stats"${disAttr}>
      Clear
    </button>
  </div>

</div>`;
}

// ── Allow-list modal ──────────────────────────────────────────────────────────

function renderAllowlistModalContent(entries) {
  if (!entries || entries.length === 0) {
    return `<div class="modal-empty">
      <svg width="24" height="24" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5" aria-hidden="true">
        <path d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"/>
      </svg>
      <span>No domains in the allow-list yet.</span>
    </div>`;
  }
  const rows = entries.map(e => {
    const [site, domain] = e.split(':');
    return `<tr>
      <td class="allowlist-td allowlist-td--site">${site === '*' ? '<em>All sites</em>' : site}</td>
      <td class="allowlist-td allowlist-td--domain">${domain}</td>
      <td class="allowlist-td allowlist-td--action">
        <button class="allowlist-remove-btn" data-entry="${e}" type="button">Remove</button>
      </td>
    </tr>`;
  }).join('');
  return `
<table class="allowlist-table">
  <thead>
    <tr>
      <th class="allowlist-th">Site</th>
      <th class="allowlist-th">Allowed domain</th>
      <th class="allowlist-th"></th>
    </tr>
  </thead>
  <tbody>${rows}</tbody>
</table>`;
}

// ── Mode hint copy ────────────────────────────────────────────────────────────

const BLOCKING_MODE_HINTS = {
  smart: 'ML confidence and category toggles control what gets blocked.',
  strict: 'Blocks all third-party requests except known CDNs, regardless of score.',
  strip_only: 'Removes tracking query parameters only; no domain blocking.',
};

function updateBlockingModeHint(mode) {
  const el = document.getElementById('blocking-mode-hint');
  if (el) el.textContent = BLOCKING_MODE_HINTS[mode] || '';
  const thresholdRow = document.getElementById('blocking-threshold-row');
  const thresholdSlider = document.getElementById('setting-block-threshold');
  const armed = !!document.getElementById('setting-blocking-enabled')?.checked;
  const smartOnly = mode === 'smart' && armed;
  if (thresholdRow) thresholdRow.classList.toggle('settings-row--inactive', !smartOnly);
  if (thresholdSlider) thresholdSlider.disabled = !smartOnly;
}

// ── Event binding ─────────────────────────────────────────────────────────────

function bindBlockingSettingsEvents(saveSettingFieldFn) {
  const enabledToggle = document.getElementById('setting-blocking-enabled');
  if (!enabledToggle) return;

  const optionIds = [
    'setting-blocking-mode', 'setting-block-threshold',
    'setting-block-session-replay', 'setting-block-fingerprinting',
    'setting-block-behavioral', 'setting-block-ad-network', 'setting-block-analytics',
  ];

  function setBlockingArmed(armed) {
    // Toggle disabled attribute on controls
    for (const id of optionIds) {
      const el = document.getElementById(id);
      if (el) el.disabled = !armed;
    }
    // Toggle disabled visual class on rows
    document.querySelectorAll('#settings-blocking .settings-row--disabled').forEach(el => {
      el.classList.remove('settings-row--disabled');
    });
    if (!armed) {
      document.querySelectorAll(
        '#blocking-mode-row, #blocking-threshold-row, #settings-blocking .settings-row--nested'
      ).forEach(el => {
        el.classList.add('settings-row--disabled');
      });
    }
    // Toggle armed state on the section card
    const section = document.getElementById('settings-blocking');
    if (section) section.classList.toggle('settings-section--blocking-armed', armed);
    const modeSelect = document.getElementById('setting-blocking-mode');
    if (modeSelect) updateBlockingModeHint(modeSelect.value);
  }

  enabledToggle.addEventListener('change', (e) => {
    const enabled = e.target.checked;
    saveSettingFieldFn('blocking_enabled', enabled);
    setBlockingArmed(enabled);
  });

  const modeSelect = document.getElementById('setting-blocking-mode');
  if (modeSelect) {
    updateBlockingModeHint(modeSelect.value);
    modeSelect.addEventListener('change', (e) => {
      saveSettingFieldFn('blocking_mode', e.target.value);
      updateBlockingModeHint(e.target.value);
    });
  }

  const thresholdSlider = document.getElementById('setting-block-threshold');
  const thresholdLabel  = document.getElementById('block-threshold-label');
  thresholdSlider?.addEventListener('input', (e) => {
    if (thresholdLabel) thresholdLabel.textContent = Math.round(parseFloat(e.target.value) * 100) + '%';
  });
  thresholdSlider?.addEventListener('change', (e) => {
    saveSettingFieldFn('block_threshold', parseFloat(e.target.value));
  });

  const toggleMap = {
    'setting-block-session-replay': 'block_session_replay',
    'setting-block-fingerprinting': 'block_fingerprinting',
    'setting-block-behavioral':     'block_behavioral',
    'setting-block-ad-network':     'block_ad_network',
    'setting-block-analytics':      'block_analytics',
  };
  for (const [id, key] of Object.entries(toggleMap)) {
    document.getElementById(id)?.addEventListener('change', (e) => {
      saveSettingFieldFn(key, e.target.checked);
    });
  }

  document.getElementById('settings-view-allowlist')?.addEventListener('click', () => {
    chrome.storage.local.get('blocking:allowlist', (r) => {
      showAllowlistModal(r['blocking:allowlist'] || []);
    });
  });

  document.getElementById('settings-export-allowlist')?.addEventListener('click', () => {
    chrome.storage.local.get('blocking:allowlist', (r) => {
      const entries = r['blocking:allowlist'] || [];
      const text = JSON.stringify(entries, null, 2);
      navigator.clipboard.writeText(text).then(() => {
        const btn = document.getElementById('settings-export-allowlist');
        if (btn) {
          const orig = btn.textContent;
          btn.textContent = 'Copied';
          setTimeout(() => { btn.textContent = orig; }, 1500);
        }
      });
    });
  });

  document.getElementById('settings-clear-blocking-stats')?.addEventListener('click', () => {
    chrome.storage.local.get('session:current', (r) => {
      const sid = r['session:current']?.id;
      if (!sid) return;
      chrome.runtime.sendMessage({ type: 'clear_blocking_stats', session_id: sid }, (res) => {
        if (res?.ok) {
          blockingStats = { blocked: 0, stripped: 0, warned: 0 };
          renderBlockingStatsBadges();
        }
      });
    });
  });
}

function showAllowlistModal(entries) {
  let modal = document.getElementById('allowlist-modal');
  if (!modal) {
    modal = document.createElement('div');
    modal.id = 'allowlist-modal';
    modal.className = 'specter-modal-overlay';
    document.body.appendChild(modal);
  }

  modal.innerHTML = `
<div class="specter-modal">
  <div class="specter-modal-header">
    <span class="specter-modal-title">Blocking allow-list</span>
    <button class="specter-modal-close" id="allowlist-close" type="button" aria-label="Close">
      <svg width="12" height="12" viewBox="0 0 12 12" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round">
        <line x1="1" y1="1" x2="11" y2="11"/><line x1="11" y1="1" x2="1" y2="11"/>
      </svg>
    </button>
  </div>
  <div class="specter-modal-body">
    ${renderAllowlistModalContent(entries)}
  </div>
</div>`;

  modal.style.display = 'flex';
  modal.addEventListener('click', (e) => { if (e.target === modal) modal.style.display = 'none'; });
  document.getElementById('allowlist-close')?.addEventListener('click', () => { modal.style.display = 'none'; });

  modal.querySelectorAll('.allowlist-remove-btn').forEach(btn => {
    btn.addEventListener('click', async () => {
      const entry = btn.dataset.entry;
      const r = await new Promise(res => chrome.storage.local.get('blocking:allowlist', res));
      const updated = (r['blocking:allowlist'] || []).filter(e => e !== entry);
      await new Promise(res => chrome.storage.local.set({ 'blocking:allowlist': updated }, res));
      chrome.runtime.sendMessage({ type: 'rebuild_dnr_rules' });
      btn.closest('tr')?.remove();
      // If table is now empty, swap to empty state
      if (!modal.querySelector('.allowlist-table tbody tr')) {
        modal.querySelector('.specter-modal-body').innerHTML = renderAllowlistModalContent([]);
      }
    });
  });
}

// ── Request detail panel: "Allow on this site" buttons ────────────────────────

function renderAllowOnSiteButton(domain, initiatorDomain) {
  return `
<div class="detail-allow-row">
  <button class="detail-allow-btn" id="detail-allow-btn"
    data-domain="${domain}"
    data-site="${initiatorDomain || ''}"
    type="button">
    Allow on this site
  </button>
  <button class="detail-allow-btn detail-allow-btn--global" id="detail-allow-global-btn"
    data-domain="${domain}"
    type="button">
    Allow everywhere
  </button>
</div>`;
}

function bindAllowOnSiteButtons(onAllowed) {
  document.getElementById('detail-allow-btn')?.addEventListener('click', (e) => {
    const { domain, site } = e.currentTarget.dataset;
    chrome.runtime.sendMessage({ type: 'allow_domain', domain, site: site || '*' }, (r) => {
      if (r?.ok && onAllowed) onAllowed(domain, site || '*');
    });
  });
  document.getElementById('detail-allow-global-btn')?.addEventListener('click', (e) => {
    const { domain } = e.currentTarget.dataset;
    chrome.runtime.sendMessage({ type: 'allow_domain', domain, site: '*' }, (r) => {
      if (r?.ok && onAllowed) onAllowed(domain, '*');
    });
  });
}
