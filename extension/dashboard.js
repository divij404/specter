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
let clearFeedOnStart = false;
let frozenElapsedSeconds = 0;


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
    btn.textContent = '■ STOP';
    btn.classList.remove('stopped');
    btn.classList.add('running');
  } else {
    btn.textContent = '▶ START';
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
    const row = document.createElement('div');
    row.className = 'feed-row' + (g.id === selectedRequestId ? ' feed-row--selected' : '') + (isNew ? ' feed-row-enter' : '');
    row.setAttribute('data-request-id', g.id);
    row.setAttribute('role', 'button');
    row.setAttribute('tabindex', '0');

    const confPct = ((req.confidence ?? 0) * 100).toFixed(0);
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

    row.innerHTML =
      '<span class="feed-cell feed-cell-badge"><span class="feed-badge ' +
      badgeClass +
      '"><span class="feed-badge-dot"></span>' +
      escapeAttr(categoryLabel(req.category)) +
      '</span></span>' +
      '<span class="feed-cell feed-cell-domain" title="' +
      escapeAttr(req.domain || '') +
      '">' +
      escapeAttr(req.domain || '—') +
      countHtml +
      '</span>' +
      '<span class="feed-cell feed-cell-url' + urlCellClass + '" title="' + escapeAttr(urlFull) + '">' +
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
    fragment.appendChild(row);
  });
  list.appendChild(fragment);

  const container = document.getElementById('feed-container');
  if (animateLast && filtered.length > 0 && settings.autoscroll_feed && !scrollState.userScrolledUp && container) {
    requestAnimationFrame(() => { container.scrollTop = 0; });
  }
}

function renderFeed(animateLast = false) {
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
  renderFeed(false);
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
  CATEGORIES.forEach((cat) => {
    const label = document.createElement('label');
    label.className = 'feed-filter-dropdown-option';
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
  const hasTab = filterState.tabFilter === 'current' && currentTabId != null;
  const hasAny = hasCategory || hasMinConf || hasDomain || hasTab;

  container.textContent = '';
  row.hidden = !hasAny;
  if (!hasAny) return;

  if (hasCategory) {
    filterState.categories.forEach((cat) => {
      const chip = document.createElement('span');
      chip.className = 'feed-active-chip';
      chip.innerHTML = '<span class="feed-active-chip-label">' + escapeAttr(categoryLabel(cat)) + '</span><button type="button" class="feed-active-chip-remove" aria-label="Remove filter">×</button>';
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
  if (hasTab) {
    const chip = document.createElement('span');
    chip.className = 'feed-active-chip';
    chip.innerHTML = '<span class="feed-active-chip-label">Current tab</span><button type="button" class="feed-active-chip-remove" aria-label="Remove filter">×</button>';
    chip.querySelector('.feed-active-chip-remove').addEventListener('click', () => {
      filterState.tabFilter = 'all';
      currentTabId = null;
      const tabLabelEl = document.getElementById('feed-tab-trigger-label');
      if (tabLabelEl) tabLabelEl.textContent = 'Tab: All tabs';
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

function init() {
  buildFilterBar();

  hideSessionConfirmBar();

  const detailCloseBtn = document.getElementById('detail-close');
  if (detailCloseBtn) {
    detailCloseBtn.addEventListener('click', () => closeDetailPanel());
  }
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') {
      const categoryPanel = document.querySelector('#feed-category-dropdown .feed-filter-dropdown-panel');
      const tabPanelEl = document.querySelector('#feed-tab-dropdown .feed-filter-dropdown-panel');
      if (categoryPanel && categoryPanel.classList.contains('is-open')) {
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
  renderFeed(false);

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
      chrome.storage.local.get(['requests:' + session.id], (res) => {
        const loaded = res['requests:' + session.id];
        if (Array.isArray(loaded) && loaded.length > 0) {
          feedRequests = loaded;
          requestCount = feedRequests.length;
          updateStatus('Requests: ' + requestCount);
          renderFeed(false);
        }
      });
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
      clearFeedOnStart = true;
      hideSessionConfirmBar();
      chrome.runtime.sendMessage({ type: 'start_session' });
    });
  }
  if (confirmKeep) {
    confirmKeep.addEventListener('click', () => {
      clearFeedOnStart = false;
      hideSessionConfirmBar();
      chrome.runtime.sendMessage({ type: 'start_session' });
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
    } else if (message.type === 'session_started') {
      hideSessionConfirmBar();
      feedPaused = false;
      frozenElapsedSeconds = 0;
      if (clearFeedOnStart) {
        feedRequests = [];
        requestCount = 0;
        pendingNewCount = 0;
        lastGroupCounts.clear();
      }
      clearFeedOnStart = false;
      sessionStartTime = Date.now();
      currentSession = { id: message.session_id, active: true };
      startSessionTimer();
      updateFeedHeaderDot();
      updateStatus('Recording');
      updateSessionButton(true);
      renderFeed(false);
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

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', init);
} else {
  init();
}
