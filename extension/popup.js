/* Specter — popup script */

const statusPill    = document.getElementById('status-pill');
const statusLabel   = document.getElementById('status-label');
const timerEl       = document.getElementById('timer');
const currentSiteEl = document.getElementById('current-site');
const scoreEl       = document.getElementById('privacy-score');
const scoreDenomEl  = document.getElementById('privacy-score-denom');
const scoreLabelEl  = document.getElementById('privacy-score-label');
const scoreBlockEl  = document.getElementById('popup-score-block');
const trackerEl     = document.getElementById('tracker-count');
const blockingEl    = document.getElementById('blocking-count');
const actionsEl     = document.getElementById('popup-actions');
const dashboardLink = document.getElementById('open-dashboard');
const copyBtn       = document.getElementById('btn-copy-report');

let timerInterval = null;
let currentDomain = '';

// ─── Helpers ──────────────────────────────────────────────────────────────────

function eTLDPlusOne(hostname) {
  if (!hostname) return '';
  const parts = hostname.split('.');
  return parts.length <= 2 ? hostname : parts.slice(-2).join('.');
}

function formatElapsed(ms) {
  const s = Math.floor(ms / 1000);
  const h = Math.floor(s / 3600);
  const m = Math.floor((s % 3600) / 60);
  const sec = s % 60;
  if (h > 0) return [h, m, sec].map((n) => String(n).padStart(2, '0')).join(':');
  return [m, sec].map((n) => String(n).padStart(2, '0')).join(':');
}

function scoreClass(score) {
  if (score == null) return '';
  if (score >= 75) return 'score--high';
  if (score >= 45) return 'score--mid';
  return 'score--low';
}

function isInternalInitiator(initiator) {
  if (!initiator || initiator === '_direct') return true;
  const s = String(initiator);
  return s.startsWith('[') || /^(chrome|edge|about|devtools|chrome-extension|moz-extension):/i.test(s);
}

function requestMatchesSite(req, siteDomain) {
  if (!siteDomain) return false;
  let init = req.initiator_domain || '_direct';
  if (isInternalInitiator(init)) init = siteDomain;
  if (init === siteDomain) return true;
  try {
    if (init.includes('.')) return eTLDPlusOne(init) === siteDomain;
  } catch {
    /* ignore */
  }
  return init === siteDomain;
}

function siteStatsFromRequests(requests, siteDomain) {
  if (!siteDomain || !Array.isArray(requests)) return { total: 0, trackers: 0 };
  let total = 0;
  let trackers = 0;
  for (const req of requests) {
    if (!requestMatchesSite(req, siteDomain)) continue;
    total += 1;
    const cat = req.category;
    if (cat && cat !== 'legitimate' && cat !== 'unclassified') trackers += 1;
  }
  return { total, trackers };
}

function formatScanningStats(siteDomain, stats) {
  const site = siteDomain || 'this site';
  const n = stats.total;
  if (n === 0) return 'SCANNING ' + site + ' — waiting for requests';
  let line = n + ' request' + (n === 1 ? '' : 's') + ' so far';
  if (stats.trackers > 0) {
    line += ' · ' + stats.trackers + ' tracker' + (stats.trackers === 1 ? '' : 's');
  }
  return line;
}

function setScoreScanningMode(scanning) {
  if (scoreBlockEl) scoreBlockEl.classList.toggle('popup-score-block--scanning', scanning);
  if (scoreDenomEl) {
    scoreDenomEl.hidden = scanning;
    if (!scanning) scoreDenomEl.hidden = false;
  }
  if (scoreLabelEl) scoreLabelEl.textContent = scanning ? 'SCANNING' : 'PRIVACY SCORE';
  if (scanning) {
    scoreEl.textContent = '···';
    scoreEl.className = 'popup-score-number popup-score-number--scanning';
  }
}

function updateSiteFromTab(tab) {
  if (tab?.url?.startsWith('http')) {
    try {
      currentDomain = eTLDPlusOne(new URL(tab.url).hostname);
      currentSiteEl.textContent = currentDomain;
      return;
    } catch {
      /* fall through */
    }
  }
  if (tab?.url) {
    currentDomain = '';
    currentSiteEl.textContent = 'Unsupported page';
  } else {
    currentDomain = '';
    currentSiteEl.textContent = 'No active tab';
  }
}

// ─── Timer ────────────────────────────────────────────────────────────────────

function startTimer() {
  stopTimer();
  function tick() {
    chrome.storage.local.get(['session:current', 'session:paused', 'session:elapsed_frozen'], (r) => {
      const session = r['session:current'];
      if (!session || !session.active) { stopTimer(); return; }
      if (r['session:paused']) {
        const sec = Math.max(0, Number(r['session:elapsed_frozen']) || 0);
        timerEl.textContent = formatElapsed(sec * 1000);
      } else {
        timerEl.textContent = formatElapsed(Date.now() - session.started_at);
      }
    });
  }
  tick();
  timerInterval = setInterval(tick, 1000);
}

function stopTimer() {
  if (timerInterval) { clearInterval(timerInterval); timerInterval = null; }
  timerEl.textContent = '';
}

// ─── Actions ──────────────────────────────────────────────────────────────────

function renderActions(state) {
  actionsEl.innerHTML = '';

  function btn(cls, label, onClick) {
    const b = document.createElement('button');
    b.type = 'button';
    b.className = 'popup-action-btn popup-action-btn--' + cls;
    b.textContent = label;
    b.addEventListener('click', onClick);
    return b;
  }

  if (state === 'stopped') {
    actionsEl.appendChild(btn('start', '▶  START SESSION', () => {
      chrome.runtime.sendMessage({ type: 'start_session' }, () => refreshUI());
    }));

  } else if (state === 'recording') {
    actionsEl.appendChild(btn('pause', '⏸  PAUSE', () => {
      chrome.storage.local.get('session:current', (r) => {
        const session = r['session:current'];
        if (!session || !session.active) return;
        const elapsed = Math.floor((Date.now() - session.started_at) / 1000);
        chrome.runtime.sendMessage({ type: 'pause_session', elapsed_seconds: elapsed }, () => refreshUI());
      });
    }));
    actionsEl.appendChild(btn('stop', '■  STOP', () => {
      chrome.runtime.sendMessage({ type: 'stop_session' }, () => refreshUI());
    }));

  } else if (state === 'paused') {
    actionsEl.appendChild(btn('resume', '▶  RESUME', () => {
      chrome.runtime.sendMessage({ type: 'resume_session' }, () => refreshUI());
    }));
    actionsEl.appendChild(btn('stop', '■  STOP', () => {
      chrome.runtime.sendMessage({ type: 'stop_session' }, () => refreshUI());
    }));
  }
}

// ─── State update ─────────────────────────────────────────────────────────────

function setUIState(active, paused) {
  const state = !active ? 'stopped' : paused ? 'paused' : 'recording';
  statusPill.dataset.state = state;
  statusLabel.textContent = state.toUpperCase();
  renderActions(state);

  if (state === 'recording') {
    startTimer();
  } else {
    stopTimer();
    if (state === 'paused') {
      chrome.storage.local.get('session:elapsed_frozen', (r) => {
        const sec = Math.max(0, Number(r['session:elapsed_frozen']) || 0);
        timerEl.textContent = formatElapsed(sec * 1000);
      });
    }
  }
}

function renderActiveSession(session, scores, requests) {
  const entry = currentDomain ? scores[currentDomain] : null;
  const live = siteStatsFromRequests(requests, currentDomain);

  if (entry) {
    setScoreScanningMode(false);
    const s = entry.privacy_score;
    scoreEl.textContent = String(s);
    scoreEl.className = 'popup-score-number ' + scoreClass(s);
    const n = entry.tracker_requests || 0;
    trackerEl.textContent = n + ' tracker' + (n === 1 ? '' : 's') + ' detected';
    trackerEl.classList.remove('popup-tracker-count--scanning');
    return;
  }

  setScoreScanningMode(true);
  trackerEl.textContent = formatScanningStats(currentDomain, live);
  trackerEl.classList.add('popup-tracker-count--scanning');
}

// ─── Full UI refresh ──────────────────────────────────────────────────────────

function refreshUI() {
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    updateSiteFromTab(tabs[0]);

    chrome.storage.local.get(['session:current', 'session:paused', 'session:elapsed_frozen'], (data) => {
      const session = data['session:current'];
      const active  = !!(session && session.active);
      const paused  = !!(active && data['session:paused']);

      setUIState(active, paused);

      if (!active) {
        setScoreScanningMode(false);
        scoreEl.textContent = '—';
        scoreEl.className = 'popup-score-number';
        trackerEl.textContent = '—';
        trackerEl.classList.remove('popup-tracker-count--scanning');
        chrome.storage.local.get(['blocking:daily', 'settings'], (res) => {
          renderBlockingCount(res.settings, res['blocking:daily']);
        });
        return;
      }

      const reqKey = 'requests:' + session.id;
      const scoresKey = 'scores:' + session.id;
      chrome.storage.local.get([reqKey, scoresKey, 'blocking:daily', 'settings'], (res) => {
        renderBlockingCount(res.settings, res['blocking:daily']);
        const scores = res[scoresKey] || {};
        const requests = res[reqKey] || [];
        renderActiveSession(session, scores, requests);
      });
    });
  });
}

function renderBlockingCount(settings, daily) {
  if (!blockingEl) return;
  const enabled = !!settings?.blocking_enabled;
  const today = new Date().toISOString().slice(0, 10);
  const blockedToday = daily?.date === today ? (daily.blocked || 0) : 0;
  if (!enabled || blockedToday === 0) {
    blockingEl.hidden = true;
    blockingEl.textContent = '';
    return;
  }
  const label = blockedToday === 1 ? '1 blocked today' : blockedToday + ' blocked today';
  blockingEl.textContent = label;
  blockingEl.title = 'Blocking is on — domains blocked today across sessions';
  blockingEl.hidden = false;
}

// ─── Dashboard link ───────────────────────────────────────────────────────────

dashboardLink.addEventListener('click', (e) => {
  e.preventDefault();
  chrome.tabs.create({ url: chrome.runtime.getURL('dashboard.html') });
});

// ─── Copy report ──────────────────────────────────────────────────────────────

copyBtn.addEventListener('click', () => {
  chrome.storage.local.get('session:current', (r) => {
    const session = r['session:current'];
    const site = currentDomain || '—';
    const buildText = (score, trackers) => [
      'Specter Privacy Report',
      '─────────────────────',
      'Site:              ' + site,
      'Privacy score:     ' + (score != null ? score + '/100' : '—'),
      'Trackers detected: ' + (trackers != null ? trackers : '—'),
      '',
      'Generated by Specter',
    ].join('\n');

    if (session && session.active) {
      chrome.storage.local.get(['scores:' + session.id, 'requests:' + session.id], (res) => {
        const entry = (res['scores:' + session.id] || {})[currentDomain];
        let trackers = entry?.tracker_requests;
        if (trackers == null && currentDomain) {
          trackers = siteStatsFromRequests(res['requests:' + session.id] || [], currentDomain).trackers;
        }
        const text = buildText(entry?.privacy_score, trackers);
        navigator.clipboard.writeText(text).then(() => flashBtn(copyBtn, 'Copied ✓'));
      });
    } else {
      navigator.clipboard.writeText(buildText(null, null)).then(() => flashBtn(copyBtn, 'Copied ✓'));
    }
  });
});

function flashBtn(btn, label) {
  const orig = btn.textContent;
  btn.textContent = label;
  setTimeout(() => { btn.textContent = orig; }, 1500);
}

// ─── Reactive updates ─────────────────────────────────────────────────────────

chrome.storage.onChanged.addListener((changes, area) => {
  if (area !== 'local') return;
  const relevant = ['session:current', 'session:paused', 'session:elapsed_frozen', 'settings'];
  const hasScoreChange = currentDomain && Object.keys(changes).some((k) => k.startsWith('scores:'));
  const hasRequestChange = Object.keys(changes).some((k) => k.startsWith('requests:'));
  const hasBlockingStats =
    'blocking:daily' in changes || Object.keys(changes).some((k) => k.startsWith('blocking:stats:'));
  if (relevant.some((k) => k in changes) || hasScoreChange || hasRequestChange || hasBlockingStats) refreshUI();
});

// ─── Init ─────────────────────────────────────────────────────────────────────

chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => updateSiteFromTab(tabs[0]));
refreshUI();
