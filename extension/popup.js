/* Specter — popup script */

const statusPill    = document.getElementById('status-pill');
const statusLabel   = document.getElementById('status-label');
const timerEl       = document.getElementById('timer');
const currentSiteEl = document.getElementById('current-site');
const scoreEl       = document.getElementById('privacy-score');
const trackerEl     = document.getElementById('tracker-count');
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

// ─── Full UI refresh ──────────────────────────────────────────────────────────

function refreshUI() {
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    const tab = tabs[0];
    if (tab?.url?.startsWith('http')) {
      try {
        currentDomain = eTLDPlusOne(new URL(tab.url).hostname);
        currentSiteEl.textContent = currentDomain;
      } catch {
        currentDomain = '';
        currentSiteEl.textContent = '—';
      }
    } else {
      currentDomain = '';
      currentSiteEl.textContent = '—';
    }

    chrome.storage.local.get(['session:current', 'session:paused', 'session:elapsed_frozen'], (data) => {
      const session = data['session:current'];
      const active  = !!(session && session.active);
      const paused  = !!(active && data['session:paused']);

      setUIState(active, paused);

      if (!active) {
        scoreEl.textContent = '—';
        scoreEl.className = 'popup-score-number';
        trackerEl.textContent = '—';
        trackerEl.classList.remove('popup-tracker-count--scanning');
        return;
      }

      chrome.storage.local.get('scores:' + session.id, (res) => {
        const scores = res['scores:' + session.id] || {};
        const entry  = currentDomain ? scores[currentDomain] : null;

        if (entry) {
          const s = entry.privacy_score;
          scoreEl.textContent = String(s);
          scoreEl.className = 'popup-score-number ' + scoreClass(s);
          const n = entry.tracker_requests || 0;
          trackerEl.textContent = n + ' tracker' + (n === 1 ? '' : 's') + ' detected';
          trackerEl.classList.remove('popup-tracker-count--scanning');
        } else {
          scoreEl.textContent = '—';
          scoreEl.className = 'popup-score-number';
          trackerEl.textContent = 'Scanning…';
          trackerEl.classList.add('popup-tracker-count--scanning');
        }
      });
    });
  });
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
      chrome.storage.local.get('scores:' + session.id, (res) => {
        const entry = (res['scores:' + session.id] || {})[currentDomain];
        const text = buildText(entry?.privacy_score, entry?.tracker_requests);
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
  const relevant = ['session:current', 'session:paused', 'session:elapsed_frozen'];
  const hasScoreChange = currentDomain && Object.keys(changes).some((k) => k.startsWith('scores:'));
  if (relevant.some((k) => k in changes) || hasScoreChange) refreshUI();
});

// ─── Init ─────────────────────────────────────────────────────────────────────

refreshUI();
