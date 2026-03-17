/* Specter — popup script */

const btnStart = document.getElementById('btn-start');
const btnStop = document.getElementById('btn-stop');
const linkDashboard = document.getElementById('open-dashboard');
const btnCopyReport = document.getElementById('btn-copy-report');
const statusDot = document.getElementById('status-dot');
const statusLabel = document.getElementById('status-label');
const timerEl = document.getElementById('timer');
const currentSiteEl = document.getElementById('current-site');
const privacyScoreEl = document.getElementById('privacy-score');
const trackerCountEl = document.getElementById('tracker-count');

let timerInterval = null;
let currentDomain = '';

function eTLDPlusOne(hostname) {
  if (!hostname) return '';
  const parts = hostname.split('.');
  if (parts.length <= 2) return hostname;
  return parts.slice(-2).join('.');
}

function setSessionState(active) {
  btnStart.disabled = !!active;
  btnStop.disabled = !active;
  statusDot.className = 'popup-status-dot ' + (active ? 'popup-status-dot--recording' : 'popup-status-dot--stopped');
  statusLabel.textContent = active ? 'RECORDING' : 'STOPPED';
  if (active) startTimer(); else stopTimer();
}

function formatElapsed(ms) {
  const totalSec = Math.floor(ms / 1000);
  const h = Math.floor(totalSec / 3600);
  const m = Math.floor((totalSec % 3600) / 60);
  const s = totalSec % 60;
  if (h > 0) return [h, m, s].map((n) => String(n).padStart(2, '0')).join(':');
  return [m, s].map((n) => String(n).padStart(2, '0')).join(':');
}

function startTimer() {
  stopTimer();
  function tick() {
    chrome.storage.local.get('session:current', (result) => {
      const session = result['session:current'];
      if (!session || !session.active) {
        stopTimer();
        return;
      }
      timerEl.textContent = formatElapsed(Date.now() - session.started_at);
    });
  }
  tick();
  timerInterval = setInterval(tick, 1000);
}

function stopTimer() {
  if (timerInterval) {
    clearInterval(timerInterval);
    timerInterval = null;
  }
  timerEl.textContent = '00:00';
}

function scoreColorClass(score) {
  if (score == null || score === undefined) return 'popup-score--none';
  if (score >= 80) return 'popup-score--high';
  if (score >= 50) return 'popup-score--mid';
  return 'popup-score--low';
}

function refreshUI() {
  chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
    const tab = tabs[0];
    if (tab && tab.url && (tab.url.startsWith('http:') || tab.url.startsWith('https:'))) {
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

    chrome.storage.local.get(['session:current'], (result) => {
      const session = result['session:current'];
      const active = session && session.active;
      setSessionState(active);

      if (!active) {
        privacyScoreEl.textContent = '—';
        privacyScoreEl.className = 'popup-score popup-score--none';
        trackerCountEl.textContent = '0 trackers detected';
        return;
      }

      const scoresKey = 'scores:' + session.id;
      chrome.storage.local.get([scoresKey], (res) => {
        const scores = res[scoresKey] || {};
        const entry = currentDomain ? scores[currentDomain] : null;
        if (entry) {
          privacyScoreEl.textContent = String(entry.privacy_score);
          privacyScoreEl.className = 'popup-score ' + scoreColorClass(entry.privacy_score);
          const n = entry.tracker_requests || 0;
          trackerCountEl.textContent = n + ' tracker' + (n === 1 ? '' : 's') + ' detected';
        } else {
          privacyScoreEl.textContent = '—';
          privacyScoreEl.className = 'popup-score popup-score--none';
          trackerCountEl.textContent = '0 trackers detected';
        }
      });
    });
  });
}

btnStart.addEventListener('click', () => {
  chrome.runtime.sendMessage({ type: 'start_session' }, () => {
    refreshUI();
  });
});

btnStop.addEventListener('click', () => {
  chrome.runtime.sendMessage({ type: 'stop_session' }, () => {
    refreshUI();
  });
});

linkDashboard.addEventListener('click', (e) => {
  e.preventDefault();
  chrome.tabs.create({ url: chrome.runtime.getURL('dashboard.html') });
});

btnCopyReport.addEventListener('click', () => {
  chrome.storage.local.get(['session:current'], (result) => {
    const session = result['session:current'];
    const site = currentDomain || 'No site';
    let score = '—';
    let trackers = '0';
    if (session && session.active) {
      const scoresKey = 'scores:' + session.id;
      chrome.storage.local.get([scoresKey], (res) => {
        const scores = res[scoresKey] || {};
        const entry = currentDomain ? scores[currentDomain] : null;
        if (entry) {
          score = String(entry.privacy_score);
          trackers = String(entry.tracker_requests || 0);
        }
        const text = [
          'Specter Report',
          'Site: ' + site,
          'Privacy score: ' + score,
          'Trackers detected: ' + trackers,
          '',
          'Generated by Specter (Chrome extension)',
        ].join('\n');
        navigator.clipboard.writeText(text).then(() => {
          const orig = btnCopyReport.textContent;
          btnCopyReport.textContent = 'Copied';
          setTimeout(() => { btnCopyReport.textContent = orig; }, 1500);
        });
      });
    } else {
      const text = [
        'Specter Report',
        'Site: ' + site,
        'Privacy score: ' + score,
        'Trackers detected: ' + trackers,
        '',
        'Generated by Specter (Chrome extension)',
      ].join('\n');
      navigator.clipboard.writeText(text).then(() => {
        const orig = btnCopyReport.textContent;
        btnCopyReport.textContent = 'Copied';
        setTimeout(() => { btnCopyReport.textContent = orig; }, 1500);
      });
    }
  });
});

chrome.storage.onChanged.addListener((changes, areaName) => {
  if (areaName !== 'local') return;
  if (changes['session:current'] || (currentDomain && Object.keys(changes).some((k) => k.startsWith('scores:')))) {
    refreshUI();
  }
});

refreshUI();
