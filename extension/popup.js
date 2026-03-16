/* Specter — popup script */

const btnStart = document.getElementById('btn-start');
const btnStop = document.getElementById('btn-stop');
const linkDashboard = document.getElementById('open-dashboard');

function setSessionState(active) {
  btnStart.disabled = !!active;
  btnStop.disabled = !active;
}

function refreshSessionState() {
  chrome.storage.local.get('session:current', (result) => {
    const session = result['session:current'];
    setSessionState(session && session.active);
  });
}

btnStart.addEventListener('click', () => {
  chrome.runtime.sendMessage({ type: 'start_session' }, () => {
    refreshSessionState();
  });
});

btnStop.addEventListener('click', () => {
  chrome.runtime.sendMessage({ type: 'stop_session' }, () => {
    refreshSessionState();
  });
});

linkDashboard.addEventListener('click', (e) => {
  e.preventDefault();
  chrome.tabs.create({ url: chrome.runtime.getURL('dashboard.html') });
});

refreshSessionState();
