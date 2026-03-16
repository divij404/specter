/* Specter — dashboard script */

let requestCount = 0;

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

chrome.runtime.onMessage.addListener((message) => {
  if (message.type === 'request_update') {
    requestCount += 1;
    updateStatus('Requests: ' + requestCount);
  } else if (message.type === 'session_started') {
    requestCount = 0;
    updateStatus('Recording');
  } else if (message.type === 'session_stopped') {
    updateStatus('Stopped (total: ' + requestCount + ')');
  }
});
