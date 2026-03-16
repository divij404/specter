/* Specter — popup script */

document.getElementById('open-dashboard').addEventListener('click', (e) => {
  e.preventDefault();
  chrome.tabs.create({ url: chrome.runtime.getURL('dashboard.html') });
});
