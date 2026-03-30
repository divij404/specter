'use strict';

/**
 * Specter — launch Chrome with remote debugging enabled
 *
 * Run this once before `npm run crawl`. Chrome opens normally with your real
 * profile and all installed extensions (including Specter). The crawl script
 * then connects to it via the remote debugging port — no profile copying,
 * no extension loading flags, no automation restrictions.
 *
 * Usage:
 *   npm run chrome      ← run this first, leave the window open
 *   npm run crawl       ← run this after Chrome has fully loaded
 */

const { spawn } = require('child_process');
const fs         = require('path');
const path       = require('path');

const DEBUG_PORT = process.env.CHROME_DEBUG_PORT || 9222;

function findChrome() {
  if (process.env.CHROME_PATH) return process.env.CHROME_PATH;

  const candidates = [
    'C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe',
    'C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe',
    process.env.LOCALAPPDATA
      ? path.join(process.env.LOCALAPPDATA, 'Google\\Chrome\\Application\\chrome.exe')
      : null,
    '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
    '/usr/bin/google-chrome',
    '/usr/bin/chromium-browser',
  ].filter(Boolean);

  for (const p of candidates) {
    try { require('fs').accessSync(p); return p; } catch {}
  }

  console.error('[chrome] Could not find Chrome. Set CHROME_PATH env var to chrome.exe path.');
  process.exit(1);
}

const chromePath = findChrome();
console.log(`[chrome] Executable: ${chromePath}`);
console.log(`[chrome] Debug port: ${DEBUG_PORT}`);
console.log(`[chrome] Launching…\n`);

const child = spawn(
  chromePath,
  [`--remote-debugging-port=${DEBUG_PORT}`],
  { detached: true, stdio: 'ignore' }
);
child.unref();

console.log('[chrome] Chrome launched. Wait for it to fully load, then run:');
console.log('[chrome]   npm run crawl');
