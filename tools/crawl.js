'use strict';

/**
 * Specter — training data crawler
 *
 * Connects to your already-running Chrome (launched via `npm run chrome`),
 * starts a Specter session automatically, visits a curated list of sites,
 * then stops the session and saves a full JSON export to tools/exports/.
 *
 * Usage:
 *   1. npm run chrome     ← launch Chrome with remote debugging (once per session)
 *   2. npm run crawl      ← connect, crawl, export
 *
 * To customise the site list, edit tools/sites.txt (one URL per line).
 * Lines starting with # are comments / section headers and are skipped.
 *
 * Dwell time per page is controlled by DWELL_MS below (default 18 s).
 */

const puppeteer = require('puppeteer-core');
const path      = require('path');
const fs        = require('fs');

// ── Config ──────────────────────────────────────────────────────────────────

const SITES_FILE  = path.resolve(__dirname, '../extension/data/sites.txt');
const EXPORTS_DIR = path.resolve(__dirname, 'exports');
const DWELL_MS    = 6_000;
const NAV_TIMEOUT = 30_000;
const DEBUG_PORT  = process.env.CHROME_DEBUG_PORT || 9222;

// ── Load site list ───────────────────────────────────────────────────────────

function loadSites() {
  if (!fs.existsSync(SITES_FILE)) {
    console.error(`[crawl] sites.txt not found at ${SITES_FILE}`);
    process.exit(1);
  }
  return fs.readFileSync(SITES_FILE, 'utf8')
    .split('\n')
    .map(l => l.trim())
    .filter(l => l && !l.startsWith('#'));
}

// ── Helpers ──────────────────────────────────────────────────────────────────

function sleep(ms)  { return new Promise(r => setTimeout(r, ms)); }
function fmt(ms) {
  const s = Math.round(ms / 1000);
  const m = Math.floor(s / 60);
  return m > 0 ? `${m}m ${s % 60}s` : `${s}s`;
}

// ── Connect to running Chrome ─────────────────────────────────────────────────

async function connectToChrome() {
  try {
    const browser = await puppeteer.connect({
      browserURL: `http://localhost:${DEBUG_PORT}`,
      defaultViewport: null,
    });
    return browser;
  } catch {
    console.error(`[crawl] Could not connect to Chrome on port ${DEBUG_PORT}.`);
    console.error('[crawl] Run  npm run chrome  first, wait for Chrome to load, then retry.');
    process.exit(1);
  }
}

// ── Find Specter extension ID ─────────────────────────────────────────────────
//
// Three-layer fallback:
//   1. Raw CDP endpoint  — GET http://localhost:{port}/json lists ALL targets
//      including MV3 service workers that Puppeteer's API doesn't expose
//   2. --id=<extensionId> CLI arg — paste from chrome://extensions
//   3. undefined → navigate-only mode (user stops + exports manually)

async function getExtensionId() {
  // Layer 1 — env var or CLI arg (--id=xxx or --id xxx)
  const envId = process.env.SPECTER_ID;
  const argIdx = process.argv.findIndex(a => a === '--id' || a.startsWith('--id='));
  const cliId  = argIdx !== -1
    ? (process.argv[argIdx].includes('=')
        ? process.argv[argIdx].split('=')[1]
        : process.argv[argIdx + 1])
    : null;
  const id = (envId || cliId || '').trim();
  if (id) {
    console.log(`[crawl] Extension ID: ${id}`);
    return id;
  }

  // Layer 2 — raw CDP fetch (bypasses Puppeteer's target wrapper)
  try {
    const res  = await fetch(`http://localhost:${DEBUG_PORT}/json`);
    const targets = await res.json();
    const sw = targets.find(
      t => t.type === 'service_worker' && t.url && t.url.startsWith('chrome-extension://')
    );
    if (sw) {
      const id = new URL(sw.url).hostname;
      console.log(`[crawl] Extension ID (auto-detected): ${id}`);
      return id;
    }
    // Any extension target at all
    const any = targets.find(t => t.url && t.url.startsWith('chrome-extension://'));
    if (any) {
      const id = new URL(any.url).hostname;
      console.warn(`[crawl] SW not found but found extension target — using ID: ${id}`);
      return id;
    }
  } catch {
    // fetch failed — Chrome might not be running yet (handled in connectToChrome)
  }

  // Layer 3 — navigate-only mode
  console.warn('[crawl] Specter extension not detected via CDP.');
  console.warn('[crawl] To enable auto-start/stop, re-run with:');
  console.warn('[crawl]   npm run crawl -- --id=<extensionId>');
  console.warn('[crawl] Find the ID at chrome://extensions (enable Developer mode).');
  console.warn('[crawl] Proceeding in navigate-only mode — start your Specter session');
  console.warn('[crawl] manually now, then stop and export from the dashboard when done.\n');
  return undefined;
}

// ── Start / stop session via popup page ──────────────────────────────────────

async function startSession(browser, extensionId) {
  const popup = await browser.newPage();
  await popup.goto(`chrome-extension://${extensionId}/popup.html`, { waitUntil: 'load' });
  await sleep(500);
  // Click the START SESSION button rendered by renderActions('stopped')
  await popup.waitForSelector('.popup-action-btn--start', { timeout: 5000 });
  await popup.click('.popup-action-btn--start');
  await sleep(500);
  await popup.close();
  console.log('[crawl] Session started.');
}

async function stopSession(browser, extensionId) {
  const popup = await browser.newPage();
  await popup.goto(`chrome-extension://${extensionId}/popup.html`, { waitUntil: 'load' });
  await sleep(500);
  try {
    await popup.waitForSelector('.popup-action-btn--stop', { timeout: 5000 });
    await popup.click('.popup-action-btn--stop');
    await sleep(1500); // let SW flush + write history
  } catch {
    console.warn('[crawl] Stop button not found — session may already be stopped.');
  }
  await popup.close();
  console.log('[crawl] Session stopped.');
}

// ── Export full session JSON directly from extension storage ─────────────────

async function exportSession(browser, extensionId) {
  const bg = await browser.newPage();
  await bg.goto(`chrome-extension://${extensionId}/dashboard.html`, { waitUntil: 'load' });
  await sleep(1000);

  const payload = await bg.evaluate(async () => {
    return new Promise((resolve) => {
      chrome.storage.local.get(['session:current'], async (r) => {
        const session = r['session:current'];
        if (!session) return resolve(null);
        const id = session.id;
        chrome.storage.local.get(['requests:' + id, 'scores:' + id], (res) => {
          resolve({
            summary:  session,
            requests: res['requests:' + id] || [],
            scores:   res['scores:' + id]   || {},
          });
        });
      });
    });
  });

  await bg.close();
  return payload;
}

// ── Main ─────────────────────────────────────────────────────────────────────

async function main() {
  const sites = loadSites();

  fs.mkdirSync(EXPORTS_DIR, { recursive: true });

  console.log(`[crawl] Connecting to Chrome on port ${DEBUG_PORT}…`);
  const browser = await connectToChrome();
  console.log('[crawl] Connected.');

  console.log(`[crawl] Sites:      ${sites.length}`);
  console.log(`[crawl] Dwell:      ${fmt(DWELL_MS)} / page`);
  console.log(`[crawl] Est. total: ~${fmt(sites.length * (DWELL_MS + 5000))}\n`);

  let extensionId = await getExtensionId();

  if (extensionId) {
    try {
      await startSession(browser, extensionId);
    } catch (e) {
      console.warn(`[crawl] Auto-start blocked (${e.message.split('\n')[0]})`);
      console.warn('[crawl] Chrome restricts extension page access via remote debugging.');
      console.warn('[crawl] Make sure your Specter session is running, then press Enter…');
      await new Promise(r => process.stdin.once('data', r));
      extensionId = undefined; // skip auto-stop/export too
    }
  } else {
    console.log('[crawl] Navigate-only mode — start your Specter session now, then press Enter…');
    await new Promise(r => process.stdin.once('data', r));
  }

  // Open a dedicated crawl tab
  const page = await browser.newPage();
  page.on('pageerror', () => {});

  let ok = 0, failed = 0;
  const startedAt = Date.now();

  for (let i = 0; i < sites.length; i++) {
    const url       = sites[i];
    const elapsed   = fmt(Date.now() - startedAt);
    const remaining = fmt((sites.length - i) * (DWELL_MS + 5000));
    process.stdout.write(`[${i + 1}/${sites.length}] ${elapsed} elapsed, ~${remaining} left  →  ${url}\n`);

    try {
      await page.goto(url, { waitUntil: 'domcontentloaded', timeout: NAV_TIMEOUT });
      await sleep(DWELL_MS);
      ok++;
    } catch (e) {
      process.stdout.write(`        ✗ ${e.message.split('\n')[0]}\n`);
      failed++;
    }
  }

  if (extensionId) {
    console.log(`\n[crawl] Crawl done. ${ok} ok, ${failed} failed. Stopping session…`);
    await stopSession(browser, extensionId);

    console.log('[crawl] Exporting session data…');
    const data = await exportSession(browser, extensionId);

    if (data && data.requests.length > 0) {
      const outFile = path.join(EXPORTS_DIR, `specter-full-${data.summary.id}.json`);
      fs.writeFileSync(outFile, JSON.stringify(data, null, 2));
      console.log(`[crawl] ✓ Exported ${data.requests.length} requests → ${outFile}`);
    } else {
      console.warn('[crawl] No request data found in storage — export skipped.');
      console.warn('[crawl] You can still export manually from the dashboard history.');
    }
  } else {
    console.log(`\n[crawl] Crawl done. ${ok} ok, ${failed} failed.`);
    console.log('[crawl] Navigate-only mode — stop the session and export from the dashboard.');
  }

  const total = fmt(Date.now() - startedAt);
  console.log(`[crawl] Total time: ${total}`);
  browser.disconnect(); // detach without closing the user's Chrome
}

main().catch(err => {
  console.error('[crawl] Fatal:', err.message);
  process.exit(1);
});
