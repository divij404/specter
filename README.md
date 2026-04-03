# Specter

A Chrome extension that records and classifies every network request your browser makes — trackers, analytics, ads, fingerprinting scripts, session replay tools, and more — so you can see exactly what a site is doing in the background.

Everything runs locally. No server, no proxy, no data leaves your machine.

---

## Features

**Live feed** — real-time stream of classified requests as you browse. Filter by category, domain, confidence, or current tab. Group duplicate requests. Pause and resume without losing data.

**ML classifier** — an XGBoost model (300 rounds, 5 classes) trained on real browsing sessions classifies each request with a confidence score. Falls back to a weighted multi-signal rule-based scorer if the model isn't available. Explainability panel shows which signals drove each classification.

**Privacy score** — per-site score (0–100) updated in real time based on tracker density, fingerprinting exposure, session replay presence, and ad network activity.

**Site summary** — doughnut chart and category breakdown for the active site or any site visited in the session.

**Timeline** — request volume over time, color-coded by category.

**Fingerprinting panel** — surfaces canvas, font, WebGL, audio, and other fingerprinting signals detected for the current site.

**Request detail** — full URL breakdown, headers, response metadata, top feature importances, and optional VirusTotal domain reputation lookup.

**Session history** — all completed sessions stored locally. Sort by date, tracker count, or privacy score. Click any session to open a per-site breakdown sidebar. Export full JSON or copy a plain-text report to clipboard.

**Settings** — autoscroll toggle, minimum confidence filter (synced with feed toolbar), data retention, VirusTotal API key with enable/disable toggle, ML vs rule-based classifier toggle, clear all data.

**Training crawl** — built-in crawl engine (Chrome alarm-based, visible to `webRequest`) generates labeled training data. Connect to your own Chrome instance and let Specter classify requests across hundreds of sites automatically.

---

## Install

**Load unpacked (recommended for development)**

1. `npm install && npm run bundle-libs` — copies D3 into `extension/lib/` (required for the timeline)
2. Open `chrome://extensions` → enable **Developer mode** → **Load unpacked** → select the `extension/` folder
3. Pin the Specter icon to your toolbar

No build step beyond bundling libs. The extension ships as plain JS.

---

## Requirements

- **Chrome 114+** (Manifest V3)
- **Node.js 18+** — only needed for building from source or running the crawl tools

---

## ML Classifier

The extension ships with a pre-trained model at `extension/data/model.json` (XGBoost, ~2.4 MB, pure JSON). It classifies requests into five categories:

| Class | Description |
|---|---|
| `legitimate` | First-party assets, CDN content, fonts, stylesheets |
| `analytics` | Google Analytics, Mixpanel, Segment, etc. |
| `ad_network` | Ad exchanges, DSPs, bidding infrastructure |
| `behavioral` | Cross-site tracking, retargeting pixels |
| `fingerprinting` | Canvas/font/WebGL fingerprinting scripts |

`session_replay` (Hotjar, FullStory, etc.) is handled by a separate rule-based classifier and is excluded from the model.

### Retraining

To retrain the model on your own crawl data:

```bash
# 1. Launch Chrome with remote debugging
npm run chrome

# 2. In another terminal — start a session from the Specter popup, then:
npm run crawl

# 3. Export sessions from the dashboard (FULL EXPORT) → save to tools/exports/

# 4. Train
pip install xgboost scikit-learn onnxmltools numpy
python tools/train.py
# Outputs: extension/data/model.json + extension/data/model_labels.json
```

The training script filters to confidence > 0.70 (silver labels), balances classes by sample weight, and prints a classification report and feature importance ranking.

---

## Data

All session data is stored in `chrome.storage.local` — no external requests except optional VirusTotal lookups (requires your own API key). Data is never synced to your Google account.

Keys:
- `session:current` — active session metadata
- `requests:{session_id}` — array of classified request objects
- `scores:{session_id}` — per-site privacy scores
- `sessions:history` — list of completed session summaries
- `settings` — user preferences

---

## Project Structure

```
extension/          Chrome extension (load this folder)
  dashboard.html/js/css   Main analysis dashboard
  popup.html/js/css       Toolbar popup (start/stop session)
  service_worker.js       Request interception, classification, storage
  data/
    blocklist.json        Tracker domain blocklist
    model.json            XGBoost model (pre-trained)
    model_labels.json     Class label index
    sites.txt             Site list for training crawls

tools/
  crawl.js          Puppeteer-based crawl driver (connects to user Chrome)
  launch-chrome.js  Launches Chrome with --remote-debugging-port=9222
  train.py          ML training pipeline (XGBoost → model.json)
  exports/          Session JSON exports (gitignored)

scripts/
  bundle-libs.js    Copies D3 into extension/lib/
```
