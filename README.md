# Specter

[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](./LICENSE)
[![Release](https://img.shields.io/github/v/release/divij404/specter)](https://github.com/divij404/specter/releases)
[![Chrome Web Store](https://img.shields.io/chrome-web-store/v/dimockbooampdcmcboibloaflhmpokbl?logo=googlechrome&label=Chrome%20Web%20Store)](https://chromewebstore.google.com/detail/specter/dimockbooampdcmcboibloaflhmpokbl)
[![Users](https://img.shields.io/chrome-web-store/users/dimockbooampdcmcboibloaflhmpokbl?logo=googlechrome)](https://chromewebstore.google.com/detail/specter/dimockbooampdcmcboibloaflhmpokbl)

> A Chrome extension that intercepts and classifies every network request your browser makes — trackers, analytics, ads, fingerprinting scripts, session replay tools, and more — so you can see exactly what a site is doing in the background.

Everything runs **locally**. No server. No proxy. No data leaves your machine.

---

## Table of Contents

- [Features](#features)
- [Install](#install)
- [Requirements](#requirements)
- [ML Classifier](#ml-classifier)
- [Retraining](#retraining)
- [Data & Privacy](#data--privacy)
- [Project Structure](#project-structure)
- [License](#license)

---

## Features

| Feature | Description |
|---|---|
| **Live Feed** | Real-time stream of classified requests. Filter by category, domain, confidence, or tab. Group duplicates. Pause and resume without losing data. |
| **ML Classifier** | XGBoost model (300 rounds, 5 classes) trained on real browsing sessions. Confidence scores per request. Falls back to weighted rule-based scorer. Explainability panel shows top signals. |
| **Privacy Score** | Per-site score (0–100) updated in real time based on tracker density, fingerprinting exposure, session replay presence, and ad activity. |
| **Site Summary** | Doughnut chart and category breakdown for the active site or any session site. |
| **Timeline** | Request volume over time via D3.js, color-coded by category. |
| **Fingerprinting Panel** | Surfaces canvas, font, WebGL, audio, and other fingerprinting signals. |
| **Request Detail** | Full URL breakdown, headers, response metadata, feature importances, and optional VirusTotal domain reputation lookup. |
| **Session History** | All sessions stored locally. Sort by date, tracker count, or privacy score. Per-site breakdown sidebar. Full JSON export or plain-text report copy. |
| **Settings** | Autoscroll, confidence filter, data retention, VirusTotal API key, ML vs rule-based toggle, clear all data. |
| **Training Crawl** | Built-in crawl engine connects to your Chrome instance and generates labeled training data across hundreds of sites. |

---

## Install

### Chrome Web Store

The easiest way — no build step required.

[**Install from the Chrome Web Store →**](https://chromewebstore.google.com/detail/specter/dimockbooampdcmcboibloaflhmpokbl)

### Load Unpacked (Development)

```bash
npm install
npm run bundle-libs   # copies D3 into extension/lib/ (required for timeline)
```

1. Open `chrome://extensions`
2. Enable **Developer mode** (top right toggle)
3. Click **Load unpacked** → select the `extension/` folder
4. Pin the Specter icon to your toolbar

> No build step beyond bundling libs. The extension ships as plain JS.

---

## Requirements

- **Chrome 114+** (Manifest V3)
- **Node.js 18+** — only needed for building from source or running the crawl tools

---

## ML Classifier

Specter ships with a pre-trained model at `extension/data/model.json` (XGBoost, ~2.4 MB, pure JSON). It classifies requests into five categories:

| Class | Description |
|---|---|
| `legitimate` | First-party assets, CDN content, fonts, stylesheets |
| `analytics` | Google Analytics, Mixpanel, Segment, etc. |
| `ad_network` | Ad exchanges, DSPs, bidding infrastructure |
| `behavioral` | Cross-site tracking, retargeting pixels |
| `fingerprinting` | Canvas/font/WebGL fingerprinting scripts |

`session_replay` (Hotjar, FullStory, etc.) is handled by a separate rule-based classifier.

The classifier extracts **27 features per request** — URL structure, response size, header patterns, domain reputation, path semantics — and classifies each in under 50ms via ONNX Runtime.

**Model stats:** trained on 25,290 real browsing requests · 96.2% accuracy · weighted F1: 0.967

---

## Retraining

To retrain on your own crawl data:

```bash
# 1. Launch Chrome with remote debugging
npm run chrome

# 2. Start a session from the Specter popup, then in another terminal:
npm run crawl

# 3. Export sessions from the dashboard (Full Export) → save to tools/exports/

# 4. Train
pip install xgboost scikit-learn onnxmltools numpy
python tools/train.py
# Outputs: extension/data/model.json + extension/data/model_labels.json
```

The training script filters to confidence > 0.70 (silver labels), balances classes by sample weight, and prints a classification report and feature importance ranking.

---

## Data & Privacy

All session data is stored in `chrome.storage.local`. No external requests are made except **optional** VirusTotal lookups (requires your own API key). Data is never synced to your Google account.

| Key | Contents |
|---|---|
| `session:current` | Active session metadata |
| `requests:{session_id}` | Array of classified request objects |
| `scores:{session_id}` | Per-site privacy scores |
| `sessions:history` | List of completed session summaries |
| `settings` | User preferences |

---

## Project Structure

```
specter/
├── extension/          # Load this folder in chrome://extensions
│   ├── dashboard.html/js/css   # Main analysis dashboard
│   ├── popup.html/js/css       # Toolbar popup (start/stop session)
│   ├── service_worker.js       # Request interception, classification, storage
│   └── data/
│       ├── blocklist.json      # Tracker domain blocklist
│       ├── model.json          # Pre-trained XGBoost model
│       ├── model_labels.json   # Class label index
│       └── sites.txt           # Site list for training crawls
├── tools/
│   ├── crawl.js                # Puppeteer crawl driver (connects to user Chrome)
│   ├── launch-chrome.js        # Launches Chrome with --remote-debugging-port=9222
│   ├── train.py                # ML training pipeline (XGBoost → model.json)
│   └── exports/                # Session JSON exports (gitignored)
└── scripts/
    └── bundle-libs.js          # Copies D3 into extension/lib/
```

---

## License

[MIT](./LICENSE) — Divij Agarwal
