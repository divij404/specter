# Specter

Specter is a self-contained Chrome Extension that intercepts, classifies, and visualizes browser network traffic in real time for privacy auditing. It categorizes each request by tracker type from request metadata alone. There is no external server, no Docker, no proxy, and no installation beyond loading the extension in Chrome.

## Architecture

Everything runs inside the Chrome extension: request interception via `chrome.webRequest`, classification in the service worker, storage in `chrome.storage.local`, and a full-page dashboard plus toolbar popup. No data leaves your machine.

**Classifier:** The extension currently uses a **rule-based classifier** (URL patterns, tracking params, blocklist, response headers) so it runs reliably in the service worker.

## Prerequisites

- **Chrome 114+** (Manifest V3)
- **Python 3.10+** (only for training the model via `train.py`;)

## Developer setup

1. **Blocklist** (optional): `extension/data/blocklist.json` is used for rule-based classification. Populate it via `train.py` when implemented, or leave as `[]`.
2. Bundle frontend libs (D3, Lucide) into the extension:
   ```bash
   npm install
   node scripts/bundle-libs.js
   ```
3. Generate placeholder icons (if not already present):
   ```bash
   node scripts/generate-icons.js
   ```
4. In Chrome, open `chrome://extensions`, turn on **Developer mode**, click **Load unpacked**, and select the `extension` folder.

The extension should load with no manifest or CSP errors.

## End-user setup

1. Download the latest release zip from the Specter GitHub Releases page and unzip to a folder.
2. In Chrome, open `chrome://extensions`, enable **Developer mode**, click **Load unpacked**, and select the unzipped folder.

## What Specter captures (and what it doesn’t)

Specter uses the Chrome `webRequest` API. It has access to **request and response metadata** only: URL, method, headers, status, size, content-type, timing. It does **not** have access to response bodies. That is an intentional tradeoff: no proxy or root certificate is required, so the tool stays simple and privacy-preserving. The classifier is trained on these metadata features and still achieves strong tracker detection.
