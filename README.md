# Specter

Chrome extension that records and classifies network requests (trackers, analytics, ads, etc.). All in-browser—no server. Click **Start** in the popup to record, **Stop** to save. Open **Dashboard** to see the count. Data stays local (metadata only, no response bodies).

## Install

- **Store / release zip:** Install from Chrome Web Store or load the unzipped folder at `chrome://extensions` (Developer mode → Load unpacked). No build step.
- **From source:** Run `npm install && npm run bundle-libs`, then `node scripts/generate-icons.js` if you need icons. Load the `extension` folder in Chrome (Load unpacked).

## Requirements

- Chrome 114+
- Node.js (for bundling from source)

Blocklist path: `extension/data/blocklist.json` (empty `[]` is valid).
