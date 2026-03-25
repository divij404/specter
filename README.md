# Specter

A Chrome extension that records and classifies network requests—trackers, analytics, ads, and more—so you can see what a site is doing in the background. Everything runs in the browser: no server, no proxy, no data sent off your machine.

**How it works:** Click **Start** in the popup to begin recording. As you browse, Specter classifies each request (rule-based: URL patterns, tracking params, blocklist). Click **Stop** to save the session. Open the **Dashboard** to see request count and session stats; use **Copy Report** for a quick summary. The toolbar badge shows how many trackers have been logged in the current session.

---

## Install

**From the Chrome Web Store (or a release zip)**  
Install the extension or load the unzipped folder at `chrome://extensions` (turn on **Developer mode**, then **Load unpacked**). No build step.

**From source**  
1. `npm install && npm run bundle-libs` (copies D3 and other vendored libs into `extension/lib/` — required for the dashboard timeline)  
2. `node scripts/generate-icons.js` if you need icons  
3. Open `chrome://extensions` → **Load unpacked** → select the `extension` folder  

---

## Requirements

- **Chrome 114+** (Manifest V3)
- **Node.js** (only for building from source)

The extension uses a blocklist at `extension/data/blocklist.json`. An empty array `[]` is valid; you can populate it later for better tracker detection.
