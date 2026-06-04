# Changelog

All notable changes to Specter are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [1.4.0] — 2026-06-04

### Added
- Dashboard **Network** tab: live D3 force-directed graph of domain-to-domain request flow (initiator → target)
- Graph respects feed filters and site-summary scope (same as timeline); debounced live updates during recording
- Headline stat for third-party system count; category legend; 500-node cap with truncation banner
- **Export SVG** and **Reset layout** controls; click a node to filter the feed by that domain

### Changed
- Bottom activity panel refactored to three tabs: Timeline, Fingerprinting, Network
- Extension version **1.4.0**

## [1.3.1] — 2026-06-04

### Added
- Popup shows **N blocked today** when blocking is enabled (`blocking:daily` aggregate)
- DNR cleanup rules for trailing `?` and `?&` after param-only strips

### Fixed
- Site summary no longer hides score and KPIs when tracker count is zero (clean sites show full panel)
- Allow-list modal no longer stacks duplicate click handlers on reopen
- Param strip leaving `https://example.com?` when the only query param is removed

### Changed
- Settings overlay: 3-column layout (Feed/Classifier · Blocking/FP defense · Integrations)
- Bottom panel: Timeline / Fingerprinting tabs instead of chevron toggle
- Bottom panel card styling aligned with Site Summary; donut center labeled **requests**
- Feed **Clear all** button muted by default; confidence column dimmed when all values match
- Dashboard settings nav icon changed to sliders (no longer reads as brightness)

## [1.3.0] — 2026-06-04

### Added
- **Fingerprint defense** (opt-in, off by default): MAIN-world `document_start` hooks for canvas, WebGL, audio, navigator, and font enumeration APIs
- Per-surface toggles in Dashboard → Settings; session-scoped PRNG seed set when a recording session starts
- Service worker injects `__specter_fp_cfg__` / `__specter_fp_seed__` into `sessionStorage` on navigation (`scripting` + `webNavigation`)

### Changed
- Extension version **1.3**; manifest adds `scripting`, `webNavigation`, and `fp-defense.js` content script (`world: MAIN`, `all_frames`)

## [1.2.2] — 2026-06-04

### Added
- Site summary **BLOCKED** stat when blocking is enabled
- Allow-list **Export** (JSON to clipboard) and **Clear session blocking stats** in settings
- Blocking mode hints for Smart, Strict, and Param strip only
- Popup and settings stats include **flagged** (warn) counts

### Fixed
- Per-site allow no longer removes a domain from global DNR rules — only **Allow everywhere** clears dynamic blocks
- Feed duplicate collapse groups by `block_action` so blocked and observed requests to the same domain stay separate
- Block/strip/warn badges on expanded feed sub-rows

### Changed
- Allow on this site shown for blocked, stripped, and flagged requests in the detail panel

## [1.2.1] — 2026-05-28

### Fixed
- Removed invalid `'fetch'` resource type from DNR dynamic block rules — Chrome rejected the entire `updateDynamicRules` call, so no block rules ever applied
- Fixed param-strip regex capture groups in `buildParamStripRules` — old pattern had 3 groups but substitution used `\1\2`, leaving tracking params intact on many URLs
- Rewrote `blocking-ui.js` to use correct Specter CSS class names — previous version referenced non-existent classes (`settings-row-left`, `settings-row-desc`, `modal-overlay`, `modal-panel`, `modal-close-btn`), making the entire blocking settings section render incorrectly

### Changed
- Blocking settings section redesigned for clarity — removed decorative sub-headers, compacted stats bar, tightened category toggle density to match other settings sections
- Settings overlay now uses a 2-column CSS grid (`1fr 1fr`) instead of a left-aligned `max-width: 580px` column — all four sections (Feed, Integrations, Classifier, Blocking) use full screen width; Danger Zone spans both columns
- Allow-list modal uses namespaced `specter-modal-*` CSS classes to avoid collision with other overlay styles
- Dashboard design token refresh — chromatic border and background values, refined panel depth, 4px visible scrollbars

## [1.2.0] — 2026-05-27 (revised)

### Added

**Adaptive Blocking Engine** — Specter now acts on its classifier output rather than only observing it.

- `blocking.js` — new self-contained blocking engine module loaded by the service worker via `importScripts`. Provides `initBlocking`, `shouldBlock`, `handleOnBeforeRequest`, `handlePostClassify`, `allowDomain`, `rebuildDNRRules`, and blocking stats functions
- `blocking-ui.js` — dashboard UI module for the blocking settings section, feed badges, and "Allow on this site" controls
- `extension/data/blocking_rules.json` — static DNR ruleset seeding 10 high-confidence session-replay and fingerprinting domains (Hotjar, FullStory, LogRocket, Mouseflow, Smartlook, Crazyegg, FingerprintJS, fpjs.io, doubleclick.net, googleadservices.com)
- `manifest.json` — added `declarativeNetRequest`, `declarativeNetRequestFeedback` permissions and `declarative_net_request` ruleset declaration; bumped version to 1.2. (`webRequestBlocking` was intentionally excluded — unavailable to regular MV3 extensions outside enterprise force-install)

**Blocking modes:**
- **Smart** (default) — blocks requests where `confidence ≥ block_threshold` (default 0.85) for behavioral, ad_network, and optionally analytics categories
- **Strict** — blocks all third-party non-CDN requests regardless of classification
- **Param strip only** — strips tracking query parameters without blocking requests

**Always-block categories** (on by default, individually toggleable):
- Session replay (Hotjar, FullStory, LogRocket, etc.)
- Fingerprinting scripts

**URL param stripping** — tracking parameters (`fbclid`, `gclid`, `utm_*`, `__hssc`, etc.) are stripped from request URLs synchronously in `onBeforeRequest` before the request is sent

**DNR dynamic rules** — domains classified as high-confidence trackers at runtime are promoted to `declarativeNetRequest` dynamic rules so future requests are blocked at the network layer before the service worker is even woken

**Per-site allow-list** — users can click "Allow on this site" or "Allow everywhere" in a blocked request's detail panel to exempt a domain from blocking; stored in `blocking:allowlist` and removes the domain from DNR rules

**Dashboard — Blocking settings section:**
- Master on/off toggle (off by default — requires explicit opt-in)
- Blocking mode selector (Smart / Strict / Param strip only)
- Confidence threshold slider with live label (default 85%)
- Category toggles (session replay, fingerprinting, behavioral, ad network, analytics)
- Allow-list viewer with per-entry removal

**Dashboard — Feed integration:**
- Blocked requests show a red `BLOCKED` badge in the feed domain column
- Stripped requests show an amber `STRIPPED` badge
- Request detail panel shows block badge + reason + "Allow on this site" / "Allow everywhere" buttons for blocked requests
- Live blocking stats bar in settings showing blocked/stripped counts for the current session

**Per-session blocking stats** — `blocking:stats:{sessionId}` storage key tracks `{ blocked, stripped, warned }` counts; flushed on session stop

### Changed

- `service_worker.js` — wired `importScripts('blocking.js')`, `initBlocking()` calls in install/activate/wake-up, `setTabUrlCacheRef`/`deleteTabUrlCacheRef` in nav and tab-close handlers, `handleOnBeforeRequest` blocking listener, `handlePostClassify` call in `onCompleted`, `flushBlockStats` in `stop_session` handler
- `service_worker.js` — `DEFAULT_SETTINGS` extended with 9 blocking-related keys
- `service_worker.js` — `storage.onChanged` handler now also calls `applySettingsUpdate` to keep blocking cache in sync with settings changes
- `service_worker.js` — added `allow_domain`, `get_blocking_stats`, and `rebuild_dnr_rules` message handlers
- `dashboard.js` — settings defaults extended with blocking keys; blocking section injected into Settings panel before danger zone; blocking events bound via `bindBlockingSettingsEvents`; `block_action` and `domain_allowed` message handlers added; `initBlockingUI` called on `session_started`
- `dashboard.js` — feed row builder: `renderBlockingBadge` called if `req.block_action` is set
- `dashboard.js` — detail panel: block badge, block reason, and allow-on-site buttons shown for blocked requests
- `dashboard.css` — new blocking UI classes: `.block-badge`, `.blocking-stats-bar`, `.bstat`, `.detail-allow-row`, `.detail-allow-btn`, `.allowlist-table`, `.settings-threshold-value`, `.settings-row--disabled`
- `dashboard.html` — `<script src="blocking-ui.js">` added before `dashboard.js`

### Security

- Blocking is **off by default** — users must explicitly enable it. This prevents unexpected breakage on first install and maintains trust in the classifier before users have seen it in action
- Per-site allow-list is stored locally in `chrome.storage.local` alongside all other Specter data; no cloud sync

---

## [1.1.0] — 2026-05-25

### Added
- ML classifier (XGBoost, pure JS tree traversal, no WASM) loaded from `data/model.json`
- Unique domain count in fingerprinting alerts
- Dashboard session detail and delete confirmation modals

### Changed
- Dashboard UI: risk count display styling
- README expanded with features, installation instructions, project structure

---

## [1.0.1] — Prior

- Initial privacy policy
- Crawl functionality with state restoration and progress tracking
- Settings and crawl overlays
- Session history overlay
