# Privacy Policy — Specter Privacy Auditor

*Last updated: April 2, 2026*

## Overview

Specter Privacy Auditor is a Chrome extension that analyzes network requests made by your browser. This policy explains what data Specter accesses, how it is used, and what leaves your device.

## Data Collection

Specter does not collect, transmit, or store any data on external servers. No data ever leaves your machine.

Specter accesses the following data locally:

- **Network request metadata** — URLs, headers, response sizes, and timing of requests made by your browser. This data is used exclusively for classification and is stored in your browser's local IndexedDB.
- **Browsing activity** — The domains you visit are used to compute per-site privacy scores. This data never leaves your device.

## Data Storage

All data is stored locally in your browser using IndexedDB. Sessions are retained according to your configured data retention setting (default: 30 days). You can delete individual sessions or all data at any time from the Settings page.

## Third-Party Services

Specter optionally integrates with the VirusTotal API for domain reputation lookups. If you provide a VirusTotal API key in Settings, Specter will send domain names (never full URLs or paths) to VirusTotal's API. This feature is disabled by default and entirely opt-in. VirusTotal's privacy policy applies to those requests.

## ML Classifier

Specter's ML classifier runs entirely locally using ONNX Runtime. No request data is sent to any external service for classification.

## Permissions

Specter requests the following Chrome permissions:

- `webRequest` — to intercept and analyze network requests
- `storage` — to persist session data locally
- `tabs` — to associate requests with the correct tab and domain

These permissions are used exclusively for the features described above.

## Changes

This policy may be updated occasionally. The latest version will always be available at this URL.

## Contact

For questions or concerns, open an issue on the [GitHub repository](https://github.com/divij404/specter).
