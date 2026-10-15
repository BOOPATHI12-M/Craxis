# AI Phishing Guard: Code Analysis and How the Extension Works

This document explains how the code in this folder is organised and how the Chrome extension runs end to end. It describes version 1.1.0.

## 1. What this project is

AI Phishing Guard is a Manifest V3 Chrome extension. It scores every http/https page a user visits for phishing risk. It combines three signals:

1. **URL rules** written in JavaScript.
2. **Page structure (DOM) checks** run by a content script inside the page.
3. **A machine learning model** served by a local Flask API at `http://127.0.0.1:5000`.

The result is shown as an on-page badge or banner, a blocking warning page for dangerous sites, an explainable report in the popup, and a saved history and dashboard.

## 2. Folder map

| Path | Role |
| :--- | :--- |
| `manifest.json` | Extension config: permissions, service worker, popup, options page, content scripts |
| `background.js` | Service worker. Auto-scan, early block check, tab state, history, trust and proceed handling |
| `content.js` | Runs in every page. DOM analysis and badge or banner rendering |
| `shared/config.json` | Single source of truth: rules, keywords, brands, TLDs, thresholds, trusted domains |
| `shared/config.js` | Generated from `config.json` by `tools/sync_config.py` |
| `shared/scoring.js` | URL rules, brand detection, trust, score fusion, classification |
| `shared/settings.js` | Settings stored in `chrome.storage.sync` |
| `shared/api.js` | Backend client with caching and timeouts |
| `popup.*` | Toolbar popup: report, manual scan, trust button |
| `options.*` | Settings page |
| `warning.*` | Blocking warning page |
| `history.*`, `dashboard.*` | Scan history and analytics |
| `ml/app.py` | Flask API: `/predict`, `/health`, `/model-info`, `/api/model-evaluation`, `/test-pages/*` |
| `ml/feature_extractor.py` | URL to 32 numeric features |
| `ml/build_dataset.py` | Builds training data from PhishTank and Tranco |
| `ml/train_model.py`, `ml/evaluate_model.py` | Training and held-out evaluation |
| `ml/domain_intel.py` | Optional domain age and certificate lookups |
| `test-pages/` | Ten harmless local pages (TC01 to TC10) |
| `tests/`, `ml/tests/` | JavaScript, Python and browser tests |
| `tools/` | Config generator and trusted-domain builder |

## 3. Manifest and permissions

- **Manifest version:** 3, with `background.js` as the service worker.
- **Permissions:** `scripting`, `storage`, `webNavigation`.
- **Host permissions:** `http://*/*` and `https://*/*`. This also covers the call to the backend.
- **Content scripts:** `shared/config.js`, `shared/scoring.js`, `content.js` on every http/https page.
- **Options page:** `options.html`.

## 4. Runtime flow

```text
Navigation starts
   |
   v
webNavigation.onBeforeNavigate (main frame)
   |-- skip if auto-scan or blocking is off, site trusted, or user chose to proceed
   |-- URL rules + AI model (AI skipped for local addresses)
   |-- DANGEROUS? -> replace the tab with warning.html
   v
Page loads
   |
   v
tabs.onUpdated (status = "complete")
   |-- skip non-http(s) pages and a repeat scan within 8 s
   v
runAutomaticScan
   +--> analyzeURL(url)                 URL rule score
   +--> content.js ANALYZE_PAGE         page score
   +--> POST /predict                   AI score (skipped for local addresses)
   v
calculateCombinedScore
   |-- weighted fusion, corroboration floor, trusted cap
   v
   +--> tab state in memory and chrome.storage.session
   +--> saveScanToHistory (chrome.storage.local, max 100)
   +--> DANGEROUS and blocking on -> warning.html
        otherwise SHOW_WARNING -> badge or banner in the page
```

### 4.1 Messages

| Action | From | To | Purpose |
| :--- | :--- | :--- | :--- |
| `ANALYZE_PAGE` | background, popup | content.js | Return DOM analysis |
| `SHOW_WARNING` | background | content.js | Render badge or banner |
| `GET_TAB_SCAN` | popup | background | Read the tab's latest scan |
| `STORE_MANUAL_SCAN` | popup | background | Save a manual scan and history entry |
| `TRUST_SITE`, `UNTRUST_SITE` | popup, warning page | background | Edit the trusted-site list |
| `PROCEED_ANYWAY` | warning page | background | Remember the choice for the session and load the page |
| `GO_TO_SAFETY` | warning page | background | Open a new tab page |
| `OPEN_HISTORY` | any page | background | Open `history.html` |

## 5. Detection layers

### 5.1 URL rules (`analyzeURL` in `shared/scoring.js`)

| Rule | Points |
| :--- | :---: |
| Not HTTPS | +20 |
| IPv4 address as hostname | +30 |
| `@` in URL | +25 |
| URL longer than 100 characters | +15 |
| More than 3 dots in hostname | +15 |
| Sensitive keyword in hostname | +10 |
| Sensitive keyword only in path | +3 |
| URL shortener | +15 |
| Punycode hostname | +15 |
| Frequently abused TLD | +10 |
| 3 or more hyphens in hostname | +10 |
| Brand name in an unrelated domain, homoglyph or typo-squat | +25 |
| Malformed URL | 100 |

The total is capped at 100. Domain age under 30 days (+25) or 90 days (+10) and an invalid certificate (+15) can be added when the optional lookups are on.

### 5.2 DOM analysis (`analyzePage` in `content.js`)

| Check | Points |
| :--- | :---: |
| Sensitive keyword in page title | +5 |
| Password field on an HTTP page, with no form, or posting to another domain | +10 |
| Form posts to a different domain | +25 |
| Suspicious links (`javascript:`, `@`, link to another IP host) | +15 |
| Hidden links | +10 |
| External iframe | +10 |
| Brand named in title or site name but hosted elsewhere, with a form or password field | +20 |
| Icon loaded from another domain on a page with a password field | +5 |

A same-origin HTTPS login form adds nothing. The code reads only structure. It never reads typed values, cookies or passwords.

### 5.3 Model (`ml/app.py`)

1. `extract_features(url)` builds 32 numbers: lengths, counts, subdomain depth, HTTPS flag, IP flag, entropy, keyword count, brand flags, TLD flag, shared-hosting flag and lexical measures of the site name.
2. The model returns a class and a phishing probability.
3. The API returns `prediction`, `phishing_probability` and `ai_risk_score`.

The model is not applied to localhost and private network addresses.

## 6. Fusion, trust and classification

| Available signals | URL | Page | AI |
| :--- | :---: | :---: | :---: |
| All three | 30% | 20% | 50% |
| URL + AI | 35% | n/a | 65% |
| URL + page | 60% | 40% | n/a |
| URL only | 100% | n/a | n/a |

After weighting:

- **Corroboration.** If at least two layers are available and all score 50 or more, the result is raised to the DANGEROUS threshold.
- **Trust.** Built-in trusted domains (HTTPS, not on shared hosting) and the user's trusted list cap the score at 20.

| Score (defaults) | Class | What the user sees |
| :---: | :--- | :--- |
| 0 to 29 | SAFE | Small badge, bottom right |
| 30 to 59 | SUSPICIOUS | Banner at the top with reasons |
| 60 to 100 | DANGEROUS | Warning page, or a banner when blocking is off |

Thresholds are user settings. Classification is decided once, in the background, and the content script follows `statusLevel`.

## 7. Popup, options, history and dashboard

- **Popup:** reads the tab's scan with `GET_TAB_SCAN`, or runs the same pipeline on demand. It shows each layer, an AI offline notice with Retry, a Trust this site button and a link to Settings.
- **Options:** switches, thresholds, backend address with a connection test, optional intelligence and the trusted-site list.
- **History:** reads `aiphish_scan_history`. Search, filter, details, clear.
- **Dashboard:** counts, score bins, trend and common indicators from the same data.

## 8. How to run it

1. `pip install -r requirements.txt` then `python ml/app.py` (or `start-backend.ps1`, `./start-backend.sh`, Docker).
2. Open `chrome://extensions`, enable **Developer mode**, **Load unpacked**, choose this folder.
3. Browse. Open `http://127.0.0.1:5000/test-pages/index.html` for the safe test pages.
4. After a code change press the reload icon on the extension card.

The backend is optional. Without it the extension uses URL and page checks.

## 9. Tests

| Command | What it covers |
| :--- | :--- |
| `python -m pytest ml/tests` | Feature extractor, API, dataset splitting, intel safety, config sync |
| `npm test` | Scoring rules, fusion, trust, settings, JavaScript and Python parity |
| `npm run test:e2e` | Real Chromium with the extension: TC01 to TC10, blocking, proceed, trust, settings, page loads |

## 10. Known limits

- **Training data.** Phishing URLs come from one feed. Legitimate URLs use real domains with synthetic paths. Held-out results are useful for comparing versions, not as a guarantee of real-world accuracy.
- **Single-layer limits.** A clean-looking HTTPS phishing page with no page indicators can still score only SUSPICIOUS.
- **Local pages.** `127.0.0.1` over HTTP scores 30 from the URL rules alone, so a developer on a local IP sees a banner. Use Trust this site.
- **Backend dependency.** The AI layer needs the backend on the configured address.
- **Redirect chains** and **page-content features in the model** are not implemented.
- **Settings sync.** The trusted list lives in `chrome.storage.sync` and may sync across devices.

## 11. Where to change things

| Goal | File and place |
| :--- | :--- |
| Add or tune a URL rule | `analyzeURL` in `shared/scoring.js` |
| Change keywords, brands, TLDs, thresholds | `shared/config.json`, then `python tools/sync_config.py` |
| Add a DOM check | `analyzePage` in `content.js` |
| Change weights or the corroboration floor | `shared/config.json` and `calculateCombinedScore` |
| Add an ML feature | `ml/feature_extractor.py`, then `python ml/train_model.py` |
| Refresh the trusted list | `python tools/build_trusted_domains.py` |
| Change blocking behaviour | `maybeBlock` and `onBeforeNavigate` in `background.js` |
