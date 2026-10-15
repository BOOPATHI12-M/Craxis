# AI Phishing Guard: Improvement Roadmap and Status

This roadmap turns the weak points found in `extension.md` into phased work. Status below reflects what was built and verified on 2026-10-15 (version 1.1.0).

## Status overview

| Phase | Goal | Status |
| :--- | :--- | :--- |
| 1 | Quick fixes and safety | Done |
| 2 | Single source of scoring logic | Done |
| 3 | Reduce false positives | Done, with one check not run |
| 4 | Real dataset and model quality | Done, with data limits |
| 5 | Stronger detection signals | Partly done |
| 6 | Real blocking warning page | Done |
| 7 | Automated tests | Done, CI not yet run on GitHub |
| 8 | Settings, packaging and release | Done, Docker image not built, no release tag |

Verification run: 36 Python tests, 23 JavaScript tests and 27 browser checks (10 test pages and 17 flow checks) all pass locally.

---

## Phase 1: Quick fixes and safety (done)

- Warning banner and popup render reasons with `textContent`. `history.js` and `dashboard.js` already escape stored text.
- README matches the code. The DANGEROUS state is a banner, or a full warning page when blocking is on.
- README and `PRIVACY.md` state that full URLs go to the configured backend.
- Model version labels now come from the model file. Nothing is hard-coded in the popup.
- Dead code removed from `content.js`.
- Tab scan state is mirrored into `chrome.storage.session`, so a service worker restart keeps it.

## Phase 2: Single source of scoring logic (done)

- `shared/scoring.js` holds `analyzeURL`, `calculateCombinedScore`, `classify`, trust and brand detection.
- It is loaded by the service worker (`importScripts`), the popup (script tags), the content script (manifest) and Node tests.
- Thresholds, weights, keywords and lists live in `shared/config.json`. `shared/config.js` is generated.
- The content script follows the `statusLevel` decided in the background.
- Not done: the static "(< 30)" and "(60+)" labels on the history and dashboard pages do not follow custom thresholds.

## Phase 3: Reduce false positives (done)

- 1000 trusted domains from Tranco, with shared hosting platforms excluded. Trusted sites are capped at 20.
- Keyword in the hostname scores 10. Keyword only in the path scores 3.
- A same-origin HTTPS login form is not penalised. A same-origin link to an IP address is no longer suspicious.
- User trusted list in `chrome.storage.sync`, with a Trust this site button in the popup and an editor in Settings.
- Python and JavaScript read the same keyword list.
- Not done: the "50 known-good login pages score SAFE" check needs a corpus of real pages. Unit tests cover representative cases only.

## Phase 4: Real dataset and model quality (done, with data limits)

- `ml/build_dataset.py` builds 15,000 phishing URLs (PhishTank) and 15,000 legitimate URLs (Tranco). Sources and date are in `ml/dataset/DATASET-INFO.json`.
- The split is 80/20 grouped by domain. The held-out set has 5,294 URLs.
- Random Forest and Histogram Gradient Boosting are compared with 5-fold grouped cross-validation.
- Reported: accuracy, precision, recall, F1, ROC-AUC, false-positive rate, recall at 1% false-positive rate.
- The backend refuses a model whose feature list does not match `feature_extractor.py`.
- `evaluation_results.json` and `MODEL-EVALUATION-REPORT.md` are regenerated, and the old model is kept for comparison.

| Held-out result | Previous model | Current model |
| :--- | ---: | ---: |
| ROC-AUC | 0.64 | 0.92 |
| False-positive rate | 0.34 | 0.05 |
| Recall | 0.50 | 0.66 |

Limits to keep in mind:

- Legitimate URLs use real domains with synthetic paths, so the model learns mostly host-level and keyword signals.
- An earlier build scored 0.99 AUC only because path length separated the classes. That shortcut was removed on purpose.
- Cross-validation AUC varies by about 0.06 between folds. Treat small differences as noise.
- The full CSV is not committed. Check the PhishTank and Tranco terms before redistributing it.

## Phase 5: Stronger detection signals (partly done)

Done:

- Lookalike detection: brand in unrelated domain, homoglyphs, typo-squats, punycode, abused TLDs, many hyphens.
- Brand-in-page check and external icon check in the content script.
- Optional domain age (RDAP) and TLS certificate check in the backend, cached, off by default, never contacting private hosts. Live-checked on example.com and badssl.com.
- Eight new model features (brand flags, hostname lexical measures, shared hosting flag).

Not done:

- Redirect chain counting.
- Page-content features inside the model. The model sees only the URL.
- A per-signal ablation. The only measured gain is for the host features as a group.
- RDAP returned no age for some domains (github.com in a live test). Missing data adds no points.

## Phase 6: Real blocking warning page (done)

- `warning.html` replaces the tab. It is triggered before load (URL and model) and again after load (all layers).
- Buttons: Go back to safety, Report as safe (adds to the trusted list), Proceed anyway (disabled for 5 seconds).
- Proceed is remembered per site until the browser closes.
- SUSPICIOUS results keep the in-page banner.
- Implemented with `webNavigation` and a tab update, not `declarativeNetRequest`.

## Phase 7: Automated tests (done)

- JavaScript: 23 tests with the built-in Node test runner, including a JavaScript and Python parity test.
- Python: 36 pytest tests for features, the API, dataset splitting, intel safety and config sync.
- Browser: `tests/e2e/smoke.test.js` loads the extension in Chromium and checks TC01 to TC10 and the block, proceed, trust, settings and page-load flows.
- `.github/workflows/ci.yml` runs all three. It has not yet run on GitHub.
- TC01 and TC02 expectations changed to "SAFE or SUSPICIOUS". They are served over HTTP from an IP address, which scores 30 from the URL rules alone.

## Phase 8: Settings, packaging and release (done)

- Options page with switches, thresholds, backend address with test, intelligence switch and trusted-site list.
- Backend address is a setting. `/health` is used for the connection test and the popup shows an offline notice with Retry.
- `Dockerfile`, `start-backend.ps1`, `start-backend.sh`, `.env.example`, `requirements-dev.txt`.
- Permissions: removed `tabs` and `activeTab`, added `webNavigation`.
- `PRIVACY.md`, `CHANGELOG.md`, version 1.1.0.
- Not done: the Docker image was not built here, no git tag or release was created, and the ten-minute install time was not measured.

---

## What to do next

1. Collect real legitimate URLs (browser history exports or a crawl) to replace the synthetic paths, then retrain.
2. Add a second phishing feed (OpenPhish) to reduce single-feed bias.
3. Run CI on GitHub and fix any platform differences.
4. Add redirect-chain checks and a measured ablation for each new signal.
5. Schedule a monthly retrain with `build_dataset.py` and `train_model.py`.
6. Make the history and dashboard labels follow the configured thresholds.

## Risks and notes

- **Dataset licensing.** Check feed terms before bundling data.
- **Privacy.** Domain intelligence sends hostnames outside the machine. It is opt-in on both sides.
- **Model drift.** Phishing patterns change quickly. Retrain on a schedule.
- **Scope.** The tool is advisory and can be wrong in both directions.
