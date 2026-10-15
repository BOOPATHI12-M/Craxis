# Changelog

## 1.1.0 - 2026-10-15

### Added
- Unexpected permission requests: pages that ask for the camera, microphone, screen, location or clipboard without any user action (+20), login pages that ask at all (+10), notifications on load (+10), and cross-domain frames allowed to use the camera or microphone (+10). A rescan runs when a request happens after the first scan. New test page TC11.
- "View details" on the in-page banner now opens the scan's detail view in a new tab instead of showing an alert.
- Dashboard separates "not applied (local address)" from "backend unavailable" and history shows the reason.
- Blocking warning page for DANGEROUS sites, with Go back, Report as safe and a delayed Proceed anyway.
- Settings page: scan and block switches, risk thresholds, backend address, optional domain intelligence and a trusted-site list.
- "Trust this site" button in the popup and a built-in list of 1000 trusted domains (shared hosting platforms excluded).
- Lookalike detection: brand name in an unrelated domain, homoglyph and typo-squatted brand names, punycode, frequently abused TLDs, many hyphens.
- Page checks for a brand shown on an unrelated domain and an icon loaded from another domain.
- Optional domain age (RDAP) and TLS certificate checks in the backend, off by default.
- `/health` endpoint and an "AI server offline" notice with a Retry button.
- Real training pipeline: `ml/build_dataset.py`, domain-grouped splits and cross-validated model selection.
- Unit tests (JavaScript and Python), a JavaScript and Python parity test and a browser smoke test for TC01 to TC10.
- Dockerfile, start scripts, GitHub Actions workflow, privacy policy.

### Changed
- All scoring logic now lives in `shared/scoring.js` and is used by the background worker, popup and content script.
- Keywords, shorteners, brands and TLD lists come from one file, `shared/config.json`, shared with the Python model.
- Keyword in the hostname scores 10 and keyword only in the path scores 3.
- A password field is only a risk signal on HTTP pages, pages without a form, or forms that post to another domain.
- Same-origin links to an IP address are no longer counted as suspicious.
- Classification now uses the thresholds from Settings.
- When all available layers report elevated risk the score is raised to at least the DANGEROUS threshold.
- The AI model is not applied to localhost and private network addresses.
- Model version 3.0 with 32 features. The backend refuses a model whose feature list does not match.
- CORS on the backend is limited to extension and local origins.
- Permissions: removed `tabs` and `activeTab`, added `webNavigation`.
- TC01 and TC02 expectations are now "SAFE or SUSPICIOUS" because they are served over HTTP from an IP address.

### Fixed
- Warning banner and popup no longer build HTML from page-derived text.
- Tab scan state survives service worker restarts.
- Model version labels were inconsistent between files.
- README described a full-screen overlay; the warning is a banner and, when blocking, a full page.

### Removed
- The 20-row example dataset is no longer used for training when the full dataset exists. The previous model is kept as `phishing_model_v2_legacy.pkl` for comparison.

## 1.0.0

Initial release: URL rules, DOM analysis, Random Forest model, history and dashboard.
