# 🛡️ AI Phishing Guard

**AI Phishing Guard** is a Manifest V3 Chrome extension that scores every web page you open for phishing risk. It combines URL rules, page-structure checks and a machine learning model served by a small local Flask API, then explains the result and can block dangerous pages.

---

## ✨ Features

- **Automatic scanning:** each http/https page is scanned when it finishes loading.
- **Three detection layers:** URL rules, page (DOM) structure, and a Random Forest or Gradient Boosting model.
- **Lookalike detection:** brand names in unrelated domains, homoglyphs such as `paypa1`, typo-squats, punycode, abused TLDs.
- **Explainable report:** the popup shows every rule that fired, each layer's score and how they were combined.
- **Blocking warning page:** DANGEROUS sites are replaced by a warning page with *Go back to safety*, *Report as safe* and a delayed *Proceed anyway*.
- **Trusted sites:** a built-in list of 1000 trusted domains plus your own list. Trusted sites are never blocked.
- **History and dashboard:** the last 100 scans with search, filters and charts.
- **Settings:** switches, risk thresholds, backend address, optional domain intelligence.
- **Local and private:** page analysis runs in your browser. See [PRIVACY.md](PRIVACY.md).

---

## 🏗️ How it works

```text
Tab navigation ──► background.js (service worker)
                      │
        ┌─────────────┼───────────────────┐
        ▼             ▼                   ▼
  URL rules      content.js          Flask API
 (scoring.js)   page structure     /predict (model)
        └─────────────┼───────────────────┘
                      ▼
          Weighted fusion  (shared/scoring.js)
   30% URL + 20% page + 50% AI  (weights adapt when a layer is missing)
                      ▼
        SAFE / SUSPICIOUS / DANGEROUS
          │              │             │
     green badge   yellow banner   warning page
```

| File | Role |
| :--- | :--- |
| `manifest.json` | Extension configuration and permissions |
| `background.js` | Navigation scanning, blocking, tab state, history |
| `content.js` | Page analysis and the in-page badge or banner |
| `shared/config.json` | Single source of rules, keywords, brands, thresholds, trusted domains |
| `shared/scoring.js` | URL rules, brand detection, score fusion, classification |
| `shared/settings.js`, `shared/api.js` | Settings storage and backend client |
| `popup.*`, `options.*`, `warning.*`, `history.*`, `dashboard.*` | User interface pages |
| `ml/` | Flask API, feature extractor, dataset builder, training and evaluation |
| `test-pages/` | Ten harmless local pages (TC01 to TC10) |
| `tests/`, `ml/tests/` | Automated tests |

### Score fusion and classes

| Signals available | URL | Page | AI |
| :--- | :---: | :---: | :---: |
| All three | 30% | 20% | 50% |
| URL + AI | 35% | n/a | 65% |
| URL + page | 60% | 40% | n/a |
| URL only | 100% | n/a | n/a |

| Score (defaults) | Class | What you see |
| :---: | :--- | :--- |
| 0 to 29 | SAFE | Small badge, bottom right |
| 30 to 59 | SUSPICIOUS | Banner at the top with reasons |
| 60 to 100 | DANGEROUS | Blocking warning page (or a banner if blocking is off) |

Two extra rules apply. When every available layer scores 50 or more, the result is raised to at least the DANGEROUS threshold. Trusted sites are capped at 20.

The AI model is **not** applied to `localhost` and private network addresses, because it is trained on public web URLs.

---

## 🚀 Setup

### 1. Start the backend

```bash
pip install -r requirements.txt
python ml/app.py
```

or use `start-backend.ps1` (Windows), `./start-backend.sh` (macOS or Linux), or Docker:

```bash
docker build -t ai-phishing-guard .
docker run --rm -p 127.0.0.1:5000:5000 ai-phishing-guard
```

The API listens on `http://127.0.0.1:5000`. The extension still works without it, using URL and page checks only.

### 2. Load the extension

1. Open `chrome://extensions` and turn on **Developer mode**.
2. Click **Load unpacked** and choose this folder.
3. Pin **AI Phishing Guard**. After code changes press the reload icon on the extension card.

### 3. Try the test pages

Open `http://127.0.0.1:5000/test-pages/index.html` and launch TC01 to TC10. TC09 and TC10 are blocked by the warning page.

---

## ⚙️ Settings

Open the popup and click **Settings**, or use the extension's options page.

| Setting | Default | Meaning |
| :--- | :--- | :--- |
| Scan pages automatically | on | Scan every page after it loads |
| Block dangerous pages | on | Show the warning page for DANGEROUS results |
| Suspicious / dangerous thresholds | 30 / 60 | Score cut-offs |
| Backend address | `http://127.0.0.1:5000` | Where the model API runs |
| Domain age and certificate lookup | off | Needs `AIPHISH_ENABLE_INTEL=1` on the backend. Sends the hostname to public registries |
| Trusted sites | empty | Never blocked, score capped |

---

## 🤖 Model

The model is trained on real data built by `ml/build_dataset.py`:

- **Phishing:** verified, online URLs from the PhishTank feed.
- **Legitimate:** domains from the Tranco top-sites ranking, with synthetic paths.

```bash
python ml/build_dataset.py      # downloads both feeds, writes ml/dataset/phishing_urls_full.csv
python ml/train_model.py        # cross-validates, trains, evaluates, saves the model
```

Evaluation uses a 20% split **grouped by domain**, so no site appears in both sets. Current held-out results are in [ml/MODEL-EVALUATION-REPORT.md](ml/MODEL-EVALUATION-REPORT.md).

> **Limitations.** The legitimate class uses real domains but synthetic paths, and phishing comes from one feed. Expect roughly a 5% false-positive rate on unknown sites and about two thirds of phishing URLs caught from the URL alone. The final decision combines this with the URL rules and page checks, and one layer alone cannot block a page. Retrain on fresh data regularly.

---

## 🧪 Testing

```bash
pip install -r requirements-dev.txt
npm install
python -m pytest ml/tests            # Python unit and API tests
npm test                             # JavaScript unit and parity tests
npx playwright install chromium
npm run test:e2e                     # loads the extension, checks TC01 to TC10 and the block/trust/settings flows
```

CI runs the same steps in `.github/workflows/ci.yml`.

---

## 🔒 Privacy

Passwords, form values and cookies are never read. Page URLs go only to the backend you configure, which is on your own machine by default. Details and permission reasons are in [PRIVACY.md](PRIVACY.md).

---

## 📂 More documentation

- [extension.md](extension.md): code walkthrough
- [improve.md](improve.md): improvement roadmap and status
- [CHANGELOG.md](CHANGELOG.md)
- [ml/README.md](ml/README.md): backend and model details
- [test-pages/README.md](test-pages/README.md): local test suite
