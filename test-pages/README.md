# Craxis — Local Security Test & Evaluation Suite

This directory contains the **Safe Local Security Test & Evaluation System** for the Craxis Chrome Extension.

---

## 📂 Directory Structure

```text
test-pages/
├── index.html                  # Main Local Test Center Dashboard
├── evaluation.html             # Developer Evaluation Dashboard & Pass Rate Tracker
├── test-config.js              # Metadata definitions for all 10 test cases
├── safe-https-test.html        # TC01: Safe HTTPS Baseline Test
├── normal-login-test.html      # TC02: Normal Login Form (False Positive Validation)
├── http-test.html              # TC03: Non-HTTPS Protocol Test
├── ip-url-test.html            # TC04: IP Address Hostname Test
├── long-url-test.html          # TC05: Long URL Parameter Test
├── suspicious-keyword-test.html# TC06: Security Keyword Test
├── password-form-test.html     # TC07: Password Field Form Test
├── external-form-test.html     # TC08: External Domain Form Action Test
├── multiple-indicators-test.html# TC09: Multi-Indicator Controlled Simulation
├── permission-request-test.html # TC11: Camera requested on a sign-in page (browser shows its own prompt: choose Block)
├── critical-risk-test.html     # TC10: Critical Risk Combination Test (Dangerous)
└── README.md                   # Module Overview & Documentation
```

---

## 🚀 How to Run the Test Suite

1. **Start the Flask REST API Backend:**
   ```bash
   python ml/app.py
   ```
2. **Reload Extension in Chrome:**
   - Open `chrome://extensions` and click **Reload (↻)** on Craxis.
3. **Launch Test Center:**
   - Open `http://127.0.0.1:5000/test-pages/index.html` in Google Chrome.
4. **Execute & Record Test Cases:**
   - Click **Launch Test Page** on any card (e.g. `TC01` to `TC10`).
   - Open the extension popup or observe automatic background scanning.
   - Open `test-pages/evaluation.html` to log actual scores and mark **PASS / FAIL**.

5. **Or run the automated check** (loads the extension in Chromium):
   ```bash
   npm install && npx playwright install chromium
   npm run test:e2e
   ```

> TC09 and TC10 are expected to be **blocked** by the warning page. Use *Proceed anyway* on the warning page to view them, or turn blocking off in the extension settings.

---

## 🔒 Safety & Privacy Guarantee

- **100% Local & Harmless:** No external network requests or malicious code.
- **Zero Credential Collection:** Forms do not collect, store, or transmit passwords or user inputs.
- **Submission Prevention:** All forms use `onSubmit="event.preventDefault()"` or `action="#"`.
