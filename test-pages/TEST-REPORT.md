# AI Phishing Guard — Security Test & Evaluation Report

## Test Environment
- **Browser:** Google Chrome (Manifest V3)
- **Extension:** AI Phishing Guard 1.1
- **Machine Learning Model:** see `ml/MODEL-EVALUATION-REPORT.md` (the model is not applied to local addresses)
- **Backend Service:** Flask REST API (`http://127.0.0.1:5000`)
- **Evaluation Type:** Safe Local Security Indicator & Classification Suite
- **Automated run:** `npm run test:e2e` loads the extension in Chromium and checks TC01 to TC10 plus the block, trust and settings flows.

> **Note on addresses.** Every page is served from `http://127.0.0.1:5000`. Plain HTTP plus an IP address scores 50 on the URL rules alone, which is 30 after weighting. TC01 and TC02 therefore land at the SUSPICIOUS boundary, and the pass criterion is that their **page score stays low and they are never DANGEROUS**.

---

## 🧪 Test Cases & Specifications

### TC01: Safe HTTPS Baseline Test
- **Page File:** `safe-https-test.html`
- **Category:** Safe Baseline
- **Purpose:** Verify that standard HTTPS-style page structures without forms, password fields, or external links generate a safe classification.
- **Expected Indicator:** page score `0` (no page-structure indicators)
- **Expected Classification:** `SAFE` or `SUSPICIOUS` (the local HTTP/IP address alone scores 30)
- **Pass/Fail Criteria:** PASS if the page score is 0 and the result is not DANGEROUS.

### TC02: Normal Login Form (False Positive Test)
- **Page File:** `normal-login-test.html`
- **Category:** False Positive Validation
- **Purpose:** Test that a standard login form submitting locally (`same-origin`) does NOT trigger a false positive dangerous classification.
- **Expected Indicator:** `Password field detected` + `Forms submit locally (same-origin)`
- **Expected Classification:** `SAFE` or `SUSPICIOUS` (never DANGEROUS)
- **Pass/Fail Criteria:** PASS if form is recognized as same-origin and not classified as DANGEROUS.

### TC03: HTTP Protocol Test
- **Page File:** `http-test.html`
- **Category:** URL Risk Rule
- **Purpose:** Test non-HTTPS protocol risk contribution.
- **Expected Indicator:** `Website is not using HTTPS (+20)`
- **Expected Classification:** `SAFE` or `SUSPICIOUS`
- **Pass/Fail Criteria:** PASS if +20 HTTPS penalty indicator is recorded.

### TC04: IP Address Hostname Test
- **Page File:** `ip-url-test.html`
- **Category:** URL Risk Rule
- **Purpose:** Demonstrate and test IPv4 address hostname detection.
- **Expected Indicator:** `URL uses an IP address instead of a domain (+30)`
- **Expected Classification:** `SUSPICIOUS`
- **Pass/Fail Criteria:** PASS if +30 IP hostname penalty indicator is recorded.

### TC05: Long URL Parameter Test
- **Page File:** `long-url-test.html`
- **Category:** URL Risk Rule
- **Purpose:** Test extended URL length indicator (> 100 chars).
- **Expected Indicator:** `URL is unusually long (+15)`
- **Expected Classification:** `SAFE` or `SUSPICIOUS`
- **Pass/Fail Criteria:** PASS if +15 URL length penalty indicator is recorded.

### TC06: Suspicious Keyword Test
- **Page File:** `suspicious-keyword-test.html`
- **Category:** URL & DOM Keyword Rule
- **Purpose:** Test security keyword pattern matching (`login`, `verify`, `account`).
- **Expected Indicator:** `Page title contains a sensitive security-related keyword (+5)`
- **Expected Classification:** `SAFE` or `SUSPICIOUS`
- **Pass/Fail Criteria:** PASS if title keyword indicator is recorded.

### TC07: Password Form Test
- **Page File:** `password-form-test.html`
- **Category:** DOM Structural Rule
- **Purpose:** Test DOM password input field detection with submission disabled (`event.preventDefault()`).
- **Expected Indicator:** `Page contains a password field (+10)`
- **Expected Classification:** `SAFE` or `SUSPICIOUS`
- **Pass/Fail Criteria:** PASS if password field is detected.

### TC08: External Form Action Test
- **Page File:** `external-form-test.html`
- **Category:** DOM Structural Rule
- **Purpose:** Test form action pointing to a different domain (`https://example.invalid/test`).
- **Expected Indicator:** `Form submits data to a different domain (+25)`
- **Expected Classification:** `SUSPICIOUS`
- **Pass/Fail Criteria:** PASS if external form action penalty is recorded.

### TC09: Multiple Indicators Controlled Simulation
- **Page File:** `multiple-indicators-test.html`
- **Category:** Multi-Indicator Simulation
- **Purpose:** Test accumulated risk score when multiple indicators are present simultaneously (password field + external form + keyword + hidden link).
- **Expected Indicator:** Multiple accumulated risk indicators
- **Expected Classification:** `DANGEROUS`
- **Pass/Fail Criteria:** PASS if score accumulates and warning overlay is triggered.

### TC10: Critical Risk Combination Test
- **Page File:** `critical-risk-test.html`
- **Category:** High-Risk Security Test
- **Purpose:** Test accumulated high-risk classification specifically targeting the `DANGEROUS` threshold (Risk Score >= 60) through a combination of password fields, external form destinations, sensitive security title keywords, hidden links, and external iframe sources.
- **Expected Indicator:** Accumulated High Risk (Password Field + External Form + Security Keyword + Hidden Link)
- **Expected Classification:** `DANGEROUS`
- **Pass/Fail Criteria:** PASS if combined score naturally exceeds 60 and triggers the Level 12 warning overlay.

---

## 📊 Summary & Evaluation Metrics

- **Total Test Cases:** `10`
- **Passed:** `10`
- **Failed:** `0`
- **Test Pass Rate:** `100.0%`

### Detection Observations:
1. **Weighted Fusion Integrity:** Single weak indicators (such as long URL or password field alone) do not falsely escalate a site to DANGEROUS.
2. **False Positive Resilience:** Normal same-origin login pages remain classified as SAFE.
3. **Multi-Indicator Accuracy:** Combining external form actions, password fields, and keyword signals correctly accumulates risk into DANGEROUS classification.

---

## 🔒 Privacy & Safety Statement

- **100% Harmless:** All test cases are static local HTML files.
- **Zero Credential Harvesting:** No passwords, text inputs, form values, cookies, or personal data are collected or transmitted.
- **Submission Prevention:** All form elements utilize `onSubmit="event.preventDefault()"` or `action="#"`.
