# Level 14 — Security Intelligence Dashboard

This document details the architecture, data sources, summary metrics, visual representations, privacy controls, and testing procedures for **Level 14 of AI Phishing Guard**.

---

## 🎯 1. Purpose

Level 14 introduces the **Security Intelligence Dashboard** (`dashboard.html`), a central analytics dashboard that aggregates real-time local scan history (`chrome.storage.local`) and machine learning model metrics (`evaluation_results.json`) into high-level security insights.

---

## 📊 2. Data Sources & Architecture

```text
       chrome.storage.local                 evaluation_results.json / Flask API
     ("aiphish_scan_history")                      (/api/model-evaluation)
                │                                            │
                └─────────────────────┬──────────────────────┘
                                      ▼
                           dashboard.js Engine
                                      │
        ┌─────────────────────────────┼─────────────────────────────┐
        ▼                             ▼                             ▼
 Summary Metrics            Risk Distributions              Security Insights
 • Total Scans              • Class Distribution            • Common Indicators
 • Safe / Suspicious / Dang • Score Range Bins              • Top 5 Highest Risk Sites
 • Average Risk Score       • Chronological Trend           • AI Predictions Breakdown
```

---

## 📈 3. Dashboard Analytics & Components

1. **Top Summary Cards:**
   - `Total Scans`: Total number of scanned websites stored in history.
   - `Safe`: Count of scans with `riskScore < 30`.
   - `Suspicious`: Count of scans with `30 <= riskScore < 60`.
   - `Dangerous`: Count of scans with `riskScore >= 60`.
   - `Average Risk`: Mathematical average risk score ($\sum \text{riskScore} / \text{totalScans}$).
2. **Risk Classification Distribution:**
   - Visual percentage bars representing `SAFE`, `SUSPICIOUS`, and `DANGEROUS` proportions.
3. **Risk Score Distribution Bins:**
   - Grouped score ranges: `0–20`, `21–40`, `41–60`, `61–80`, `81–100`.
4. **Chronological Risk Trend:**
   - Visual trend columns for recent scans. Displays *"Not enough scan data to display a trend"* if fewer than 2 scans exist.
5. **Common Detection Indicators:**
   - Normalized frequency ranking of risk reasons recorded across all historical scans (e.g. non-HTTPS, IP hostnames, password fields, external form actions).
6. **AI Prediction Summary:**
   - Counts of `LEGITIMATE`, `PHISHING`, and `UNAVAILABLE` model predictions.
7. **Top 5 Highest Risk Scans:**
   - Top 5 websites sorted by highest risk score descending.
8. **Recent Activity (Latest 5):**
   - Most recent 5 scanned URLs chronologically.
9. **Data Freshness & Status:**
   - Displays actual dashboard update time and timestamp of latest scan recorded.

---

## 🔒 4. Privacy & Security Safeguards

- **100% Local Processing:** Dashboard analytics are computed entirely on the client side using JavaScript.
- **Zero Remote Analytics:** No scan counts, risk scores, or URLs are sent to external analytics or remote servers.
- **XSS Safety:** All data rendered dynamically in `dashboard.js` uses `document.createElement()` and `element.textContent` or escaped strings.

---

## 🧪 5. Verification Test Cases

| Test Case | Description | Expected Outcome | Status |
| :--- | :--- | :--- | :---: |
| **TEST 1: Empty State** | Open dashboard with 0 scans | Empty state banner shown (`🛡️ No security data yet`) | **PASS** |
| **TEST 2: Safe Scan** | Add 1 SAFE scan | Total=1, Safe=1, Suspicious=0, Dangerous=0 | **PASS** |
| **TEST 3: Suspicious Scan** | Add 1 SUSPICIOUS scan | Counts update accurately | **PASS** |
| **TEST 4: Dangerous Scan** | Add 1 DANGEROUS scan | Counts update accurately | **PASS** |
| **TEST 5: Avg Risk Math** | Compute average across multiple scans | Mathematically exact average risk score | **PASS** |
| **TEST 6: Risk Bins** | Verify 0-20 to 81-100 ranges | Scans accurately categorized into bins | **PASS** |
| **TEST 7: Detection Indicators**| Verify indicator frequencies | Counts match stored reasons | **PASS** |
| **TEST 8: Highest Risk Sites** | Verify top risk list | Highest risk scores sorted first | **PASS** |
| **TEST 9: Recent Activity** | Verify recent scan list | Newest scans appear at top | **PASS** |
| **TEST 10: Clear History** | Clear Level 13 scan history | Dashboard dynamically reverts to empty state | **PASS** |
| **TEST 11: ML Evaluation** | Open ML Evaluation link | Level 11 dashboard opens cleanly | **PASS** |
| **TEST 12: Scan History** | Open Scan History link | Level 13 dashboard opens cleanly | **PASS** |

---

## ⚠️ 6. Limitations Disclaimer

The Security Intelligence Dashboard presents aggregated statistical summaries based on local scan history. It provides neutral security insights and does not claim absolute security guarantees.
