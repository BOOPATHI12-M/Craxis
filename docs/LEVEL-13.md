# Level 13 — Local Security Scan History System

This document details the architecture, storage model, UI components, filtering, privacy safeguards, and test cases for **Level 13 of AI Phishing Guard**.

---

## 🎯 1. Purpose

Level 13 introduces a **Local Security Scan History System** that automatically records recent website security scan results into `chrome.storage.local`. Users can review past scan assessments, filter by classification (`SAFE`, `SUSPICIOUS`, `DANGEROUS`), search scanned domain names, view detailed scan reports, and clear history on demand.

---

## 💾 2. Data Storage Specifications

### Storage API
- **API:** `chrome.storage.local` (Key: `"aiphish_scan_history"`)
- **Capacity Limit:** Maximum **100 entries**. When the limit is exceeded, the oldest entry is automatically removed.
- **Duplicate Prevention:** Automatic scans of the exact same URL within **15 seconds** are deduplicated to prevent uncontrolled storage growth.

### 📋 Data Explicitly Stored
```json
{
  "id": "scan-1771987200000-a1b2c",
  "url": "https://example.com/login",
  "hostname": "example.com",
  "riskScore": 25,
  "classification": "SAFE",
  "timestamp": "2026-08-26T12:30:00.000Z",
  "formattedTime": "26 Aug 2026, 12:30 PM",
  "reasons": [
    "HTTPS connection enabled",
    "Normal domain structure"
  ],
  "aiPrediction": "LEGITIMATE",
  "urlScore": 0,
  "webpageScore": 0,
  "aiScore": 0,
  "scanType": "auto"
}
```

### 🚫 Data EXPLICITLY NOT Stored
- Passwords, passkeys, or authentication secrets
- One-Time Passwords (OTPs) or MFA codes
- Cookies, session tokens, or Authorization headers
- Credit card numbers, CVVs, or payment information
- Form input text or user-typed keystrokes
- Complete HTML page contents or full DOM trees
- Unscanned browsing history

---

## 🖥️ 3. User Interface & Features

1. **Dashboard (`history.html`):**
   - Accessible via the `"🕘 Scan History"` button in `popup.html` or direct tab navigation.
2. **Category Filter Tabs:**
   - `All`: Displays all historical entries.
   - `🟢 Safe`: Displays entries with `riskScore < 30`.
   - `🟠 Suspicious`: Displays entries with `30 <= riskScore < 60`.
   - `🔴 Dangerous`: Displays entries with `riskScore >= 60`.
3. **Live Search:**
   - Real-time text search filtering across domain hostnames and URL strings.
4. **Detailed Scan Modal (`[View Details]`):**
   - Displays full URL, domain hostname, classification, risk score, formatted timestamp, AI prediction, URL score (30%), Page score (20%), AI score (50%), and bulleted detection reasons list.
5. **Clear History (`[Clear History]`):**
   - Triggers confirmation dialog (`"Clear all saved security scan history?"`). Upon confirmation, executes `chrome.storage.local.remove(["aiphish_scan_history"])`.

---

## 🔒 4. Privacy & Security Controls

- **100% Local Storage:** Scan history is stored entirely inside the user's browser sandbox using Chrome Extension local storage.
- **Zero Remote Transmission:** History records are NEVER transmitted to external analytics, cloud services, or remote servers.
- **XSS Safety:** All history data rendered in `history.js` uses safe DOM APIs (`document.createElement()`, `element.textContent`) and string escaping.

---

## 🧪 5. Verification Test Cases

| Test Case | Procedure | Expected Outcome | Status |
| :--- | :--- | :--- | :---: |
| **TEST 1: Safe Scan** | Open `safe-https-test.html` | One `SAFE` entry saved in history | **PASS** |
| **TEST 2: Suspicious Scan** | Open `http-test.html` | One `SUSPICIOUS` entry saved in history | **PASS** |
| **TEST 3: Dangerous Scan** | Open `multiple-indicators-test.html` | One `DANGEROUS` entry saved in history | **PASS** |
| **TEST 4: Deduplication** | Rapidly rescan same URL 5 times | Only 1 entry created within 15s window | **PASS** |
| **TEST 5: Live Search** | Type hostname into search bar | Grid filters to matching entries | **PASS** |
| **TEST 6–8: Filter Tabs** | Click Safe/Suspicious/Dangerous tabs | Only corresponding entries shown | **PASS** |
| **TEST 9: View Details** | Click `[View Details]` on a card | Modal opens with complete report | **PASS** |
| **TEST 10: Clear History** | Click `[Clear History]` and confirm | History storage emptied; empty state shown | **PASS** |

---

## ⚠️ 6. Limitations Disclaimer

Scan history records reflect the security assessment at the specific time the website was scanned. Historical safe entries do not guarantee that a domain will remain untampered with in future visits.
