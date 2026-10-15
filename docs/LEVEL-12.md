# Level 12 — Real-Time Phishing Warning System

This document outlines the architecture, detection flow, warning levels, user actions, privacy controls, and error handling for **Level 12 of AI Phishing Guard**.

---

## 🎯 1. Purpose

The Level 12 **Real-Time Phishing Warning System** automatically evaluates active browser tabs upon navigation and presents dynamic, non-destructive security indicators, banners, and overlays based on the calculated combined risk score.

---

## 🛡️ 2. Warning Levels & UI Behavior

Risk scores are computed using the established Level 9 score fusion model:
$$\text{Final Risk Score} = \text{Math.round}((\text{URL Score} \times 0.30) + (\text{Page Score} \times 0.20) + (\text{AI Risk Score} \times 0.50))$$

| Classification | Score Threshold | Overlay / Banner UI | Action Buttons |
| :--- | :---: | :--- | :--- |
| **SAFE** | `< 30` | Small non-intrusive floating badge in bottom-right corner (`🛡️ SAFE (Score/100)`). Automatically fades to subtle transparency after 6 seconds. | Click badge to view status |
| **SUSPICIOUS** | `30 – 59` | Non-destructive top warning banner (`⚠️ SUSPICIOUS WEBSITE`). Displays risk score and top risk reasons. | `[View Security Details]`, `[Continue Anyway]` |
| **DANGEROUS** | `>= 60` | High-visibility warning overlay (`🛑 HIGH-RISK WEBSITE`). Displays risk score, reasons, and warning recommendation text. | `[Go Back]`, `[View Security Details]`, `[Continue Anyway]` |

---

## 🔄 3. Detection Flow Architecture

```text
               PAGE NAVIGATION
                     │
                     ▼
       background.js Service Worker
         (chrome.tabs.onUpdated)
                     │
                     ▼
          Automatic Scan Engine
                     │
     ┌───────────────┼───────────────┐
     ▼               ▼               ▼
URL Rule Engine  Content Script   Flask REST API (http://127.0.0.1:5000)
(analyzeURL)     DOM Metrics      Random Forest Model (Version 2.0)
     │               │               │
     └───────────────┼───────────────┘
                     ▼
          Weighted Score Fusion (30% URL + 20% Page + 50% AI)
                     │
                     ▼
             Final Risk Score & Classification
                     │
     ┌───────────────┼───────────────┐
     ▼               ▼               ▼
   SAFE         SUSPICIOUS       DANGEROUS
  (< 30)         (30 – 59)        (>= 60)
    │               │                │
Safe Badge      Top Banner     Warning Overlay
                [Dismiss]     [Go Back] [Continue]
```

---

## 🖐️ 4. User Actions

1. **Go Back:**
   - Available on **DANGEROUS** warnings. Executes `window.history.back()` safely to return the user to their previous web page without closing the tab or browser.
2. **View Security Details:**
   - Guides the user to click the extension toolbar icon to view the full Level 7/9 explainable security report (including score breakdowns, metrics, and feature importances).
3. **Continue Anyway / Dismiss:**
   - Dismisses the warning banner or overlay for the active page session.
   - Stores `sessionStorage.setItem("aiphish_dismissed_" + location.href, "true")` so the warning does NOT continuously re-appear on dynamic DOM mutations during the current page visit.

---

## 🔒 5. Privacy & Security Safeguards

- **Zero Credential Collection:** Does NOT collect, store, or transmit passwords, OTPs, payment information, cookies, keystrokes, or personal identity data.
- **Local DOM Execution:** Page structural inspection occurs entirely within `content.js`.
- **No Impersonation:** Warnings are clearly branded as **AI Phishing Guard** and do not imitate native browser internal alerts.
- **XSS Safety:** All banner and overlay strings are rendered using `document.createElement()` and `element.textContent`.

---

## 🛠️ 6. Error Handling & Offline Fallback

- **Flask API Offline:** If `http://127.0.0.1:5000` is offline or times out, the scanner falls back to local URL and DOM rules ($60\%\text{ URL} + 40\%\text{ Webpage}$). The website is NOT classified as dangerous solely because Flask is offline.
- **Chrome Internal Pages (`chrome://extensions`):** Automatic scanning and warning overlays are disabled on restricted browser pages, displaying `Status: Not available for this page` in the popup.

---

## 🧪 7. Local Testing

Level 12 warning UI behavior can be safely verified using the Level 10 Local Test Suite (`test-pages/index.html`):
- `TC01 (Safe Baseline)` $\rightarrow$ Renders small **SAFE** badge.
- `TC03 (HTTP Test)` / `TC08 (External Form)` $\rightarrow$ Renders **SUSPICIOUS** banner.
- `TC09 (Multi-Indicator Simulation)` $\rightarrow$ Renders **DANGEROUS** overlay with **Go Back**, **View Security Details**, and **Continue Anyway** buttons.

---

## ⚠️ 8. Limitations Disclaimer

The Level 12 warning system is an **advisory risk-analysis tool**. It evaluates structural indicators and machine learning probabilities to inform users of potential threats. It does not replace user vigilance when submitting sensitive credentials online.
