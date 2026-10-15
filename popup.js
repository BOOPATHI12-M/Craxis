// popup.js - Craxis explainable security report (v1.1)
// Uses shared/scoring.js, shared/settings.js and shared/api.js for all scoring
// logic so the popup always agrees with the background scanner.

const Scoring = self.AIPhishScoring;
const SettingsStore = self.AIPhishSettings;
const BackendApi = self.AIPhishApi;

// Loaded once when the popup opens.
let popupSettings = SettingsStore.normalize(null);

/**
 * Validates if a URL is a scannable HTTP or HTTPS webpage.
 * Rejects chrome://, chrome-extension://, edge://, about:, file://, devtools://, etc.
 * @param {string} url
 * @returns {boolean}
 */
function isScannableUrl(url) {
  return typeof url === "string" && (url.startsWith("http://") || url.startsWith("https://"));
}

document.addEventListener("DOMContentLoaded", async () => {
  const scanBtn = document.getElementById("scanBtn");
  const autoScanStateText = document.getElementById("autoScanStateText");

  if (!scanBtn) {
    console.error("Scan button not found.");
    return;
  }

  popupSettings = await SettingsStore.load();

  const historyBtn = document.getElementById("historyBtn");
  if (historyBtn) {
    historyBtn.addEventListener("click", () => {
      chrome.tabs.create({ url: "history.html" });
    });
  }

  const dashboardBtn = document.getElementById("dashboardBtn");
  if (dashboardBtn) {
    dashboardBtn.addEventListener("click", () => {
      chrome.tabs.create({ url: "dashboard.html" });
    });
  }

  const optionsBtn = document.getElementById("optionsBtn");
  if (optionsBtn) {
    optionsBtn.addEventListener("click", () => chrome.runtime.openOptionsPage());
  }

  // Fetch model metadata on popup load if available
  fetchModelInfo();

  try {
    const activeTab = await getCurrentTab();
    setupTrustButton(activeTab);
    setupRetryButton();

    if (!activeTab || !activeTab.url || !isScannableUrl(activeTab.url)) {
      displayRestrictedState("Automatic scanning is unavailable on browser internal pages.");
      return;
    }

    // Query background service worker for tab-isolated scan state
    chrome.runtime.sendMessage(
      { action: "GET_TAB_SCAN", tabId: activeTab.id },
      async (response) => {
        try {
          const scan = (response && response.success) ? response.scan : null;

          if (scan && scan.url === activeTab.url) {
            if (scan.status === "completed" && scan.result) {
              const typeLabel = scan.type === "manual" ? "(Manual)" : "(Auto-Scanned)";
              if (autoScanStateText) autoScanStateText.textContent = `Status: Completed ${typeLabel}`;
              displayCombinedResultFromObj(scan.result);
            } else if (scan.status === "scanning") {
              if (autoScanStateText) autoScanStateText.textContent = "Status: Scanning...";
              updateProgressText("Scan in progress on active tab...");
            } else if (scan.status === "failed") {
              if (autoScanStateText) autoScanStateText.textContent = "Status: Scan Failed";
              displayFailedState(scan.error || "Scan failed for current page.");
            } else if (scan.status === "unavailable") {
              displayRestrictedState("Automatic scanning is unavailable on browser internal pages.");
            } else {
              if (autoScanStateText) autoScanStateText.textContent = "Status: Not scanned yet";
            }
          } else {
            if (autoScanStateText) autoScanStateText.textContent = "Status: Scanning...";
            await runScanForTab(activeTab, false);
          }
        } catch (innerErr) {
          console.error("Error processing stored tab scan:", innerErr);
          await runScanForTab(activeTab, false);
        }
      }
    );
  } catch (initErr) {
    console.error("Popup Initialization Error:", initErr);
    displayRestrictedState("Error loading active tab information.");
  }

  // Handle manual "Scan Website" button click with defensive error handling
  scanBtn.addEventListener("click", async () => {
    const tab = await getCurrentTab();
    if (!tab || !tab.url || !isScannableUrl(tab.url)) {
      displayRestrictedState("Automatic scanning is unavailable on browser internal pages.");
      return;
    }

    scanBtn.disabled = true;
    if (autoScanStateText) autoScanStateText.textContent = "Status: Rescanning...";

    try {
      await runScanForTab(tab, true);
    } catch (clickErr) {
      console.error("Scan Button Click Handler Error:", clickErr);
      displayFailedState("An error occurred during manual scan.");
    } finally {
      scanBtn.disabled = false;
    }
  });
});

/**
 * Runs full Level 9 security scan pipeline for a tab and saves result to background service worker.
 */
async function runScanForTab(tab, isManual = false) {
  if (!tab || !tab.url || !isScannableUrl(tab.url)) {
    displayRestrictedState("Automatic scanning is unavailable on browser internal pages.");
    return;
  }

  const url = tab.url;

  try {
    popupSettings = await SettingsStore.load();
    const trust = Scoring.trustStatus(url, popupSettings.userAllowlist);

    updateProgressText("Checking URL security rules...");
    let urlResult = Scoring.analyzeURL(url);

    updateProgressText("Analyzing webpage DOM structure...");
    const pageResult = await requestPageAnalysis(tab);

    updateProgressText("Consulting the Random Forest AI model...");
    let isLocal = false;
    try {
      isLocal = Scoring.isLocalHost(new URL(url).hostname);
    } catch (e) {
      isLocal = false;
    }
    const aiResult = isLocal ? null : await BackendApi.predict(url, popupSettings, 3500);
    if (aiResult && aiResult.intel) urlResult = Scoring.applyIntel(urlResult, aiResult.intel);

    updateProgressText("Generating explainable security report...");
    const combinedResult = Scoring.calculateCombinedScore(url, urlResult, pageResult, aiResult, {
      thresholds: SettingsStore.thresholds(popupSettings),
      trust,
      aiSkipped: isLocal
    });

    // Save result to background.js in-memory store
    chrome.runtime.sendMessage({
      action: "STORE_MANUAL_SCAN",
      tabId: tab.id,
      url: url,
      result: combinedResult
    }).catch(() => {});

    const autoScanStateText = document.getElementById("autoScanStateText");
    if (autoScanStateText) {
      autoScanStateText.textContent = isManual ? "Status: Completed (Manual)" : "Status: Completed (Auto)";
    }

    displayCombinedResultFromObj(combinedResult);
  } catch (error) {
    console.error("Scan Execution Error:", error);
    displayFailedState("An error occurred during website analysis.");
  }
}

/**
 * Retrieves active tab in the focused window using Chrome Tabs API.
 */
function getCurrentTab() {
  return new Promise((resolve) => {
    try {
      chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        if (tabs && tabs.length > 0) {
          resolve(tabs[0]);
        } else {
          resolve(null);
        }
      });
    } catch (e) {
      resolve(null);
    }
  });
}

/**
 * Sends a message to content.js on the active tab requesting DOM structural analysis.
 */
function requestPageAnalysis(tab) {
  return new Promise((resolve) => {
    if (!tab || !tab.id) {
      resolve(null);
      return;
    }

    chrome.tabs.sendMessage(tab.id, { action: "ANALYZE_PAGE" }, (response) => {
      if (chrome.runtime.lastError || !response || !response.success) {
        chrome.scripting.executeScript(
          { target: { tabId: tab.id }, files: ["shared/config.js", "shared/scoring.js", "content.js"] },
          () => {
            if (chrome.runtime.lastError) {
              resolve(null);
              return;
            }
            chrome.tabs.sendMessage(tab.id, { action: "ANALYZE_PAGE" }, (retryResponse) => {
              if (chrome.runtime.lastError || !retryResponse || !retryResponse.success) {
                resolve(null);
              } else {
                resolve(retryResponse.data);
              }
            });
          }
        );
      } else {
        resolve(response.data);
      }
    });
  });
}

/**
 * Fetches model metadata (top features) from the backend and renders it safely.
 */
async function fetchModelInfo() {
  const topFeaturesList = document.getElementById("topFeaturesList");
  if (!topFeaturesList) return;
  const data = await BackendApi.modelInfo(popupSettings);

  topFeaturesList.textContent = "";
  if (data && Array.isArray(data.top_features)) {
    data.top_features.forEach((feat, idx) => {
      const li = document.createElement("li");
      const label = document.createElement("span");
      label.textContent = `${idx + 1}. ${feat.name}`;
      const pct = document.createElement("strong");
      pct.textContent = `${((feat.importance || 0) * 100).toFixed(1)}%`;
      li.appendChild(label);
      li.appendChild(pct);
      topFeaturesList.appendChild(li);
    });
    const modelVersionText = document.getElementById("modelVersionText");
    if (modelVersionText && data.version) modelVersionText.textContent = data.version;
    const infoVersion = document.getElementById("modelInfoVersion");
    if (infoVersion) infoVersion.textContent = data.version || "-";
    const infoFeatures = document.getElementById("modelInfoFeatures");
    if (infoFeatures) infoFeatures.textContent = `${data.feature_count || "-"} features`;
  } else {
    const li = document.createElement("li");
    li.className = "no-reasons";
    li.textContent = "AI server offline. Top model features unavailable.";
    topFeaturesList.appendChild(li);
  }
}

/**
 * Trust / untrust button for the current site.
 */
function setupTrustButton(tab) {
  const btn = document.getElementById("trustBtn");
  if (!btn) return;
  let host = "";
  try {
    host = new URL(tab && tab.url ? tab.url : "").hostname.toLowerCase();
  } catch (e) {
    host = "";
  }
  if (!host || !tab || !isScannableUrl(tab.url)) {
    btn.disabled = true;
    return;
  }

  const labelEl = btn.querySelector("span") || btn;
  const refreshLabel = () => {
    const trusted = Scoring.trustStatus(tab.url, popupSettings.userAllowlist);
    if (trusted.source === "user") {
      labelEl.textContent = "Remove trust";
      btn.dataset.mode = "untrust";
    } else {
      labelEl.textContent = "Trust site";
      btn.dataset.mode = "trust";
    }
  };
  refreshLabel();

  btn.addEventListener("click", async () => {
    btn.disabled = true;
    const action = btn.dataset.mode === "untrust" ? "UNTRUST_SITE" : "TRUST_SITE";
    await new Promise((resolve) => chrome.runtime.sendMessage({ action, host }, resolve));
    popupSettings = await SettingsStore.load();
    refreshLabel();
    btn.disabled = false;
    await runScanForTab(tab, true);
  });
}

/**
 * Retry button shown when the AI backend is offline.
 */
function setupRetryButton() {
  const btn = document.getElementById("retryAiBtn");
  if (!btn) return;
  btn.addEventListener("click", async () => {
    btn.disabled = true;
    const tab = await getCurrentTab();
    await runScanForTab(tab, true);
    btn.disabled = false;
  });
}

function setAiOfflineNote(visible) {
  const note = document.getElementById("aiOfflineNote");
  const text = document.getElementById("aiOfflineText");
  if (!note) return;
  note.hidden = !visible;
  if (visible && text) {
    text.textContent = `AI server not reachable at ${BackendApi.baseUrl(popupSettings)}. Using URL and page checks only.`;
  }
}

/**
 * Updates UI progress message during manual scanning.
 */
function updateProgressText(msg) {
  const statusBadge = document.getElementById("statusBadge");
  const recommendationText = document.getElementById("recommendationText");

  if (statusBadge) {
    statusBadge.textContent = "Scanning...";
    statusBadge.className = "status-badge status-default";
  }
  if (recommendationText) {
    recommendationText.textContent = msg;
  }
}

/**
 * Renders the combined result object into popup UI safely with Level 9 details.
 */
function displayCombinedResultFromObj(res) {
  if (!res) {
    displayRestrictedState("No analysis data available.");
    return;
  }

  const urlText = document.getElementById("urlText");
  const statusBadge = document.getElementById("statusBadge");
  const recommendationBox = document.getElementById("recommendationBox");
  const recommendationText = document.getElementById("recommendationText");
  const summaryChecklist = document.getElementById("summaryChecklist");

  const urlScoreText = document.getElementById("urlScoreText");
  const webpageScoreText = document.getElementById("webpageScoreText");
  const aiRiskScoreBreakdownText = document.getElementById("aiRiskScoreBreakdownText");
  const finalScoreText = document.getElementById("finalScoreText");

  const urlCalcText = document.getElementById("urlCalcText");
  const webpageCalcText = document.getElementById("webpageCalcText");
  const aiCalcText = document.getElementById("aiCalcText");
  const finalCalcText = document.getElementById("finalCalcText");

  const urlReasonsList = document.getElementById("urlReasonsList");
  const webpageReasonsList = document.getElementById("webpageReasonsList");

  const pageTitleText = document.getElementById("pageTitleText");
  const passwordFieldsText = document.getElementById("passwordFieldsText");
  const formsText = document.getElementById("formsText");
  const extFormsText = document.getElementById("extFormsText");
  const extLinksText = document.getElementById("extLinksText");
  const suspLinksText = document.getElementById("suspLinksText");
  const hiddenLinksText = document.getElementById("hiddenLinksText");
  const extIframesText = document.getElementById("extIframesText");
  const extScriptsText = document.getElementById("extScriptsText");

  const aiPredictionText = document.getElementById("aiPredictionText");
  const aiProbText = document.getElementById("aiProbText");
  const aiLegitProbText = document.getElementById("aiLegitProbText");
  const aiScoreText = document.getElementById("aiScoreText");
  const modelVersionText = document.getElementById("modelVersionText");

  if (urlText) urlText.textContent = res.url || "N/A";

  // 1. Render URL Rules
  renderReasonsList(urlReasonsList, (res.urlResult && res.urlResult.reasons) ? res.urlResult.reasons : []);

  // 2. Render Webpage Rules & Metrics
  if (res.hasPageData && res.pageResult) {
    const pageResult = res.pageResult;
    if (pageTitleText) pageTitleText.textContent = pageResult.pageTitle || "-";
    if (passwordFieldsText) passwordFieldsText.textContent = pageResult.passwordFields ?? 0;
    if (formsText) formsText.textContent = pageResult.forms ?? 0;
    if (extFormsText) extFormsText.textContent = pageResult.externalForms ?? 0;
    if (extLinksText) extLinksText.textContent = pageResult.externalLinks ?? 0;
    if (suspLinksText) suspLinksText.textContent = pageResult.suspiciousLinks ?? 0;
    if (hiddenLinksText) hiddenLinksText.textContent = pageResult.hiddenLinks ?? 0;
    if (extIframesText) extIframesText.textContent = pageResult.externalIframesCount ?? 0;
    if (extScriptsText) extScriptsText.textContent = pageResult.externalScriptsCount ?? 0;

    const pageReasonsFormatted = (pageResult.reasons || []).map((r) => {
      if (r.includes("password")) return "+10 " + r;
      if (r.includes("different domain")) return "+25 " + r;
      if (r.includes("suspicious links")) return "+15 " + r;
      if (r.includes("hidden links")) return "+10 " + r;
      if (r.includes("brand")) return "+20 " + r;
      if (r.includes("external iframe")) return "+10 " + r;
      return "+5 " + r;
    });
    renderReasonsList(webpageReasonsList, pageReasonsFormatted);
  } else {
    if (pageTitleText) pageTitleText.textContent = "Unavailable";
    if (passwordFieldsText) passwordFieldsText.textContent = "N/A";
    if (formsText) formsText.textContent = "N/A";
    if (extFormsText) extFormsText.textContent = "N/A";
    if (extLinksText) extLinksText.textContent = "N/A";
    if (suspLinksText) suspLinksText.textContent = "N/A";
    if (hiddenLinksText) hiddenLinksText.textContent = "N/A";
    if (extIframesText) extIframesText.textContent = "N/A";
    if (extScriptsText) extScriptsText.textContent = "N/A";

    renderReasonsList(webpageReasonsList, [res.unavailableNote || "Webpage analysis is unavailable on this page."]);
  }

  // 3. Render Level 9 AI Prediction & Probabilities
  if (res.hasAIData && res.aiResult) {
    const aiResult = res.aiResult;
    const pProb = typeof aiResult.phishing_probability === "number" ? aiResult.phishing_probability : 0;
    const lProb = typeof aiResult.legitimate_probability === "number" ? aiResult.legitimate_probability : (1.0 - pProb);

    const phishingPct = (pProb * 100).toFixed(1);
    const legitPct = (lProb * 100).toFixed(1);

    if (aiPredictionText) {
      aiPredictionText.textContent = aiResult.prediction || "N/A";
      aiPredictionText.className = aiResult.prediction === "PHISHING" ? "phishing-tag" : "legitimate-tag";
    }
    if (aiProbText) aiProbText.textContent = `${phishingPct}%`;
    if (aiLegitProbText) aiLegitProbText.textContent = `${legitPct}%`;
    if (aiScoreText) aiScoreText.textContent = `${res.aiScore ?? 0} / 100`;
    if (modelVersionText) modelVersionText.textContent = aiResult.model || "Random Forest";
    setAiOfflineNote(false);
  } else {
    if (aiPredictionText) {
      aiPredictionText.textContent = res.aiSkipped
        ? "Not applied to local addresses"
        : "Unavailable (AI server offline)";
      aiPredictionText.className = "";
    }
    if (aiProbText) aiProbText.textContent = "N/A";
    if (aiLegitProbText) aiLegitProbText.textContent = "N/A";
    if (aiScoreText) aiScoreText.textContent = "N/A";
    setAiOfflineNote(!res.aiSkipped);
  }

  // 4. Update Score Cards
  const safeUrlScore = res.urlScore ?? 0;
  const safeWebScore = res.webpageScore ?? 0;
  const safeAiScore = res.aiScore ?? 0;
  const safeFinalScore = res.finalScore ?? 0;

  if (urlScoreText) urlScoreText.textContent = `${safeUrlScore}`;
  if (webpageScoreText) webpageScoreText.textContent = res.hasPageData ? `${safeWebScore}` : "N/A";
  if (aiRiskScoreBreakdownText) aiRiskScoreBreakdownText.textContent = res.hasAIData ? `${safeAiScore}` : "N/A";
  if (finalScoreText) finalScoreText.textContent = `${safeFinalScore} / 100`;

  // 5. Update Calculation Explanations
  const urlWeight = res.urlWeight ?? 0.30;
  const pageWeight = res.pageWeight ?? 0.20;
  const aiWeight = res.aiWeight ?? 0.50;
  const urlContrib = res.urlContrib ?? 0;
  const pageContrib = res.pageContrib ?? 0;
  const aiContrib = res.aiContrib ?? 0;

  if (urlCalcText) urlCalcText.textContent = `${safeUrlScore} × ${(urlWeight * 100).toFixed(0)}% = ${urlContrib.toFixed(1)}`;
  if (webpageCalcText) webpageCalcText.textContent = res.hasPageData ? `${safeWebScore} × ${(pageWeight * 100).toFixed(0)}% = ${pageContrib.toFixed(1)}` : "N/A";
  if (aiCalcText) aiCalcText.textContent = res.hasAIData ? `${safeAiScore} × ${(aiWeight * 100).toFixed(0)}% = ${aiContrib.toFixed(1)}` : "N/A";
  if (finalCalcText) {
    const sumVal = (urlContrib + pageContrib + aiContrib).toFixed(1);
    finalCalcText.textContent = `${sumVal} → ${safeFinalScore} / 100`;
  }

  // 6. Classification & Recommendation
  let recText = "";
  let recClass = "";
  const statusLevel = res.statusLevel || "SAFE";

  if (statusLevel === "DANGEROUS") {
    recText = "Multiple strong phishing indicators detected. Do not enter passwords, payment details, or sensitive information.";
    recClass = "rec-dangerous";
  } else if (statusLevel === "SUSPICIOUS") {
    recText = "Some suspicious indicators detected. Verify the website address before entering sensitive information.";
    recClass = "rec-suspicious";
  } else {
    recText = "No major suspicious indicators detected. Continue with normal caution.";
    recClass = "rec-safe";
  }
  if (res.trusted === "user") {
    recText = "You marked this site as trusted. " + recText;
  } else if (res.trusted === "builtin") {
    recText = "This domain is on the built-in trusted list. " + recText;
  }

  if (statusBadge) {
    statusBadge.textContent = statusLevel;
    statusBadge.className = `status-badge status-${statusLevel.toLowerCase()}`;
  }

  if (recommendationBox && recommendationText) {
    recommendationText.textContent = recText;
    recommendationBox.className = `recommendation-box ${recClass}`;
  }

  // 7. Render Detection Summary Checklist Safely with Level 9 Grouping
  renderSummaryChecklist(summaryChecklist, res.urlResult, res.pageResult, res.aiResult, res.aiSkipped);
}

/**
 * Renders State for Restricted Browser Internal Pages (chrome://, edge://, etc.).
 */
function displayRestrictedState(message) {
  const autoScanStateText = document.getElementById("autoScanStateText");
  const urlText = document.getElementById("urlText");
  const statusBadge = document.getElementById("statusBadge");
  const recommendationBox = document.getElementById("recommendationBox");
  const recommendationText = document.getElementById("recommendationText");
  const summaryChecklist = document.getElementById("summaryChecklist");

  if (autoScanStateText) autoScanStateText.textContent = "Status: Not available for this page";
  if (urlText) urlText.textContent = "N/A";

  if (statusBadge) {
    statusBadge.textContent = "UNAVAILABLE";
    statusBadge.className = "status-badge status-default";
  }

  if (recommendationBox && recommendationText) {
    recommendationText.textContent = message || "Automatic scanning is unavailable on browser internal pages.";
    recommendationBox.className = "recommendation-box rec-default";
  }

  const urlScoreText = document.getElementById("urlScoreText");
  const webpageScoreText = document.getElementById("webpageScoreText");
  const aiRiskScoreBreakdownText = document.getElementById("aiRiskScoreBreakdownText");
  const finalScoreText = document.getElementById("finalScoreText");

  if (urlScoreText) urlScoreText.textContent = "N/A";
  if (webpageScoreText) webpageScoreText.textContent = "N/A";
  if (aiRiskScoreBreakdownText) aiRiskScoreBreakdownText.textContent = "N/A";
  if (finalScoreText) finalScoreText.textContent = "N/A / 100";

  const urlCalcText = document.getElementById("urlCalcText");
  const webpageCalcText = document.getElementById("webpageCalcText");
  const aiCalcText = document.getElementById("aiCalcText");
  const finalCalcText = document.getElementById("finalCalcText");

  if (urlCalcText) urlCalcText.textContent = "N/A";
  if (webpageCalcText) webpageCalcText.textContent = "N/A";
  if (aiCalcText) aiCalcText.textContent = "N/A";
  if (finalCalcText) finalCalcText.textContent = "N/A";

  const pageTitleText = document.getElementById("pageTitleText");
  const passwordFieldsText = document.getElementById("passwordFieldsText");
  const formsText = document.getElementById("formsText");
  const extFormsText = document.getElementById("extFormsText");
  const extLinksText = document.getElementById("extLinksText");
  const suspLinksText = document.getElementById("suspLinksText");
  const hiddenLinksText = document.getElementById("hiddenLinksText");
  const extIframesText = document.getElementById("extIframesText");
  const extScriptsText = document.getElementById("extScriptsText");

  if (pageTitleText) pageTitleText.textContent = "N/A";
  if (passwordFieldsText) passwordFieldsText.textContent = "N/A";
  if (formsText) formsText.textContent = "N/A";
  if (extFormsText) extFormsText.textContent = "N/A";
  if (extLinksText) extLinksText.textContent = "N/A";
  if (suspLinksText) suspLinksText.textContent = "N/A";
  if (hiddenLinksText) hiddenLinksText.textContent = "N/A";
  if (extIframesText) extIframesText.textContent = "N/A";
  if (extScriptsText) extScriptsText.textContent = "N/A";

  const aiPredictionText = document.getElementById("aiPredictionText");
  const aiProbText = document.getElementById("aiProbText");
  const aiLegitProbText = document.getElementById("aiLegitProbText");
  const aiScoreText = document.getElementById("aiScoreText");
  const modelVersionText = document.getElementById("modelVersionText");

  if (aiPredictionText) {
    aiPredictionText.textContent = "N/A";
    aiPredictionText.className = "";
  }
  if (aiProbText) aiProbText.textContent = "N/A";
  if (aiLegitProbText) aiLegitProbText.textContent = "N/A";
  if (aiScoreText) aiScoreText.textContent = "N/A";
  if (modelVersionText) modelVersionText.textContent = "N/A";
  setAiOfflineNote(false);

  const urlReasonsList = document.getElementById("urlReasonsList");
  const webpageReasonsList = document.getElementById("webpageReasonsList");

  if (urlReasonsList) setSingleListItem(urlReasonsList, "no-reasons", "URL analysis unavailable on internal pages.");
  if (webpageReasonsList) setSingleListItem(webpageReasonsList, "no-reasons", "Webpage DOM analysis unavailable on internal pages.");

  if (summaryChecklist) {
    setChecklistItem(summaryChecklist, "check-neutral", "ℹ", "Automatic scanning is unavailable on browser internal pages.");
  }
}

/**
 * Renders State for Failed Scans.
 */
function displayFailedState(message) {
  const autoScanStateText = document.getElementById("autoScanStateText");
  const statusBadge = document.getElementById("statusBadge");
  const recommendationBox = document.getElementById("recommendationBox");
  const recommendationText = document.getElementById("recommendationText");
  const summaryChecklist = document.getElementById("summaryChecklist");

  if (autoScanStateText) autoScanStateText.textContent = "Status: Scan Failed";

  if (statusBadge) {
    statusBadge.textContent = "UNAVAILABLE";
    statusBadge.className = "status-badge status-default";
  }

  if (recommendationBox && recommendationText) {
    recommendationText.textContent = message || "Scan failed for current page.";
    recommendationBox.className = "recommendation-box rec-default";
  }

  const finalScoreText = document.getElementById("finalScoreText");
  if (finalScoreText) finalScoreText.textContent = "N/A / 100";

  if (summaryChecklist) {
    setChecklistItem(summaryChecklist, "check-warn", "⚠️", `Scan failed: ${message}`);
  }
}

/**
 * Renders Level 9 Grouped Summary Checklist with Severity Badges (INFO, LOW, MEDIUM, HIGH).
 */
function renderSummaryChecklist(container, urlResult, pageResult, aiResult, aiSkipped) {
  if (!container) return;
  container.textContent = "";

  const items = [];

  // Group 1: URL Indicators
  if (urlResult && urlResult.indicators) {
    urlResult.indicators.forEach((ind) => items.push(ind));
  }

  // Group 2: Webpage Indicators
  if (pageResult && pageResult.indicators) {
    pageResult.indicators.forEach((ind) => items.push(ind));
  }

  // Group 3: AI Model Analysis Indicator
  if (aiResult) {
    if (aiResult.prediction === "PHISHING") {
      const probPct = typeof aiResult.phishing_probability === "number"
        ? (aiResult.phishing_probability * 100).toFixed(0)
        : "100";
      items.push({ severity: "HIGH", text: `AI Model predicts PHISHING (${probPct}% probability)`, icon: "⚠" });
    } else {
      const probPct = typeof aiResult.legitimate_probability === "number"
        ? (aiResult.legitimate_probability * 100).toFixed(0)
        : "100";
      items.push({ severity: "INFO", text: `AI Model predicts LEGITIMATE (${probPct}% probability)`, icon: "✓" });
    }
  } else {
    items.push({
      severity: "INFO",
      text: aiSkipped ? "AI model is not applied to local addresses" : "AI Model analysis unavailable (Server offline)",
      icon: "ℹ"
    });
  }

  items.forEach((item) => {
    const li = document.createElement("li");
    let statusClass = "check-neutral";
    if (item.severity === "HIGH") statusClass = "check-fail";
    else if (item.severity === "MEDIUM" || item.severity === "LOW") statusClass = "check-warn";
    else if (item.severity === "INFO" && item.icon === "✓") statusClass = "check-pass";

    li.className = `check-item ${statusClass}`;
    const iconEl = document.createElement("strong");
    iconEl.textContent = item.icon;
    const textEl = document.createElement("span");
    textEl.textContent = `[${item.severity}] ${item.text}`;
    li.appendChild(iconEl);
    li.appendChild(document.createTextNode(" "));
    li.appendChild(textEl);
    container.appendChild(li);
  });
}

/**
 * Helper to render reasons bullet list into a UL container safely.
 */
function renderReasonsList(container, reasons) {
  if (!container) return;
  container.textContent = "";

  if (reasons && Array.isArray(reasons) && reasons.length > 0) {
    reasons.forEach((reason) => {
      const li = document.createElement("li");
      li.className = "reason-item";
      li.textContent = reason;
      container.appendChild(li);
    });
  } else {
    const li = document.createElement("li");
    li.className = "no-reasons";
    li.textContent = "No suspicious indicators detected.";
    container.appendChild(li);
  }
}

/**
 * Replaces the content of a list with one plain-text item.
 */
function setSingleListItem(list, className, text) {
  list.textContent = "";
  const li = document.createElement("li");
  li.className = className;
  li.textContent = text;
  list.appendChild(li);
}

/**
 * Replaces the content of the checklist with one icon + text item.
 */
function setChecklistItem(list, statusClass, icon, text) {
  list.textContent = "";
  const li = document.createElement("li");
  li.className = `check-item ${statusClass}`;
  const iconEl = document.createElement("strong");
  iconEl.textContent = icon;
  const textEl = document.createElement("span");
  textEl.textContent = text;
  li.appendChild(iconEl);
  li.appendChild(document.createTextNode(" "));
  li.appendChild(textEl);
  list.appendChild(li);
}
