// background.js - Craxis Service Worker (v1.1)
// Navigation scanning, score fusion (shared/scoring.js), tab state, history,
// trusted sites and the blocking warning page.

importScripts("shared/config.js", "shared/scoring.js", "shared/settings.js", "shared/api.js");

const Scoring = self.AIPhishScoring;
const Settings = self.AIPhishSettings;
const Api = self.AIPhishApi;

const HISTORY_KEY = "aiphish_scan_history";
const BYPASS_KEY = "aiphish_bypass";
const HISTORY_LIMIT = 100;
const DEDUPE_MS = 15000;
const RESCAN_GUARD_MS = 8000;

// In-memory cache of tab scans. Mirrored into chrome.storage.session so a
// service worker restart does not lose the state shown in the popup.
const tabScans = {};

// Last permission-triggered rescan per tab (debounce).
const permissionRescan = {};

// Settings cache, refreshed when the user changes them.
let settingsCache = null;

async function getSettings() {
  if (!settingsCache) settingsCache = await Settings.load();
  return settingsCache;
}

chrome.storage.onChanged.addListener((changes, area) => {
  if ((area === "sync" || area === "local") && changes[Settings.STORAGE_KEY]) {
    settingsCache = Settings.normalize(changes[Settings.STORAGE_KEY].newValue);
  }
});

function isScannableUrl(url) {
  return typeof url === "string" && (url.startsWith("http://") || url.startsWith("https://"));
}

function hostOf(url) {
  try {
    return new URL(url).hostname.toLowerCase();
  } catch (e) {
    return "";
  }
}

// ---------------------------------------------------------------- tab state

async function setTabScan(tabId, scan) {
  tabScans[tabId] = scan;
  try {
    await chrome.storage.session.set({ ["tabscan_" + tabId]: scan });
  } catch (e) {
    // storage.session unavailable: in-memory state only.
  }
}

async function getTabScan(tabId) {
  if (tabScans[tabId]) return tabScans[tabId];
  try {
    const key = "tabscan_" + tabId;
    const stored = await chrome.storage.session.get(key);
    if (stored[key]) {
      tabScans[tabId] = stored[key];
      return stored[key];
    }
  } catch (e) {
    // ignore
  }
  return null;
}

async function clearTabScan(tabId) {
  delete tabScans[tabId];
  try {
    await chrome.storage.session.remove("tabscan_" + tabId);
  } catch (e) {
    // ignore
  }
}

// ------------------------------------------------------------------- bypass

async function getBypassList() {
  try {
    const stored = await chrome.storage.session.get(BYPASS_KEY);
    return Array.isArray(stored[BYPASS_KEY]) ? stored[BYPASS_KEY] : [];
  } catch (e) {
    return [];
  }
}

async function isBypassed(host) {
  if (!host) return false;
  const list = await getBypassList();
  return list.includes(host);
}

async function addBypass(host) {
  if (!host) return;
  const list = await getBypassList();
  if (!list.includes(host)) {
    list.push(host);
    try {
      await chrome.storage.session.set({ [BYPASS_KEY]: list });
    } catch (e) {
      // ignore
    }
  }
}

// ----------------------------------------------------------------- blocking

/**
 * Replaces the tab with the blocking warning page when the result is
 * DANGEROUS, blocking is enabled, and the user has not chosen to proceed.
 */
async function maybeBlock(tabId, url, result) {
  const settings = await getSettings();
  if (!settings.blockDangerous || !result || result.statusLevel !== "DANGEROUS") return false;
  if (result.trusted) return false;
  if (await isBypassed(hostOf(url))) return false;

  const reasons = Scoring.collectReasons(result).slice(0, 5);
  const params = new URLSearchParams({
    target: url,
    score: String(result.finalScore),
    reasons: JSON.stringify(reasons)
  });
  try {
    await chrome.tabs.update(tabId, { url: chrome.runtime.getURL("warning.html") + "?" + params.toString() });
    return true;
  } catch (e) {
    return false;
  }
}

// Early check before the page loads: URL rules + AI only (no DOM yet).
chrome.webNavigation.onBeforeNavigate.addListener(async (details) => {
  if (details.frameId !== 0 || !isScannableUrl(details.url)) return;
  try {
    const settings = await getSettings();
    if (!settings.autoScan || !settings.blockDangerous) return;
    if (await isBypassed(hostOf(details.url))) return;

    const trust = Scoring.trustStatus(details.url, settings.userAllowlist);
    if (trust.trusted) return;

    const isLocal = Scoring.isLoopbackHost(hostOf(details.url));
    const isPrivate = !isLocal && Scoring.isLocalHost(hostOf(details.url));
    let urlResult = Scoring.analyzeURL(details.url);
    // Blocking never depends on the AI for private network addresses, so skip the call.
    const aiResult = isLocal || isPrivate ? null : await Api.predict(details.url, settings, 2500);
    if (aiResult && aiResult.intel) urlResult = Scoring.applyIntel(urlResult, aiResult.intel);

    const combined = Scoring.calculateCombinedScore(details.url, urlResult, null, aiResult, {
      thresholds: Settings.thresholds(settings),
      trust,
      aiSkipped: isLocal
    });
    await maybeBlock(details.tabId, details.url, combined);
  } catch (e) {
    console.error("Pre-navigation check failed:", e);
  }
});

// ------------------------------------------------------- automatic scanning

chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
  if (changeInfo.status !== "complete" || !tab || !tab.url) return;

  if (!isScannableUrl(tab.url)) {
    await setTabScan(tabId, {
      status: "unavailable",
      url: tab.url,
      message: "Browser internal pages cannot be scanned."
    });
    return;
  }

  const settings = await getSettings();
  if (!settings.autoScan) return;

  const last = await getTabScan(tabId);
  if (last && last.status === "completed" && last.url === tab.url && Date.now() - last.timestamp < RESCAN_GUARD_MS) {
    return;
  }

  await setTabScan(tabId, { status: "scanning", url: tab.url, timestamp: Date.now() });
  runAutomaticScan(tabId, tab.url);
});

chrome.tabs.onRemoved.addListener((tabId) => {
  clearTabScan(tabId);
});

async function runAutomaticScan(tabId, url) {
  try {
    const settings = await getSettings();
    const trust = Scoring.trustStatus(url, settings.userAllowlist);

    // Only the user's own machine (localhost, 127.x.x.x) is skipped. Private network
    // sites such as a college portal on 172.16.x.x are analysed like any other site.
    const isLocal = Scoring.isLoopbackHost(hostOf(url));
    const isPrivate = !isLocal && Scoring.isLocalHost(hostOf(url));
    let urlResult = Scoring.analyzeURL(url);
    const [pageResult, aiResult] = await Promise.all([
      requestPageDOM(tabId),
      isLocal ? Promise.resolve(null) : Api.predict(url, settings)
    ]);
    if (aiResult && aiResult.intel) urlResult = Scoring.applyIntel(urlResult, aiResult.intel);

    const combined = Scoring.calculateCombinedScore(url, urlResult, pageResult, aiResult, {
      thresholds: Settings.thresholds(settings),
      trust,
      aiSkipped: isLocal,
      aiAdvisory: isPrivate
    });

    await setTabScan(tabId, {
      status: "completed",
      type: "auto",
      url,
      timestamp: Date.now(),
      result: combined
    });

    saveScanToHistory(combined, "auto");

    const blocked = await maybeBlock(tabId, url, combined);
    if (!blocked) {
      chrome.tabs.sendMessage(tabId, { action: "SHOW_WARNING", result: combined }).catch(() => {});
    }
    return combined;
  } catch (err) {
    console.error("Automatic scan error:", err);
    await setTabScan(tabId, { status: "failed", url, error: err.message || "Automatic scan failed." });
    return null;
  }
}

// ----------------------------------------------------------------- messages

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
  handleMessage(request, sender)
    .then((response) => sendResponse(response))
    .catch((err) => sendResponse({ success: false, error: String(err && err.message ? err.message : err) }));
  return true;
});

async function handleMessage(request, sender) {
  switch (request.action) {
    case "GET_TAB_SCAN": {
      const scan = await getTabScan(request.tabId);
      return { success: true, scan: scan || null };
    }

    case "STORE_MANUAL_SCAN": {
      if (!request.tabId || !request.result) return { success: false };
      await setTabScan(request.tabId, {
        status: "completed",
        type: "manual",
        url: request.url,
        timestamp: Date.now(),
        result: request.result
      });
      saveScanToHistory(request.result, "manual");
      chrome.tabs.sendMessage(request.tabId, { action: "SHOW_WARNING", result: request.result }).catch(() => {});
      return { success: true };
    }

    case "OPEN_DETAILS": {
      // The address comes from the sender tab itself, never from the message.
      const tabUrl = sender.tab && sender.tab.url;
      if (!isScannableUrl(tabUrl)) return { success: false, error: "No scannable page." };
      await chrome.tabs.create({
        url: chrome.runtime.getURL("history.html") + "?details=" + encodeURIComponent(tabUrl),
        index: typeof sender.tab.index === "number" ? sender.tab.index + 1 : undefined,
        active: true
      });
      return { success: true };
    }

    case "PERMISSION_EVENT": {
      // A page asked for a sensitive permission after load: scan it again.
      const tab = sender.tab;
      if (!tab || typeof tab.id !== "number" || !isScannableUrl(tab.url)) return { success: false };
      const settings = await getSettings();
      if (!settings.autoScan) return { success: false };
      const now = Date.now();
      const last = permissionRescan[tab.id] || 0;
      if (now - last < 4000) return { success: true, debounced: true };
      permissionRescan[tab.id] = now;
      runAutomaticScan(tab.id, tab.url);
      return { success: true };
    }

    case "OPEN_HISTORY":
      await chrome.tabs.create({ url: "history.html" });
      return { success: true };

    case "TRUST_SITE": {
      const host = String(request.host || "").trim().toLowerCase();
      if (!host) return { success: false, error: "No host given." };
      settingsCache = await Settings.addToAllowlist(host);
      return { success: true, userAllowlist: settingsCache.userAllowlist };
    }

    case "UNTRUST_SITE": {
      const host = String(request.host || "").trim().toLowerCase();
      settingsCache = await Settings.removeFromAllowlist(host);
      return { success: true, userAllowlist: settingsCache.userAllowlist };
    }

    case "PROCEED_ANYWAY": {
      const target = String(request.url || "");
      if (!isScannableUrl(target) || !sender.tab || typeof sender.tab.id !== "number") {
        return { success: false, error: "Invalid proceed request." };
      }
      await addBypass(hostOf(target));
      await chrome.tabs.update(sender.tab.id, { url: target });
      return { success: true };
    }

    case "GO_TO_SAFETY": {
      if (!sender.tab || typeof sender.tab.id !== "number") return { success: false };
      await chrome.tabs.update(sender.tab.id, { url: "chrome://newtab" });
      return { success: true };
    }

    default:
      return { success: false, error: "Unknown action." };
  }
}

// ------------------------------------------------------------------ history

/**
 * Saves a scan result to chrome.storage.local ("aiphish_scan_history").
 * Max 100 entries; the same URL is not saved twice within 15 seconds.
 */
function saveScanToHistory(result, type) {
  if (!result || !result.url || result.url === "N/A" || !isScannableUrl(result.url)) return;

  try {
    chrome.storage.local.get([HISTORY_KEY], (data) => {
      if (chrome.runtime.lastError) return;

      let history = Array.isArray(data[HISTORY_KEY]) ? data[HISTORY_KEY] : [];
      const now = Date.now();
      const recent = history.find((h) => h.url === result.url && now - (h.rawTimestamp || 0) < DEDUPE_MS);
      if (recent) {
        // Keep the earlier entry unless this scan found something worse.
        if ((result.finalScore ?? 0) <= (recent.riskScore ?? 0)) return;
        history = history.filter((h) => h !== recent);
      }

      const reasons = Scoring.collectReasons(result);
      const entry = {
        id: "scan-" + now + "-" + Math.random().toString(36).slice(2, 7),
        url: result.url,
        hostname: hostOf(result.url) || result.url,
        riskScore: result.finalScore ?? 0,
        classification: result.statusLevel || "SAFE",
        timestamp: new Date(now).toISOString(),
        rawTimestamp: now,
        formattedTime: new Date(now).toLocaleString("en-US", {
          day: "2-digit",
          month: "short",
          year: "numeric",
          hour: "2-digit",
          minute: "2-digit",
          hour12: true
        }),
        reasons: reasons.length > 0 ? reasons : ["No suspicious indicators detected."],
        aiPrediction: result.aiResult && result.aiResult.prediction ? result.aiResult.prediction : "N/A",
        // ok = model answered, skipped_local = not applied to a local address, unavailable = backend gave no answer
        aiStatus: result.aiResult && result.aiResult.prediction
          ? "ok"
          : (result.aiSkipped ? "skipped_local" : "unavailable"),
        urlScore: result.urlScore ?? 0,
        webpageScore: result.webpageScore ?? 0,
        aiScore: result.aiScore ?? 0,
        // Per-website AI explanation (numbers about the address only, never page content).
        aiExplanation: result.aiResult && result.aiResult.explanation && Array.isArray(result.aiResult.explanation.features)
          ? result.aiResult.explanation.features.slice(0, 6).map((f) => ({
              label: f.label, value: f.value, typical: f.typical_legitimate, effect: f.effect_points
            }))
          : null,
        aiProbability: result.aiResult && typeof result.aiResult.phishing_probability === "number"
          ? result.aiResult.phishing_probability
          : null,
        scanType: type,
        trusted: result.trusted || null
      };

      history.unshift(entry);
      if (history.length > HISTORY_LIMIT) history = history.slice(0, HISTORY_LIMIT);
      chrome.storage.local.set({ [HISTORY_KEY]: history });
    });
  } catch (err) {
    console.error("Error saving scan history:", err);
  }
}

// ------------------------------------------------------------- page analysis

function sendAnalyze(tabId) {
  return new Promise((resolve) => {
    chrome.tabs.sendMessage(tabId, { action: "ANALYZE_PAGE" }, (response) => {
      if (chrome.runtime.lastError || !response || !response.success) resolve(null);
      else resolve(response.data);
    });
  });
}

/** Asks content.js for DOM analysis, injecting it first if it is not present. */
async function requestPageDOM(tabId) {
  const first = await sendAnalyze(tabId);
  if (first) return first;
  try {
    await chrome.scripting.executeScript({
      target: { tabId },
      files: ["shared/config.js", "shared/scoring.js", "content.js"]
    });
  } catch (e) {
    return null;
  }
  return sendAnalyze(tabId);
}
