// content.js - Craxis Content Script (v1.1)
// DOM analysis and the in-page SAFE / SUSPICIOUS / DANGEROUS warning UI.
// Uses shared/scoring.js (loaded before this file) for brand matching.

var Scoring = typeof AIPhishScoring !== "undefined" ? AIPhishScoring : null;

// Guard against double registration when the script is injected again.
if (!window.__aiphishGuardLoaded) {
  window.__aiphishGuardLoaded = true;
  chrome.runtime.onMessage.addListener(handleContentMessage);
}

function handleContentMessage(request, sender, sendResponse) {
  if (request.action === "ANALYZE_PAGE") {
    try {
      const pageData = analyzePage();
      sendResponse({ success: true, data: pageData });
    } catch (error) {
      console.error("Error analyzing webpage:", error);
      sendResponse({ success: false, error: error.message });
    }
  } else if (request.action === "SHOW_WARNING") {
    if (request.result) {
      renderWarningUI(request.result);
    }
    sendResponse({ success: true });
  }
  return true;
}

/**
 * Main DOM structural analysis function.
 * Inspects page title, password fields, forms, external form actions, links, iframes, and external scripts.
 * ZERO collection of passwords, form values, cookies, or personal data.
 * @returns {Object} Webpage analysis metrics, score, and grouped indicators with severities.
 */
function analyzePage() {
  let webpageScore = 0;
  const webpageReasons = [];
  const indicators = [];

  // 1. Page Title Analysis
  const pageTitle = document.title ? document.title.trim() : "";
  const sensitiveTitleKeywords = [
    "login", "signin", "verify", "verification", "account",
    "password", "bank", "secure", "security", "confirm"
  ];
  const lowerTitle = pageTitle.toLowerCase();
  const suspiciousTitle = sensitiveTitleKeywords.some((kw) => lowerTitle.includes(kw));

  if (suspiciousTitle) {
    webpageScore += 5;
    webpageReasons.push("Page title contains a sensitive security-related keyword");
    indicators.push({ severity: "LOW", text: "Page title contains sensitive keyword", icon: "⚠" });
  } else {
    indicators.push({ severity: "INFO", text: "Page title appears standard", icon: "✓" });
  }

  // 2. Password Fields Detection
  const passwordInputs = document.querySelectorAll('input[type="password"]');
  const passwordFields = passwordInputs.length;

  // A password field is only a risk signal when the page is insecure, has no
  // form, or posts to another domain. A normal same-origin HTTPS login is not.
  const passwordPending = passwordFields > 0;

  // 3. Form Analysis & External Form Actions
  const formsList = Array.from(document.forms || document.querySelectorAll("form"));
  const formsCount = formsList.length;
  let externalFormsCount = 0;
  let sameOriginFormsCount = 0;
  const currentHostname = window.location.hostname;

  formsList.forEach((form) => {
    const rawAction = form.getAttribute("action");
    if (rawAction) {
      try {
        const absoluteActionURL = new URL(rawAction, window.location.href);
        if (
          absoluteActionURL.hostname &&
          currentHostname &&
          absoluteActionURL.hostname !== currentHostname &&
          (absoluteActionURL.protocol === "http:" || absoluteActionURL.protocol === "https:")
        ) {
          externalFormsCount++;
        } else {
          sameOriginFormsCount++;
        }
      } catch (e) {
        sameOriginFormsCount++;
      }
    } else {
      sameOriginFormsCount++;
    }
  });

  if (externalFormsCount > 0) {
    webpageScore += 25;
    webpageReasons.push("Form submits data to a different domain");
    indicators.push({ severity: "MEDIUM", text: `Form submits to external domain (${externalFormsCount})`, icon: "⚠" });
  } else if (formsCount > 0) {
    indicators.push({ severity: "INFO", text: `Forms submit locally to same origin (${formsCount})`, icon: "✓" });
  }

  if (passwordPending) {
    const isHttpsPage = window.location.protocol === "https:";
    const risky = !isHttpsPage || externalFormsCount > 0 || formsCount === 0;
    if (risky) {
      webpageScore += 10;
      webpageReasons.push("Page contains a password field");
      indicators.push({ severity: "LOW", text: `Password input field detected (${passwordFields})`, icon: "⚠" });
    } else {
      indicators.push({ severity: "INFO", text: `Password field on a secure same-origin form (${passwordFields})`, icon: "✓" });
    }
  } else {
    indicators.push({ severity: "INFO", text: "No password fields detected", icon: "✓" });
  }

  // 4. External, Suspicious, and Hidden Links Analysis
  const links = Array.from(document.querySelectorAll("a[href]"));
  let externalLinksCount = 0;
  let suspiciousLinksCount = 0;
  let hiddenLinksCount = 0;
  const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;

  links.forEach((link) => {
    const rawHref = link.getAttribute("href") || "";
    let resolvedURL = null;

    try {
      resolvedURL = new URL(rawHref, window.location.href);
    } catch (e) {}

    if (
      resolvedURL &&
      resolvedURL.hostname &&
      currentHostname &&
      resolvedURL.hostname !== currentHostname &&
      (resolvedURL.protocol === "http:" || resolvedURL.protocol === "https:")
    ) {
      externalLinksCount++;
    }

    const lowerHref = rawHref.toLowerCase();
    let isSuspiciousLink = false;

    if (lowerHref.startsWith("javascript:") || lowerHref.includes("@")) {
      isSuspiciousLink = true;
    } else if (resolvedURL && ipv4Regex.test(resolvedURL.hostname) && resolvedURL.hostname !== currentHostname) {
      isSuspiciousLink = true;
    }

    if (isSuspiciousLink) suspiciousLinksCount++;
    if (checkIsHiddenLink(link)) hiddenLinksCount++;
  });

  if (suspiciousLinksCount > 0) {
    webpageScore += 15;
    webpageReasons.push("Page contains suspicious links");
    indicators.push({ severity: "MEDIUM", text: `Suspicious links detected (${suspiciousLinksCount})`, icon: "⚠" });
  }

  if (hiddenLinksCount > 0) {
    webpageScore += 10;
    webpageReasons.push("Page contains hidden links");
    indicators.push({ severity: "LOW", text: `Hidden link elements detected (${hiddenLinksCount})`, icon: "⚠" });
  }

  // 5. iframe & External Script Analysis
  const iframes = Array.from(document.querySelectorAll("iframe"));
  const iframesCount = iframes.length;
  let externalIframesCount = 0;

  iframes.forEach((frame) => {
    const src = frame.getAttribute("src");
    if (src) {
      try {
        const frameUrl = new URL(src, window.location.href);
        if (frameUrl.hostname && frameUrl.hostname !== currentHostname) {
          externalIframesCount++;
        }
      } catch (e) {}
    }
  });

  if (externalIframesCount > 0) {
    webpageScore += 10;
    webpageReasons.push("Page contains an external iframe source");
    indicators.push({ severity: "LOW", text: `External iframe sources detected (${externalIframesCount})`, icon: "⚠" });
  }

  const scripts = Array.from(document.querySelectorAll("script[src]"));
  let externalScriptsCount = 0;
  scripts.forEach((script) => {
    const src = script.getAttribute("src");
    if (src) {
      try {
        const scriptUrl = new URL(src, window.location.href);
        if (scriptUrl.hostname && scriptUrl.hostname !== currentHostname) {
          externalScriptsCount++;
        }
      } catch (e) {}
    }
  });

  // 6. Brand named in the page but hosted on a different domain
  let brandMismatch = null;
  if (Scoring) {
    const siteNameMeta = document.querySelector('meta[property="og:site_name"]');
    const siteName = siteNameMeta ? siteNameMeta.getAttribute("content") || "" : "";
    const brand = Scoring.findBrandInText(pageTitle + " " + siteName);
    const trusted = Scoring.trustStatus(window.location.href, []).trusted;
    if (brand && !trusted && !Scoring.hostBelongsToBrand(currentHostname, brand)) {
      brandMismatch = brand.name;
      if (passwordFields > 0 || formsCount > 0) {
        webpageScore += 20;
        webpageReasons.push(`Page presents the brand "${brand.name}" but is hosted on a different domain`);
        indicators.push({ severity: "MEDIUM", text: `Brand "${brand.name}" shown on an unrelated domain`, icon: "⚠" });
      }
    }
  }

  // 7. Favicon served from another domain on a page that asks for a password
  let externalFavicon = false;
  const iconLink = document.querySelector('link[rel~="icon"]');
  if (iconLink && iconLink.getAttribute("href")) {
    try {
      const iconUrl = new URL(iconLink.getAttribute("href"), window.location.href);
      externalFavicon = !!iconUrl.hostname && iconUrl.hostname !== currentHostname;
    } catch (e) {}
  }
  if (externalFavicon && passwordFields > 0) {
    webpageScore += 5;
    webpageReasons.push("Page icon is loaded from another domain");
    indicators.push({ severity: "LOW", text: "Favicon loaded from another domain", icon: "⚠" });
  }

  webpageScore = Math.min(webpageScore, 100);

  return {
    passwordFields: passwordFields,
    forms: formsCount,
    externalForms: externalFormsCount,
    sameOriginForms: sameOriginFormsCount,
    externalLinks: externalLinksCount,
    suspiciousLinks: suspiciousLinksCount,
    hiddenLinks: hiddenLinksCount,
    iframesCount: iframesCount,
    externalIframesCount: externalIframesCount,
    externalScriptsCount: externalScriptsCount,
    suspiciousTitle: suspiciousTitle,
    brandMismatch: brandMismatch,
    externalFavicon: externalFavicon,
    pageTitle: pageTitle || "Untitled Page",
    score: webpageScore,
    reasons: webpageReasons,
    indicators: indicators
  };
}

/**
 * Helper to detect hidden link elements.
 */
function checkIsHiddenLink(element) {
  try {
    if (element.hasAttribute("hidden")) return true;
    const style = window.getComputedStyle(element);
    if (
      style.display === "none" ||
      style.visibility === "hidden" ||
      style.opacity === "0"
    ) {
      return true;
    }
    const rect = element.getBoundingClientRect();
    if (rect.width === 0 && rect.height === 0 && element.innerText.trim() === "") {
      return true;
    }
  } catch (e) {
    return false;
  }
  return false;
}

/**
 * Renders Level 12 Real-Time Warning UI (SAFE Badge, SUSPICIOUS Banner, or DANGEROUS Overlay).
 * @param {Object} result - Scanned security result
 */
function renderWarningUI(result) {
  // Prevent warning loops if user already dismissed for current page session
  const pageSessionKey = "aiphish_dismissed_" + window.location.href;
  if (sessionStorage.getItem(pageSessionKey) === "true") {
    return;
  }

  // Remove existing root if present
  const existingRoot = document.getElementById("aiphish-guard-root");
  if (existingRoot) {
    existingRoot.remove();
  }

  const finalScore = typeof result.finalScore === "number" ? result.finalScore : 0;
  // The classification is decided by the background using the user's thresholds.
  const level = result.statusLevel || (finalScore >= 60 ? "DANGEROUS" : finalScore >= 30 ? "SUSPICIOUS" : "SAFE");
  const isDangerous = level === "DANGEROUS";
  const isSafe = level === "SAFE";

  // Root Container
  const root = document.createElement("div");
  root.id = "aiphish-guard-root";
  root.style.cssText = `
    position: fixed !important;
    top: 0 !important;
    left: 0 !important;
    right: 0 !important;
    z-index: 2147483647 !important;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif !important;
    box-sizing: border-box !important;
    padding: 0 !important;
    margin: 0 !important;
  `;

  // CASE 1: SAFE Website (Small non-intrusive indicator)
  if (isSafe) {
    const safeBadge = document.createElement("div");
    safeBadge.style.cssText = `
      position: fixed !important;
      bottom: 16px !important;
      right: 16px !important;
      background-color: #0b0b1a !important;
      color: #34d399 !important;
      border: 1px solid #10b981 !important;
      border-radius: 20px !important;
      padding: 6px 14px !important;
      font-size: 11px !important;
      font-weight: 600 !important;
      box-shadow: 0 4px 12px rgba(0,0,0,0.4) !important;
      display: flex !important;
      align-items: center !important;
      gap: 6px !important;
      cursor: pointer !important;
      opacity: 0.9 !important;
      transition: opacity 0.2s ease !important;
    `;
    safeBadge.title = "Craxis: SAFE website";
    const badgeIcon = document.createElement("span");
    badgeIcon.textContent = "🛡️";
    const badgeText = document.createElement("span");
    badgeText.textContent = result.trusted
      ? `SAFE (trusted, ${finalScore}/100)`
      : `SAFE (${finalScore}/100)`;
    safeBadge.appendChild(badgeIcon);
    safeBadge.appendChild(badgeText);
    safeBadge.onclick = () => {
      alert("Craxis: This website is classified as SAFE with low risk indicators.");
    };

    root.appendChild(safeBadge);
    document.body.appendChild(root);

    // Auto-fade safe badge after 6 seconds to avoid clutter
    setTimeout(() => {
      if (safeBadge && safeBadge.parentNode) {
        safeBadge.style.opacity = "0.3";
      }
    }, 6000);
    return;
  }

  // CASE 2 & 3: SUSPICIOUS (Banner) or DANGEROUS (Overlay Banner)
  const container = document.createElement("div");
  container.style.cssText = `
    background-color: #0b0b1a !important;
    color: #f8fafc !important;
    border-bottom: 3px solid ${isDangerous ? "#ef4444" : "#f59e0b"} !important;
    box-shadow: 0 4px 20px rgba(0,0,0,0.6) !important;
    padding: 14px 18px !important;
    display: flex !important;
    flex-direction: column !important;
    gap: 10px !important;
    max-width: 100% !important;
  `;

  // Header Row
  const headerRow = document.createElement("div");
  headerRow.style.cssText = "display: flex !important; align-items: center !important; justify-content: space-between !important; gap: 12px !important;";

  const titleGroup = document.createElement("div");
  titleGroup.style.cssText = "display: flex; align-items: center; gap: 8px;";

  const iconSpan = document.createElement("span");
  iconSpan.style.cssText = "font-size: 20px;";
  iconSpan.textContent = isDangerous ? "🛑" : "⚠️";

  const titleText = document.createElement("strong");
  titleText.style.cssText = `font-size: 14px; color: ${isDangerous ? "#fca5a5" : "#fde047"}; letter-spacing: 0.5px;`;
  titleText.textContent = isDangerous
    ? "AI PHISHING GUARD — HIGH-RISK WEBSITE"
    : "AI PHISHING GUARD — SUSPICIOUS WEBSITE";

  const scoreBadge = document.createElement("span");
  scoreBadge.style.cssText = `
    background-color: ${isDangerous ? "#7f1d1d" : "#78350f"};
    color: ${isDangerous ? "#fee2e2" : "#fef3c7"};
    border: 1px solid ${isDangerous ? "#ef4444" : "#f59e0b"};
    padding: 2px 8px;
    border-radius: 4px;
    font-size: 12px;
    font-weight: 700;
  `;
  scoreBadge.textContent = `Risk Score: ${finalScore}/100`;

  titleGroup.appendChild(iconSpan);
  titleGroup.appendChild(titleText);
  titleGroup.appendChild(scoreBadge);
  headerRow.appendChild(titleGroup);

  // Button Actions
  const actionGroup = document.createElement("div");
  actionGroup.style.cssText = "display: flex; gap: 8px; align-items: center;";

  // Go Back Button (For Dangerous Sites)
  if (isDangerous) {
    const goBackBtn = document.createElement("button");
    goBackBtn.style.cssText = `
      background-color: #dc2626 !important;
      color: #ffffff !important;
      border: none !important;
      padding: 6px 12px !important;
      border-radius: 6px !important;
      font-size: 12px !important;
      font-weight: 700 !important;
      cursor: pointer !important;
    `;
    goBackBtn.textContent = "Go Back";
    goBackBtn.onclick = () => {
      if (window.history.length > 1) {
        window.history.back();
      } else {
        alert("Cannot go back: No previous page in browsing history for this tab.");
      }
    };
    actionGroup.appendChild(goBackBtn);
  }

  // View Security Details Button
  const viewDetailsBtn = document.createElement("button");
  viewDetailsBtn.style.cssText = `
    background-color: #6d4aff !important;
    color: #ffffff !important;
    border: none !important;
    padding: 6px 12px !important;
    border-radius: 6px !important;
    font-size: 12px !important;
    font-weight: 600 !important;
    cursor: pointer !important;
  `;
  viewDetailsBtn.textContent = "View Security Details";
  viewDetailsBtn.onclick = () => {
    alert("Click the Craxis extension icon in your browser toolbar to view the complete explainable security report.");
  };

  // Continue Anyway Button
  const continueBtn = document.createElement("button");
  continueBtn.style.cssText = `
    background-color: #2a2a47 !important;
    color: #cbd5e1 !important;
    border: none !important;
    padding: 6px 12px !important;
    border-radius: 6px !important;
    font-size: 12px !important;
    font-weight: 600 !important;
    cursor: pointer !important;
  `;
  continueBtn.textContent = "Continue Anyway";
  continueBtn.onclick = () => {
    sessionStorage.setItem(pageSessionKey, "true");
    root.remove();
  };

  actionGroup.appendChild(viewDetailsBtn);
  actionGroup.appendChild(continueBtn);
  headerRow.appendChild(actionGroup);
  container.appendChild(headerRow);

  // Reasons List & Recommendation Box
  const detailBox = document.createElement("div");
  detailBox.style.cssText = `
    font-size: 12px !important;
    color: #cbd5e1 !important;
    background-color: #0b0b1a !important;
    border: 1px solid #2a2a47 !important;
    padding: 10px 12px !important;
    border-radius: 6px !important;
    display: flex !important;
    flex-direction: column !important;
    gap: 6px !important;
  `;

  // Compile Reasons List
  const reasonsList = document.createElement("ul");
  reasonsList.style.cssText = "list-style-type: none; margin: 0; padding: 0; display: flex; flex-direction: column; gap: 3px;";

  const detectedReasons = Scoring ? Scoring.collectReasons(result) : [];

  if (detectedReasons.length > 0) {
    detectedReasons.slice(0, 4).forEach((reason) => {
      const li = document.createElement("li");
      li.style.cssText = "line-height: 1.35;";
      const bullet = document.createElement("span");
      bullet.style.cssText = "color: #f59e0b; font-weight: bold;";
      bullet.textContent = "•";
      li.appendChild(bullet);
      li.appendChild(document.createTextNode(" " + reason));
      reasonsList.appendChild(li);
    });
  } else {
    const li = document.createElement("li");
    li.textContent = "• Suspicious risk indicators detected.";
    reasonsList.appendChild(li);
  }

  detailBox.appendChild(reasonsList);

  // Recommended Action Text
  const recText = document.createElement("p");
  recText.style.cssText = `font-weight: 600; color: ${isDangerous ? "#fca5a5" : "#fde047"}; margin: 4px 0 0 0;`;
  recText.textContent = isDangerous
    ? "Recommended action: Avoid entering passwords, OTPs, payment information, or sensitive credentials."
    : "Recommended action: Verify the website address in your address bar before proceeding.";
  detailBox.appendChild(recText);

  container.appendChild(detailBox);
  root.appendChild(container);
  document.body.appendChild(root);
}
