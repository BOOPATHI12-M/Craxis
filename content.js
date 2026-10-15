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

const CRAXIS_LOGO_SVG =
  '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64" width="26" height="26" aria-hidden="true">' +
  '<defs><linearGradient id="cxg" x1="0" y1="0" x2="1" y2="1"><stop offset="0" stop-color="#7c5cff"/><stop offset="1" stop-color="#2ee6a6"/></linearGradient></defs>' +
  '<path d="M32 3 57 12v20c0 15-11 25-25 29C18 57 7 47 7 32V12z" fill="url(#cxg)"/>' +
  '<path d="M32 8 52 15v17c0 12-8 20-20 24C20 52 12 44 12 32V15z" fill="#0b0b1a"/>' +
  '<path d="M40 23a12.5 12.5 0 1 0 0 18" fill="none" stroke="#f5f3ff" stroke-width="5.5" stroke-linecap="round"/>' +
  '<path d="M41 26.5l10 11M51 26.5l-10 11" fill="none" stroke="#2ee6a6" stroke-width="5" stroke-linecap="round"/></svg>';

const CRAXIS_BANNER_CSS = `
  :host { all: initial; }
  * { box-sizing: border-box; margin: 0; padding: 0; text-align: left; }
  .wrap {
    position: fixed; top: 12px; left: 50%; transform: translateX(-50%);
    width: min(860px, calc(100vw - 24px)); z-index: 2147483647;
    font: 13px/1.45 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    color: #f5f3ff; background: #0b0b1a; border: 1px solid #2a2a47;
    border-left: 5px solid var(--accent); border-radius: 12px;
    box-shadow: 0 12px 40px rgba(0,0,0,.55); padding: 14px 16px;
    display: flex; flex-direction: column; gap: 10px;
  }
  .wrap.suspicious { --accent: #f59e0b; --tint: #fde68a; --pill: #451a03; }
  .wrap.dangerous  { --accent: #ef4444; --tint: #fecaca; --pill: #450a0a; }
  .top { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
  .brand { display: flex; align-items: center; gap: 8px; font-weight: 700; letter-spacing: .02em; }
  .pill { background: var(--pill); color: var(--tint); border: 1px solid var(--accent);
    border-radius: 999px; padding: 2px 10px; font-size: 12px; font-weight: 700; }
  .score { margin-left: auto; color: #c4b5fd; font-size: 12px; font-weight: 600; }
  ul { list-style: none; display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 6px 16px; }
  li { position: relative; padding-left: 16px; color: #e2e8f0; font-size: 12.5px; }
  li::before { content: ""; position: absolute; left: 2px; top: .55em; width: 6px; height: 6px;
    border-radius: 50%; background: var(--accent); }
  .rec { color: var(--tint); font-weight: 600; font-size: 12.5px; }
  .actions { display: flex; gap: 8px; flex-wrap: wrap; }
  button { font: inherit; font-size: 12px; font-weight: 600; border: 0; border-radius: 8px;
    padding: 7px 12px; cursor: pointer; }
  button:focus-visible { outline: 2px solid #a78bfa; outline-offset: 2px; }
  .primary { background: #6d4aff; color: #fff; }
  .danger  { background: #dc2626; color: #fff; }
  .ghost   { background: #2a2a47; color: #e2e8f0; }
  .safe { position: fixed; bottom: 16px; right: 16px; z-index: 2147483647; display: flex; align-items: center; gap: 8px;
    font: 600 12px/1 -apple-system, "Segoe UI", Roboto, Arial, sans-serif; color: #6ee7b7; background: #0b0b1a;
    border: 1px solid #10b981; border-radius: 999px; padding: 6px 12px 6px 8px; opacity: .92;
    box-shadow: 0 4px 12px rgba(0,0,0,.4); cursor: default; transition: opacity .2s; }
  .safe svg { width: 18px; height: 18px; }
  @media (prefers-reduced-motion: reduce) { * { transition: none !important; } }
`;

function craxisEl(tag, className, text) {
  const el = document.createElement(tag);
  if (className) el.className = className;
  if (text !== undefined) el.textContent = text;
  return el;
}

/**
 * Renders the in-page Craxis warning UI (SAFE badge, SUSPICIOUS or DANGEROUS banner).
 * Drawn inside a shadow root so the host page's CSS cannot distort it.
 * @param {Object} result - Scanned security result
 */
function renderWarningUI(result) {
  // Prevent warning loops if user already dismissed for current page session
  const pageSessionKey = "aiphish_dismissed_" + window.location.href;
  if (sessionStorage.getItem(pageSessionKey) === "true") {
    return;
  }

  const existingRoot = document.getElementById("aiphish-guard-root");
  if (existingRoot) {
    existingRoot.remove();
  }

  const finalScore = typeof result.finalScore === "number" ? result.finalScore : 0;
  // The classification is decided by the background using the user's thresholds.
  const level = result.statusLevel || (finalScore >= 60 ? "DANGEROUS" : finalScore >= 30 ? "SUSPICIOUS" : "SAFE");
  const isDangerous = level === "DANGEROUS";
  const isSafe = level === "SAFE";

  const host = document.createElement("div");
  host.id = "aiphish-guard-root";
  const shadow = host.attachShadow({ mode: "open" });
  const style = document.createElement("style");
  style.textContent = CRAXIS_BANNER_CSS;
  shadow.appendChild(style);

  if (isSafe) {
    const badge = craxisEl("div", "safe");
    badge.title = "Craxis: SAFE website";
    badge.insertAdjacentHTML("afterbegin", CRAXIS_LOGO_SVG);
    badge.appendChild(
      craxisEl("span", "", result.trusted ? "Safe · trusted (" + finalScore + "/100)" : "Safe (" + finalScore + "/100)")
    );
    shadow.appendChild(badge);
    document.body.appendChild(host);
    // Fade the safe badge after 6 seconds to avoid clutter
    setTimeout(() => {
      badge.style.opacity = "0.3";
    }, 6000);
    return;
  }

  const wrap = craxisEl("div", "wrap " + (isDangerous ? "dangerous" : "suspicious"));
  wrap.setAttribute("role", "alert");

  const top = craxisEl("div", "top");
  const brand = craxisEl("div", "brand");
  brand.insertAdjacentHTML("afterbegin", CRAXIS_LOGO_SVG);
  brand.appendChild(craxisEl("span", "", "Craxis"));
  top.appendChild(brand);
  top.appendChild(craxisEl("span", "pill", isDangerous ? "High-risk website" : "Suspicious website"));
  top.appendChild(craxisEl("span", "score", "Risk score " + finalScore + "/100"));
  wrap.appendChild(top);

  const reasons = Scoring ? Scoring.collectReasons(result) : [];
  const list = craxisEl("ul");
  (reasons.length ? reasons.slice(0, 4) : ["Suspicious risk indicators detected."]).forEach((r) => {
    list.appendChild(craxisEl("li", "", String(r)));
  });
  wrap.appendChild(list);

  wrap.appendChild(
    craxisEl(
      "p",
      "rec",
      isDangerous
        ? "Avoid entering passwords, OTPs, payment information, or sensitive credentials."
        : "Verify the website address in your address bar before proceeding."
    )
  );

  const actions = craxisEl("div", "actions");
  if (isDangerous) {
    const back = craxisEl("button", "danger", "Go back");
    back.type = "button";
    back.onclick = () => {
      if (window.history.length > 1) window.history.back();
      else alert("Cannot go back: No previous page in browsing history for this tab.");
    };
    actions.appendChild(back);
  }
  const details = craxisEl("button", "primary", "View details");
  details.type = "button";
  details.onclick = () => {
    // A page cannot open the toolbar popup, so ask the background to open the
    // scan's detail view in a new tab.
    try {
      chrome.runtime.sendMessage({ action: "OPEN_DETAILS" }, (response) => {
        if (chrome.runtime.lastError || !response || !response.success) {
          alert("Could not open the report. Click the Craxis icon in your browser toolbar instead.");
        }
      });
    } catch (e) {
      alert("Could not open the report. Click the Craxis icon in your browser toolbar instead.");
    }
  };
  const cont = craxisEl("button", "ghost", "Continue anyway");
  cont.type = "button";
  cont.onclick = () => {
    sessionStorage.setItem(pageSessionKey, "true");
    host.remove();
  };
  actions.appendChild(details);
  actions.appendChild(cont);
  wrap.appendChild(actions);

  shadow.appendChild(wrap);
  document.body.appendChild(host);
}
