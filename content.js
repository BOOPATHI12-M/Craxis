// content.js - Craxis Content Script (v1.1)
// DOM analysis and the in-page SAFE / SUSPICIOUS / DANGEROUS warning UI.
// Uses shared/scoring.js (loaded before this file) for brand matching.

var Scoring = typeof AIPhishScoring !== "undefined" ? AIPhishScoring : null;

// Guard against double registration when the script is injected again.
if (!window.__aiphishGuardLoaded) {
  window.__aiphishGuardLoaded = true;
  chrome.runtime.onMessage.addListener(handleContentMessage);

  // permission-watch.js (page world) announces sensitive permission requests.
  // Ask the background to scan again, because the first scan may have run before.
  var permissionTimer = null;
  window.addEventListener("craxis-permission", () => {
    clearTimeout(permissionTimer);
    permissionTimer = setTimeout(() => {
      try {
        chrome.runtime.sendMessage({ action: "PERMISSION_EVENT" }, () => void chrome.runtime.lastError);
      } catch (e) {
        // extension reloaded; nothing to do
      }
    }, 1200);
  });
}

/** Permission requests recorded by permission-watch.js: [{ kind, gesture }]. */
function readPermissionRequests() {
  try {
    const raw = document.documentElement.getAttribute("data-craxis-permissions");
    const list = raw ? JSON.parse(raw) : [];
    return Array.isArray(list)
      ? list.filter((r) => r && typeof r.kind === "string").map((r) => ({ kind: r.kind, gesture: !!r.gesture }))
      : [];
  } catch (e) {
    return [];
  }
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

  // 8. Sensitive browser permissions the page asked for. A page that asks for
  // the camera, microphone, screen, location or clipboard without any user
  // action, or a login page that asks at all, has no obvious reason to.
  const permissionRequests = readPermissionRequests();
  const SENSITIVE = ["camera", "microphone", "screen", "location", "clipboard"];
  const sensitiveAuto = permissionRequests.filter((r) => SENSITIVE.includes(r.kind) && !r.gesture);
  const sensitiveClicked = permissionRequests.filter((r) => SENSITIVE.includes(r.kind) && r.gesture);
  const notifyAuto = permissionRequests.filter((r) => r.kind === "notifications" && !r.gesture);
  const names = (list) => Array.from(new Set(list.map((r) => r.kind))).join(", ");

  if (sensitiveAuto.length > 0) {
    webpageScore += 20;
    webpageReasons.push(`Page asked for ${names(sensitiveAuto)} access without any user action`);
    indicators.push({ severity: "MEDIUM", text: `Asked for ${names(sensitiveAuto)} access on its own`, icon: "⚠" });
  } else if (sensitiveClicked.length > 0 && passwordFields > 0) {
    webpageScore += 10;
    webpageReasons.push(`A login page asked for ${names(sensitiveClicked)} access, which a login page should not need`);
    indicators.push({ severity: "LOW", text: `Login page asked for ${names(sensitiveClicked)} access`, icon: "⚠" });
  }
  if (notifyAuto.length > 0) {
    webpageScore += 10;
    webpageReasons.push("Page asked to send notifications as soon as it loaded");
    indicators.push({ severity: "LOW", text: "Notification permission requested on load", icon: "⚠" });
  }

  // Embedded frames from other domains that are allowed to use the camera or microphone.
  let mediaFrames = 0;
  iframes.forEach((frame) => {
    const allow = (frame.getAttribute("allow") || "").toLowerCase();
    const src = frame.getAttribute("src");
    if (!src || !/(camera|microphone|display-capture)/.test(allow)) return;
    try {
      const frameHost = new URL(src, window.location.href).hostname;
      if (frameHost && frameHost !== currentHostname) mediaFrames++;
    } catch (e) {}
  });
  if (mediaFrames > 0) {
    webpageScore += 10;
    webpageReasons.push("Embedded frame from another domain is allowed to use the camera or microphone");
    indicators.push({ severity: "LOW", text: `Cross-domain frame with camera or microphone access (${mediaFrames})`, icon: "⚠" });
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
    permissionRequests: permissionRequests,
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
    position: fixed; top: 10px; left: 50%; transform: translateX(-50%);
    width: min(720px, calc(100vw - 20px)); z-index: 2147483647;
    font: 13px/1.4 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
    color: #f5f3ff; background: #0b0b1a; border: 1px solid #2a2a47;
    border-left: 4px solid var(--accent); border-radius: 10px;
    box-shadow: 0 8px 28px rgba(0,0,0,.5); overflow: hidden;
  }
  .wrap.suspicious { --accent: #f59e0b; --tint: #fde68a; --pill: #451a03; }
  .wrap.dangerous  { --accent: #ef4444; --tint: #fecaca; --pill: #450a0a; }
  .bar { display: flex; align-items: center; gap: 10px; padding: 8px 10px 8px 12px; }
  .bar svg { flex: none; }
  .pill { flex: none; background: var(--pill); color: var(--tint); border: 1px solid var(--accent);
    border-radius: 999px; padding: 1px 9px; font-size: 12px; font-weight: 700; white-space: nowrap; }
  .summary { flex: 1; min-width: 0; color: #cbd5e1; font-size: 12.5px;
    white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
  .score { flex: none; color: #c4b5fd; font-size: 12px; font-weight: 700; }
  .btns { flex: none; display: flex; gap: 6px; }
  button { font: inherit; font-size: 12px; font-weight: 600; border: 0; border-radius: 7px;
    padding: 6px 10px; cursor: pointer; white-space: nowrap; }
  button:focus-visible { outline: 2px solid #a78bfa; outline-offset: 2px; }
  .primary { background: #6d4aff; color: #fff; }
  .danger  { background: #dc2626; color: #fff; }
  .ghost   { background: transparent; color: #cbd5e1; border: 1px solid #2a2a47; }
  .close   { background: transparent; color: #94a3b8; font-size: 18px; line-height: 1; padding: 2px 8px; }
  .details { display: none; border-top: 1px solid #2a2a47; padding: 10px 14px 12px 14px;
    background: #12122a; }
  .wrap.open .details { display: block; }
  .details h2 { font-size: 11px; letter-spacing: .06em; text-transform: uppercase; color: #94a3b8;
    margin-bottom: 6px; font-weight: 700; }
  ul { list-style: none; display: flex; flex-direction: column; gap: 5px; }
  li { position: relative; padding-left: 16px; color: #e2e8f0; font-size: 12.5px; }
  li::before { content: ""; position: absolute; left: 2px; top: .5em; width: 6px; height: 6px;
    border-radius: 50%; background: var(--accent); }
  .rec { margin-top: 10px; color: var(--tint); font-weight: 600; font-size: 12.5px; }
  .foot { margin-top: 10px; font-size: 11.5px; color: #94a3b8; }
  .safe { position: fixed; bottom: 16px; right: 16px; z-index: 2147483647; display: flex; align-items: center; gap: 8px;
    font: 600 12px/1 -apple-system, "Segoe UI", Roboto, Arial, sans-serif; color: #6ee7b7; background: #0b0b1a;
    border: 1px solid #10b981; border-radius: 999px; padding: 6px 12px 6px 8px; opacity: .92;
    box-shadow: 0 4px 12px rgba(0,0,0,.4); cursor: default; transition: opacity .2s; }
  .safe svg { width: 18px; height: 18px; }
  @media (max-width: 560px) { .summary { display: none; } .bar { flex-wrap: wrap; } }
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
 * The banner is a single compact bar; "Details" expands the reasons in place.
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

  const reasons = Scoring ? Scoring.collectReasons(result) : [];
  const shown = reasons.length ? reasons : ["Suspicious risk indicators detected."];

  const wrap = craxisEl("div", "wrap " + (isDangerous ? "dangerous" : "suspicious"));
  wrap.setAttribute("role", "alert");

  // ---- compact bar (always visible)
  const bar = craxisEl("div", "bar");
  bar.insertAdjacentHTML("afterbegin", CRAXIS_LOGO_SVG);
  bar.appendChild(craxisEl("span", "pill", isDangerous ? "High risk" : "Suspicious"));
  const summary = craxisEl(
    "span",
    "summary",
    shown[0] + (shown.length > 1 ? " (+" + (shown.length - 1) + " more)" : "")
  );
  bar.appendChild(summary);
  bar.appendChild(craxisEl("span", "score", finalScore + "/100"));

  const btns = craxisEl("div", "btns");
  const toggle = craxisEl("button", "primary", "Details");
  toggle.type = "button";
  toggle.setAttribute("aria-expanded", "false");
  toggle.onclick = () => {
    const open = wrap.classList.toggle("open");
    toggle.setAttribute("aria-expanded", open ? "true" : "false");
    toggle.textContent = open ? "Hide" : "Details";
  };
  btns.appendChild(toggle);
  if (isDangerous) {
    const back = craxisEl("button", "danger", "Go back");
    back.type = "button";
    back.onclick = () => {
      if (window.history.length > 1) window.history.back();
      else alert("Cannot go back: No previous page in browsing history for this tab.");
    };
    btns.appendChild(back);
  }
  const close = craxisEl("button", "close", "×");
  close.type = "button";
  close.title = "Continue anyway (dismiss for this tab session)";
  close.setAttribute("aria-label", "Dismiss warning and continue");
  close.onclick = () => {
    sessionStorage.setItem(pageSessionKey, "true");
    host.remove();
  };
  btns.appendChild(close);
  bar.appendChild(btns);
  wrap.appendChild(bar);

  // ---- expandable details
  const details = craxisEl("div", "details");
  details.appendChild(craxisEl("h2", "", "Why Craxis flagged this page"));
  const list = craxisEl("ul");
  shown.slice(0, 8).forEach((r) => list.appendChild(craxisEl("li", "", String(r))));
  details.appendChild(list);
  details.appendChild(
    craxisEl(
      "p",
      "rec",
      isDangerous
        ? "Avoid entering passwords, OTPs, payment information, or sensitive credentials."
        : "Verify the website address in your address bar before proceeding."
    )
  );
  details.appendChild(
    craxisEl("p", "foot", "Open the Craxis toolbar icon for the full score breakdown. Use × to continue anyway.")
  );
  wrap.appendChild(details);

  shadow.appendChild(wrap);
  document.body.appendChild(host);
}
