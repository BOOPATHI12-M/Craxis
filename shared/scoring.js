// shared/scoring.js - Craxis shared detection and scoring logic.
//
// Single source of truth for URL rules, brand/lookalike detection, trust
// handling, score fusion and classification. Loaded by:
//   - background.js     via importScripts("shared/config.js", "shared/scoring.js")
//   - popup.html        via <script> tags
//   - content.js        via manifest content_scripts
//   - Node unit tests   via require("./shared/scoring.js")
//
// Rules, keywords and thresholds live in shared/config.json (see config.js).

(function (root, factory) {
  var cfg = root.AIPHISH_CONFIG;
  if (!cfg && typeof require === "function") {
    cfg = require("./config.js");
  }
  var api = factory(cfg);
  if (typeof module === "object" && module.exports) {
    module.exports = api;
  } else {
    root.AIPhishScoring = api;
  }
})(typeof self !== "undefined" ? self : this, function (CONFIG) {
  "use strict";

  var IPV4 = /^(\d{1,3}\.){3}\d{1,3}$/;

  // ---------------------------------------------------------------- helpers

  function parseUrl(url) {
    try {
      return new URL(url);
    } catch (e) {
      return null;
    }
  }

  function isIpHost(host) {
    return IPV4.test(host || "");
  }

  /** True for localhost, loopback and private-range hosts (the user's own network). */
  function isLocalHost(host) {
    var h = String(host || "").trim().toLowerCase().replace(/^\[|\]$/g, "");
    if (!h) return false;
    if (h === "localhost" || h.endsWith(".localhost") || h === "::1") return true;
    var m = IPV4.exec(h);
    if (!m) return false;
    var parts = h.split(".").map(Number);
    if (parts.some(function (n) { return n > 255; })) return false;
    if (parts[0] === 127 || parts[0] === 10) return true;
    if (parts[0] === 192 && parts[1] === 168) return true;
    if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return true;
    if (parts[0] === 169 && parts[1] === 254) return true;
    return false;
  }

  /** True only for the user's own machine: localhost, 127.x.x.x and ::1. */
  function isLoopbackHost(host) {
    var h = String(host || "").trim().toLowerCase().replace(/^\[|\]$/g, "");
    if (!h) return false;
    if (h === "localhost" || h.endsWith(".localhost") || h === "::1") return true;
    return /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(h);
  }

  function normalizeHost(host) {
    return String(host || "").trim().toLowerCase().replace(/^\.+|\.+$/g, "");
  }

  function hostMatchesDomain(host, domain) {
    return host === domain || host.endsWith("." + domain);
  }

  /** Returns the registrable domain (example.com, example.co.uk) of a host. */
  function registrableDomain(host, cfg) {
    cfg = cfg || CONFIG;
    host = normalizeHost(host);
    if (!host || isIpHost(host)) return host;
    var parts = host.split(".");
    if (parts.length <= 2) return host;
    var lastTwo = parts.slice(-2).join(".");
    if (cfg.multi_part_suffixes.indexOf(lastTwo) !== -1 && parts.length >= 3) {
      return parts.slice(-3).join(".");
    }
    return lastTwo;
  }

  function editDistance(a, b) {
    if (a === b) return 0;
    if (!a.length) return b.length;
    if (!b.length) return a.length;
    var prev = [];
    var i;
    var j;
    for (j = 0; j <= b.length; j++) prev[j] = j;
    for (i = 1; i <= a.length; i++) {
      var cur = [i];
      for (j = 1; j <= b.length; j++) {
        var cost = a[i - 1] === b[j - 1] ? 0 : 1;
        cur[j] = Math.min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + cost);
      }
      prev = cur;
    }
    return prev[b.length];
  }

  /** Possible un-obfuscated spellings of a label (paypa1 -> paypal, rnicrosoft -> microsoft). */
  function glyphVariants(label) {
    var base = label.replace(/0/g, "o").replace(/3/g, "e").replace(/5/g, "s").replace(/rn/g, "m").replace(/vv/g, "w");
    var out = {};
    out[base.replace(/1/g, "l")] = true;
    out[base.replace(/1/g, "i")] = true;
    return Object.keys(out);
  }

  // ----------------------------------------------------------------- trust

  /**
   * Is this URL trusted?
   * Returns { trusted: boolean, source: "user" | "builtin" | null }.
   * Built-in trust needs HTTPS, no "@", a non-IP host and a domain that is
   * not on a shared hosting suffix. User trust matches the host or a parent.
   */
  function trustStatus(url, userAllowlist, cfg) {
    cfg = cfg || CONFIG;
    var parsed = parseUrl(url);
    if (!parsed) return { trusted: false, source: null };
    var host = normalizeHost(parsed.hostname);

    var list = Array.isArray(userAllowlist) ? userAllowlist : [];
    for (var i = 0; i < list.length; i++) {
      var entry = normalizeHost(list[i]);
      if (entry && hostMatchesDomain(host, entry)) return { trusted: true, source: "user" };
    }

    if (parsed.protocol !== "https:" || url.indexOf("@") !== -1 || isIpHost(host)) {
      return { trusted: false, source: null };
    }
    for (var s = 0; s < cfg.shared_hosting_suffixes.length; s++) {
      if (hostMatchesDomain(host, cfg.shared_hosting_suffixes[s])) return { trusted: false, source: null };
    }
    var reg = registrableDomain(host, cfg);
    if (cfg.trusted_domains.indexOf(reg) !== -1) return { trusted: true, source: "builtin" };
    return { trusted: false, source: null };
  }

  // ----------------------------------------------------------------- brands

  function isBrandOwnDomain(host, reg, brand) {
    for (var i = 0; i < brand.domains.length; i++) {
      var d = brand.domains[i];
      if (reg === d || hostMatchesDomain(host, d)) return true;
    }
    return false;
  }

  /**
   * Looks for a brand name used in a domain that does not belong to that brand.
   * kind: "brand-in-domain" | "homoglyph" | "typosquat"
   */
  function detectBrandAbuse(hostname, cfg) {
    cfg = cfg || CONFIG;
    var host = normalizeHost(hostname);
    if (!host || isIpHost(host)) return null;
    var reg = registrableDomain(host, cfg);
    var label = reg.split(".")[0];
    var tokens = host.split(/[^a-z0-9]+/).filter(Boolean);
    var i;
    var b;

    for (i = 0; i < cfg.brands.length; i++) {
      b = cfg.brands[i];
      if (isBrandOwnDomain(host, reg, b)) continue;
      var hit = b.match === "contains" ? host.indexOf(b.name) !== -1 : tokens.indexOf(b.name) !== -1;
      if (hit) return { brand: b.name, kind: "brand-in-domain" };
    }

    var candidates = [];
    [label].concat(label.split("-")).forEach(function (c) {
      if (c && candidates.indexOf(c) === -1) candidates.push(c);
    });

    for (i = 0; i < cfg.brands.length; i++) {
      b = cfg.brands[i];
      if (isBrandOwnDomain(host, reg, b)) continue;
      for (var c = 0; c < candidates.length; c++) {
        var cand = candidates[c];
        if (cand === b.name) continue;
        if (glyphVariants(cand).indexOf(b.name) !== -1) return { brand: b.name, kind: "homoglyph" };
        if (b.name.length >= 6 && cand.length >= 5 && editDistance(cand, b.name) === 1) {
          return { brand: b.name, kind: "typosquat" };
        }
      }
    }
    return null;
  }

  /** Finds a brand name mentioned in free text (page title, site name). */
  function findBrandInText(text, cfg) {
    cfg = cfg || CONFIG;
    var lower = String(text || "").toLowerCase();
    if (!lower) return null;
    var words = lower.split(/[^a-z0-9]+/).filter(Boolean);
    for (var i = 0; i < cfg.brands.length; i++) {
      var b = cfg.brands[i];
      if (words.indexOf(b.name) !== -1) return b;
    }
    return null;
  }

  /** True when the host belongs to the given brand object. */
  function hostBelongsToBrand(hostname, brand, cfg) {
    var host = normalizeHost(hostname);
    return isBrandOwnDomain(host, registrableDomain(host, cfg || CONFIG), brand);
  }

  // ------------------------------------------------------------- URL rules

  function analyzeURL(url, opts) {
    opts = opts || {};
    var cfg = opts.config || CONFIG;
    var score = 0;
    var reasons = [];
    var indicators = [];

    var parsed = parseUrl(url);
    var details = {
      isHttps: false, isIp: false, hasAt: false, isLong: false, isSubdomain: false,
      isKeyword: false, isShortener: false, isPunycode: false, isSuspiciousTld: false,
      manyHyphens: false, brandAbuse: null
    };
    if (!parsed || !parsed.hostname) {
      return {
        score: 100,
        reasons: ["+100 Invalid or malformed URL structure"],
        indicators: [{ severity: "HIGH", text: "Invalid or malformed URL structure", icon: "⚠" }],
        details: details
      };
    }

    var hostname = normalizeHost(parsed.hostname);
    var builtinTrusted = trustStatus(url, [], cfg).trusted;

    var isHttps = parsed.protocol === "https:";
    details.isHttps = isHttps;
    if (!isHttps) {
      score += 20;
      reasons.push("+20 Website is not using HTTPS");
      indicators.push({ severity: "LOW", text: "Website is not using HTTPS (+20)", icon: "⚠" });
    } else {
      indicators.push({ severity: "INFO", text: "HTTPS connection enabled", icon: "✓" });
    }

    var isIp = isIpHost(hostname);
    details.isIp = isIp;
    if (isIp) {
      score += 30;
      reasons.push("+30 URL uses an IP address instead of a domain");
      indicators.push({ severity: "MEDIUM", text: "IP address detected in hostname (+30)", icon: "⚠" });
    } else {
      indicators.push({ severity: "INFO", text: "Standard domain name used", icon: "✓" });
    }

    var hasAt = url.indexOf("@") !== -1;
    details.hasAt = hasAt;
    if (hasAt) {
      score += 25;
      reasons.push("+25 URL contains an @ symbol");
      indicators.push({ severity: "MEDIUM", text: "URL contains an @ symbol (+25)", icon: "⚠" });
    }

    var isLong = url.length > 100;
    details.isLong = isLong;
    if (isLong) {
      score += 15;
      reasons.push("+15 URL is unusually long");
      indicators.push({ severity: "LOW", text: "Unusually long URL length (+15)", icon: "⚠" });
    }

    var dotCount = (hostname.match(/\./g) || []).length;
    var isSubdomain = dotCount > 3;
    details.isSubdomain = isSubdomain;
    if (isSubdomain) {
      score += 15;
      reasons.push("+15 URL contains an unusually large number of subdomains");
      indicators.push({ severity: "LOW", text: "Excessive subdomain depth (+15)", icon: "⚠" });
    }

    // Keywords: a hit in the hostname is a stronger signal than one in the path.
    var hostKeywords = cfg.keywords.filter(function (k) { return hostname.indexOf(k) !== -1; });
    var rest = (parsed.pathname + parsed.search).toLowerCase();
    var pathKeywords = cfg.keywords.filter(function (k) {
      return hostKeywords.indexOf(k) === -1 && rest.indexOf(k) !== -1;
    });
    if (hostKeywords.length > 0) {
      score += 10;
      details.isKeyword = true;
      reasons.push("+10 URL hostname contains a sensitive keyword (" + hostKeywords[0] + ")");
      indicators.push({ severity: "LOW", text: "Sensitive keyword in hostname: " + hostKeywords[0] + " (+10)", icon: "⚠" });
    } else if (pathKeywords.length > 0) {
      score += 3;
      details.isKeyword = true;
      reasons.push("+3 URL path contains a sensitive keyword (" + pathKeywords[0] + ")");
      indicators.push({ severity: "INFO", text: "Sensitive keyword in URL path: " + pathKeywords[0] + " (+3)", icon: "⚠" });
    }

    var isShortener = cfg.shorteners.some(function (s) { return hostMatchesDomain(hostname, s); });
    details.isShortener = isShortener;
    if (isShortener) {
      score += 15;
      reasons.push("+15 URL uses a URL shortening service");
      indicators.push({ severity: "MEDIUM", text: "URL shortening service detected (+15)", icon: "⚠" });
    }

    if (hostname.indexOf("xn--") !== -1) {
      score += 15;
      details.isPunycode = true;
      reasons.push("+15 Hostname uses punycode (possible look-alike characters)");
      indicators.push({ severity: "MEDIUM", text: "Punycode / internationalised hostname (+15)", icon: "⚠" });
    }

    var tld = hostname.split(".").pop();
    if (!isIp && cfg.suspicious_tlds.indexOf(tld) !== -1) {
      score += 10;
      details.isSuspiciousTld = true;
      reasons.push("+10 Top-level domain .{tld} is frequently abused".replace("{tld}", tld));
      indicators.push({ severity: "LOW", text: "Frequently abused top-level domain .{tld} (+10)".replace("{tld}", tld), icon: "⚠" });
    }

    var hyphens = (hostname.replace(/xn--/g, "").match(/-/g) || []).length;
    if (hyphens >= 3) {
      score += 10;
      details.manyHyphens = true;
      reasons.push("+10 Hostname contains many hyphens");
      indicators.push({ severity: "LOW", text: "Hostname contains " + hyphens + " hyphens (+10)", icon: "⚠" });
    }

    if (!builtinTrusted) {
      var abuse = detectBrandAbuse(hostname, cfg);
      if (abuse) {
        score += 25;
        details.brandAbuse = abuse;
        var why = abuse.kind === "brand-in-domain"
          ? "uses the brand name \"" + abuse.brand + "\" in a domain that does not belong to it"
          : "looks like a misspelling of the brand \"" + abuse.brand + "\"";
        reasons.push("+25 Hostname " + why);
        indicators.push({ severity: "HIGH", text: "Look-alike brand domain: " + abuse.brand + " (+25)", icon: "⚠" });
      }
    }

    score = Math.min(score, 100);
    return { score: score, reasons: reasons, indicators: indicators, details: details };
  }

  /**
   * Adds optional domain intelligence (domain age, certificate) to a URL result.
   * intel: { domain_age_days: number|null, cert: { valid: boolean|null, age_days: number|null } }
   */
  function applyIntel(urlResult, intel) {
    if (!urlResult || !intel) return urlResult;
    var score = urlResult.score;
    var reasons = urlResult.reasons.slice();
    var indicators = (urlResult.indicators || []).slice();
    var age = intel.domain_age_days;

    if (typeof age === "number") {
      if (age < 30) {
        score += 25;
        reasons.push("+25 Domain was registered only " + age + " days ago");
        indicators.push({ severity: "HIGH", text: "Very new domain: " + age + " days old (+25)", icon: "⚠" });
      } else if (age < 90) {
        score += 10;
        reasons.push("+10 Domain was registered " + age + " days ago");
        indicators.push({ severity: "LOW", text: "Recently registered domain: " + age + " days (+10)", icon: "⚠" });
      }
    }
    if (intel.cert && intel.cert.valid === false) {
      score += 15;
      reasons.push("+15 TLS certificate is invalid or does not match the hostname");
      indicators.push({ severity: "MEDIUM", text: "Invalid TLS certificate (+15)", icon: "⚠" });
    }

    return {
      score: Math.min(score, 100),
      reasons: reasons,
      indicators: indicators,
      details: urlResult.details
    };
  }

  // ----------------------------------------------------------- fusion / class

  function classify(score, thresholds) {
    var th = thresholds || CONFIG.thresholds;
    if (score >= th.dangerous) return "DANGEROUS";
    if (score >= th.suspicious) return "SUSPICIOUS";
    return "SAFE";
  }

  /**
   * Weighted fusion of URL, page (DOM) and AI scores.
   * opts: { thresholds, trust: {trusted, source}, unavailableNote, config }
   */
  function calculateCombinedScore(url, urlResult, pageResult, aiResult, opts) {
    opts = opts || {};
    var cfg = opts.config || CONFIG;
    var thresholds = opts.thresholds || cfg.thresholds;

    var urlScore = urlResult && typeof urlResult.score === "number" ? urlResult.score : 0;
    var hasPageData = !!(pageResult && typeof pageResult.score === "number");
    var webpageScore = hasPageData ? pageResult.score : 0;
    var hasAIData = !!(aiResult && typeof aiResult.ai_risk_score === "number");
    var aiScore = hasAIData ? aiResult.ai_risk_score : 0;

    var w;
    var urlWeight;
    var pageWeight = 0;
    var aiWeight = 0;
    if (hasAIData && hasPageData) {
      w = cfg.weights.all;
      urlWeight = w.url; pageWeight = w.page; aiWeight = w.ai;
    } else if (hasAIData) {
      w = cfg.weights.url_ai;
      urlWeight = w.url; aiWeight = w.ai;
    } else if (hasPageData) {
      w = cfg.weights.url_page;
      urlWeight = w.url; pageWeight = w.page;
    } else {
      urlWeight = 1;
    }

    var urlContrib = urlScore * urlWeight;
    var pageContrib = webpageScore * pageWeight;
    var aiContrib = aiScore * aiWeight;
    var finalScore = Math.round(urlContrib + pageContrib + aiContrib);
    finalScore = Math.min(Math.max(finalScore, 0), 100);

    // Corroboration: when every available layer independently reports elevated
    // risk, the weighted average must not dilute that agreement below DANGEROUS.
    var layerScores = [urlScore];
    if (hasPageData) layerScores.push(webpageScore);
    if (hasAIData) layerScores.push(aiScore);
    var corroborationMin = cfg.thresholds.corroboration_min || 50;
    var corroborated = layerScores.length >= 2 && layerScores.every(function (s) { return s >= corroborationMin; });
    if (corroborated && finalScore < thresholds.dangerous) {
      finalScore = thresholds.dangerous;
    }

    var trust = opts.trust && opts.trust.trusted ? opts.trust : null;
    var rawScore = finalScore;
    if (trust && finalScore > cfg.thresholds.trusted_cap) {
      finalScore = cfg.thresholds.trusted_cap;
    }

    return {
      url: url || "N/A",
      urlResult: urlResult || null,
      pageResult: pageResult || null,
      aiResult: aiResult || null,
      urlScore: urlScore,
      webpageScore: webpageScore,
      aiScore: aiScore,
      hasPageData: hasPageData,
      hasAIData: hasAIData,
      urlContrib: urlContrib,
      pageContrib: pageContrib,
      aiContrib: aiContrib,
      urlWeight: urlWeight,
      pageWeight: pageWeight,
      aiWeight: aiWeight,
      rawScore: rawScore,
      corroborated: corroborated,
      aiSkipped: !!opts.aiSkipped,
      finalScore: finalScore,
      statusLevel: classify(finalScore, thresholds),
      trusted: trust ? trust.source : null,
      unavailableNote: opts.unavailableNote || ""
    };
  }

  /** Flat list of human-readable reasons for history and warning UI. */
  function collectReasons(result) {
    var reasons = [];
    if (!result) return reasons;
    if (result.trusted) {
      reasons.push(result.trusted === "user"
        ? "Site is on your trusted list"
        : "Domain is in the built-in trusted list");
    }
    if (result.urlResult && result.urlResult.reasons) {
      result.urlResult.reasons.forEach(function (r) { reasons.push(r); });
    }
    if (result.corroborated) {
      reasons.push("URL rules, page structure and AI model all report elevated risk");
    }
    if (result.pageResult && result.pageResult.reasons) {
      result.pageResult.reasons.forEach(function (r) { reasons.push(r); });
    }
    if (result.aiResult && result.aiResult.prediction === "PHISHING") {
      var pct = typeof result.aiResult.phishing_probability === "number"
        ? Math.round(result.aiResult.phishing_probability * 100)
        : null;
      reasons.push(pct === null
        ? "AI Model flags site as PHISHING"
        : "AI Model flags site as PHISHING (" + pct + "% probability)");
    }
    return reasons;
  }

  return {
    CONFIG: CONFIG,
    parseUrl: parseUrl,
    isIpHost: isIpHost,
    isLocalHost: isLocalHost,
    isLoopbackHost: isLoopbackHost,
    registrableDomain: registrableDomain,
    editDistance: editDistance,
    trustStatus: trustStatus,
    detectBrandAbuse: detectBrandAbuse,
    findBrandInText: findBrandInText,
    hostBelongsToBrand: hostBelongsToBrand,
    analyzeURL: analyzeURL,
    applyIntel: applyIntel,
    classify: classify,
    calculateCombinedScore: calculateCombinedScore,
    collectReasons: collectReasons
  };
});
