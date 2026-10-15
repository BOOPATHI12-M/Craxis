// shared/settings.js - Craxis user settings (chrome.storage.sync).
// Works in the service worker, popup, options page and warning page.

(function (root) {
  "use strict";

  var STORAGE_KEY = "aiphish_settings";

  var DEFAULTS = {
    backendUrl: "http://127.0.0.1:5000",
    autoScan: true,
    blockDangerous: true,
    suspiciousThreshold: 30,
    dangerousThreshold: 60,
    useIntel: false,
    userAllowlist: []
  };

  function area() {
    if (typeof chrome === "undefined" || !chrome.storage) return null;
    return chrome.storage.sync || chrome.storage.local || null;
  }

  function normalizeBackendUrl(value) {
    var text = String(value || "").trim().replace(/\/+$/, "");
    if (!/^https?:\/\/[^\s/]+(:\d+)?$/i.test(text)) return DEFAULTS.backendUrl;
    return text;
  }

  function clampNumber(value, min, max, fallback) {
    var n = Number(value);
    if (!isFinite(n)) return fallback;
    return Math.min(max, Math.max(min, Math.round(n)));
  }

  /** Validates and fills in defaults for any stored object. */
  function normalize(raw) {
    var s = Object.assign({}, DEFAULTS, raw || {});
    s.backendUrl = normalizeBackendUrl(s.backendUrl);
    s.autoScan = s.autoScan !== false;
    s.blockDangerous = s.blockDangerous !== false;
    s.useIntel = s.useIntel === true;
    s.suspiciousThreshold = clampNumber(s.suspiciousThreshold, 1, 99, DEFAULTS.suspiciousThreshold);
    s.dangerousThreshold = clampNumber(s.dangerousThreshold, 2, 100, DEFAULTS.dangerousThreshold);
    if (s.dangerousThreshold <= s.suspiciousThreshold) {
      s.suspiciousThreshold = DEFAULTS.suspiciousThreshold;
      s.dangerousThreshold = DEFAULTS.dangerousThreshold;
    }
    var seen = {};
    s.userAllowlist = (Array.isArray(s.userAllowlist) ? s.userAllowlist : [])
      .map(function (h) { return String(h || "").trim().toLowerCase(); })
      .filter(function (h) {
        if (!h || seen[h]) return false;
        seen[h] = true;
        return /^[a-z0-9.-]+$/.test(h);
      });
    return s;
  }

  function load() {
    return new Promise(function (resolve) {
      var a = area();
      if (!a) {
        resolve(normalize(null));
        return;
      }
      try {
        a.get([STORAGE_KEY], function (data) {
          if (chrome.runtime && chrome.runtime.lastError) {
            resolve(normalize(null));
            return;
          }
          resolve(normalize(data && data[STORAGE_KEY]));
        });
      } catch (e) {
        resolve(normalize(null));
      }
    });
  }

  function save(settings) {
    var clean = normalize(settings);
    return new Promise(function (resolve) {
      var a = area();
      if (!a) {
        resolve(clean);
        return;
      }
      var payload = {};
      payload[STORAGE_KEY] = clean;
      try {
        a.set(payload, function () { resolve(clean); });
      } catch (e) {
        resolve(clean);
      }
    });
  }

  function addToAllowlist(host) {
    return load().then(function (s) {
      s.userAllowlist.push(String(host || "").trim().toLowerCase());
      return save(s);
    });
  }

  function removeFromAllowlist(host) {
    var target = String(host || "").trim().toLowerCase();
    return load().then(function (s) {
      s.userAllowlist = s.userAllowlist.filter(function (h) { return h !== target; });
      return save(s);
    });
  }

  function thresholds(settings) {
    return {
      suspicious: settings.suspiciousThreshold,
      dangerous: settings.dangerousThreshold
    };
  }

  var api = {
    STORAGE_KEY: STORAGE_KEY,
    DEFAULTS: DEFAULTS,
    normalize: normalize,
    load: load,
    save: save,
    addToAllowlist: addToAllowlist,
    removeFromAllowlist: removeFromAllowlist,
    thresholds: thresholds
  };

  if (typeof module === "object" && module.exports) {
    module.exports = api;
  } else {
    root.AIPhishSettings = api;
  }
})(typeof self !== "undefined" ? self : this);
