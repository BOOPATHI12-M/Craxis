// shared/api.js - client for the local Craxis Flask backend.
// Every call is best-effort: failures resolve to null so the extension keeps
// working with URL and page analysis when the backend is offline.

(function (root) {
  "use strict";

  var DEFAULT_BACKEND = "http://127.0.0.1:5000";
  var aiCache = new Map();
  var CACHE_TTL_MS = 60 * 1000;

  function baseUrl(settings) {
    return (settings && settings.backendUrl ? settings.backendUrl : DEFAULT_BACKEND).replace(/\/+$/, "");
  }

  function fetchJson(url, options, timeoutMs) {
    var controller = new AbortController();
    var timer = setTimeout(function () { controller.abort(); }, timeoutMs);
    var opts = Object.assign({}, options, { signal: controller.signal });
    return fetch(url, opts)
      .then(function (resp) {
        clearTimeout(timer);
        if (!resp.ok) return null;
        return resp.json();
      })
      .catch(function () {
        clearTimeout(timer);
        return null;
      });
  }

  /** POST /predict. Returns the prediction object or null. */
  function predict(url, settings, timeoutMs) {
    if (!url || typeof url !== "string") return Promise.resolve(null);
    var useIntel = !!(settings && settings.useIntel);
    var key = baseUrl(settings) + "|e|" + (useIntel ? "i|" : "n|") + url;
    var hit = aiCache.get(key);
    if (hit && Date.now() - hit.ts < CACHE_TTL_MS) return Promise.resolve(hit.data);

    return fetchJson(
      baseUrl(settings) + "/predict",
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: url, intel: useIntel, explain: true })
      },
      timeoutMs || 3500
    ).then(function (data) {
      if (data && data.prediction && typeof data.ai_risk_score === "number") {
        aiCache.set(key, { ts: Date.now(), data: data });
        if (aiCache.size > 200) aiCache.delete(aiCache.keys().next().value);
        return data;
      }
      return null;
    });
  }

  /** GET /health. Resolves to { ok: boolean, data }. */
  function health(settings, timeoutMs) {
    return fetchJson(baseUrl(settings) + "/health", { method: "GET" }, timeoutMs || 2000).then(function (data) {
      return { ok: !!(data && data.status === "ok"), data: data };
    });
  }

  /** GET /model-info. Returns the object or null. */
  function modelInfo(settings, timeoutMs) {
    return fetchJson(baseUrl(settings) + "/model-info", { method: "GET" }, timeoutMs || 2500);
  }

  var api = { predict: predict, health: health, modelInfo: modelInfo, baseUrl: baseUrl };

  if (typeof module === "object" && module.exports) {
    module.exports = api;
  } else {
    root.AIPhishApi = api;
  }
})(typeof self !== "undefined" ? self : this);
