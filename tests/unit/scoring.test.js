// Unit tests for shared/scoring.js and shared/settings.js (no browser needed).
// Run: node --test tests/unit

const test = require("node:test");
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");

const ROOT = path.resolve(__dirname, "..", "..");
const Scoring = require(path.join(ROOT, "shared", "scoring.js"));
const Settings = require(path.join(ROOT, "shared", "settings.js"));
const CONFIG = Scoring.CONFIG;

const reasonsOf = (url) => Scoring.analyzeURL(url).reasons.join(" | ");

test("config.js is generated from config.json", () => {
  const json = JSON.parse(fs.readFileSync(path.join(ROOT, "shared", "config.json"), "utf8"));
  assert.deepEqual(CONFIG, json);
});

test("trusted domains never include shared hosting suffixes", () => {
  for (const domain of CONFIG.trusted_domains) {
    for (const suffix of CONFIG.shared_hosting_suffixes) {
      assert.notEqual(domain, suffix, `${domain} must not be trusted`);
      assert.ok(!domain.endsWith("." + suffix), `${domain} is on shared hosting ${suffix}`);
    }
  }
  assert.ok(CONFIG.trusted_domains.length >= 500);
});

test("clean https URL scores 0", () => {
  assert.equal(Scoring.analyzeURL("https://example.org/about").score, 0);
});

test("URL rules add the documented points", () => {
  assert.match(reasonsOf("http://example.org/"), /\+20 Website is not using HTTPS/);
  assert.match(reasonsOf("https://203.0.113.9/"), /\+30 URL uses an IP address/);
  assert.match(reasonsOf("https://user@example.org/"), /\+25 URL contains an @ symbol/);
  assert.match(reasonsOf("https://example.org/" + "a".repeat(120)), /\+15 URL is unusually long/);
  assert.match(reasonsOf("https://a.b.c.d.example.org/"), /\+15 URL contains an unusually large number of subdomains/);
  assert.match(reasonsOf("https://bit.ly/abc"), /\+15 URL uses a URL shortening service/);
  assert.match(reasonsOf("https://example.top/"), /\+10 Top-level domain \.top/);
  assert.match(reasonsOf("https://xn--pple-43d.com/"), /\+15 Hostname uses punycode/);
  assert.match(reasonsOf("https://a-b-c-d.example.org/"), /\+10 Hostname contains many hyphens/);
});

test("keyword in hostname scores more than keyword in path", () => {
  const host = Scoring.analyzeURL("https://login-example.org/").score;
  const pathOnly = Scoring.analyzeURL("https://example.org/login").score;
  assert.equal(host, 10);
  assert.equal(pathOnly, 3);
});

test("malformed URL scores 100", () => {
  assert.equal(Scoring.analyzeURL("not a url").score, 100);
});

test("score is capped at 100", () => {
  const worst = Scoring.analyzeURL("http://user@203.0.113.9/login/" + "x".repeat(120));
  assert.ok(worst.score <= 100);
  const boosted = Scoring.applyIntel({ score: 90, reasons: [], indicators: [], details: {} }, { domain_age_days: 1 });
  assert.equal(boosted.score, 100);
});

test("brand abuse: domains that use or imitate a brand", () => {
  const kinds = {
    "paypal-secure-login.com": "brand-in-domain",
    "paypa1.com": "homoglyph",
    "rnicrosoft.com": "homoglyph",
    "amaz0n-support.net": "homoglyph",
    "goggle.com": "typosquat"
  };
  for (const [host, kind] of Object.entries(kinds)) {
    const hit = Scoring.detectBrandAbuse(host);
    assert.ok(hit, `${host} should be flagged`);
    assert.equal(hit.kind, kind, host);
  }
});

test("brand abuse: legitimate domains are not flagged", () => {
  for (const host of ["paypal.com", "www.paypal.com", "mail.google.com", "phase.com", "applesauce.com", "chase.com", "login-update.org"]) {
    assert.equal(Scoring.detectBrandAbuse(host), null, host);
  }
});

test("brand abuse adds 25 points but is skipped for trusted domains", () => {
  assert.match(reasonsOf("https://paypal-secure.com/"), /\+25 Hostname uses the brand name "paypal"/);
  assert.equal(Scoring.analyzeURL("https://www.google.com/").details.brandAbuse, null);
});

test("registrableDomain handles multi-part suffixes", () => {
  assert.equal(Scoring.registrableDomain("a.b.example.co.uk"), "example.co.uk");
  assert.equal(Scoring.registrableDomain("www.example.com"), "example.com");
  assert.equal(Scoring.registrableDomain("127.0.0.1"), "127.0.0.1");
});

test("trustStatus", () => {
  assert.deepEqual(Scoring.trustStatus("https://www.google.com/", []), { trusted: true, source: "builtin" });
  assert.equal(Scoring.trustStatus("http://www.google.com/", []).trusted, false, "needs https");
  assert.equal(Scoring.trustStatus("https://sites.google.com/x", []).trusted, false, "shared hosting");
  assert.equal(Scoring.trustStatus("https://someone.github.io/", []).trusted, false);
  assert.equal(Scoring.trustStatus("https://x.example.org/", ["example.org"]).source, "user");
  assert.equal(Scoring.trustStatus("https://notexample.org/", ["example.org"]).trusted, false);
});

test("isLocalHost", () => {
  for (const h of ["localhost", "127.0.0.1", "192.168.1.5", "10.0.0.1", "172.16.0.9", "[::1]", "app.localhost"]) {
    assert.equal(Scoring.isLocalHost(h), true, h);
  }
  for (const h of ["8.8.8.8", "172.32.0.1", "example.com", "1.2.3.400", ""]) {
    assert.equal(Scoring.isLocalHost(h), false, h);
  }
});

test("classify uses default and custom thresholds", () => {
  assert.equal(Scoring.classify(29), "SAFE");
  assert.equal(Scoring.classify(30), "SUSPICIOUS");
  assert.equal(Scoring.classify(59), "SUSPICIOUS");
  assert.equal(Scoring.classify(60), "DANGEROUS");
  assert.equal(Scoring.classify(45, { suspicious: 20, dangerous: 40 }), "DANGEROUS");
});

test("score fusion weights for each available signal combination", () => {
  const u = { score: 40 };
  const p = { score: 20 };
  const a = { ai_risk_score: 80 };

  const all = Scoring.calculateCombinedScore("x", u, p, a);
  assert.equal(all.finalScore, Math.round(40 * 0.3 + 20 * 0.2 + 80 * 0.5));

  const urlAi = Scoring.calculateCombinedScore("x", u, null, a);
  assert.equal(urlAi.finalScore, Math.round(40 * 0.35 + 80 * 0.65));

  const urlPage = Scoring.calculateCombinedScore("x", u, p, null);
  assert.equal(urlPage.finalScore, Math.round(40 * 0.6 + 20 * 0.4));

  const urlOnly = Scoring.calculateCombinedScore("x", u, null, null);
  assert.equal(urlOnly.finalScore, 40);
  assert.equal(urlOnly.hasAIData, false);
});

test("corroboration lifts the score when every layer reports elevated risk", () => {
  const strong = Scoring.calculateCombinedScore("x", { score: 50 }, { score: 65 }, { ai_risk_score: 55 });
  assert.equal(strong.corroborated, true);
  assert.equal(strong.finalScore, 60);
  assert.equal(strong.statusLevel, "DANGEROUS");

  const mixed = Scoring.calculateCombinedScore("x", { score: 50 }, { score: 40 }, { ai_risk_score: 55 });
  assert.equal(mixed.corroborated, false);
  assert.notEqual(mixed.statusLevel, "DANGEROUS");

  const single = Scoring.calculateCombinedScore("x", { score: 90 }, null, null);
  assert.equal(single.corroborated, false, "one layer is not corroboration");
});

test("trusted sites are capped below the suspicious threshold", () => {
  const trust = { trusted: true, source: "user" };
  const r = Scoring.calculateCombinedScore("x", { score: 100 }, { score: 100 }, { ai_risk_score: 100 }, { trust });
  assert.equal(r.finalScore, CONFIG.thresholds.trusted_cap);
  assert.equal(r.statusLevel, "SAFE");
  assert.equal(r.trusted, "user");
  assert.equal(r.rawScore, 100);
});

test("custom thresholds change the classification", () => {
  const r = Scoring.calculateCombinedScore("x", { score: 50 }, null, null, {
    thresholds: { suspicious: 20, dangerous: 45 }
  });
  assert.equal(r.statusLevel, "DANGEROUS");
});

test("applyIntel adds points for new domains and bad certificates", () => {
  const base = { score: 10, reasons: [], indicators: [], details: {} };
  assert.equal(Scoring.applyIntel(base, { domain_age_days: 5 }).score, 35);
  assert.equal(Scoring.applyIntel(base, { domain_age_days: 60 }).score, 20);
  assert.equal(Scoring.applyIntel(base, { domain_age_days: 400 }).score, 10);
  assert.equal(Scoring.applyIntel(base, { cert: { valid: false } }).score, 25);
  assert.equal(Scoring.applyIntel(base, null), base);
  assert.equal(base.score, 10, "input must not be mutated");
});

test("collectReasons lists URL, page and AI reasons", () => {
  const result = Scoring.calculateCombinedScore(
    "https://x.test/",
    { score: 20, reasons: ["+20 Website is not using HTTPS"] },
    { score: 10, reasons: ["Page contains a password field"] },
    { ai_risk_score: 90, prediction: "PHISHING", phishing_probability: 0.9 }
  );
  const reasons = Scoring.collectReasons(result);
  assert.ok(reasons.some((r) => r.includes("HTTPS")));
  assert.ok(reasons.some((r) => r.includes("password")));
  assert.ok(reasons.some((r) => r.includes("PHISHING (90% probability)")));
});

test("settings.normalize validates and repairs values", () => {
  const defaults = Settings.normalize(null);
  assert.equal(defaults.backendUrl, "http://127.0.0.1:5000");
  assert.equal(defaults.suspiciousThreshold, 30);
  assert.equal(defaults.dangerousThreshold, 60);

  const bad = Settings.normalize({
    backendUrl: "javascript:alert(1)",
    suspiciousThreshold: 80,
    dangerousThreshold: 50,
    userAllowlist: ["Example.com", "example.com", "bad host!", ""]
  });
  assert.equal(bad.backendUrl, "http://127.0.0.1:5000");
  assert.equal(bad.suspiciousThreshold, 30);
  assert.equal(bad.dangerousThreshold, 60);
  assert.deepEqual(bad.userAllowlist, ["example.com"]);

  const custom = Settings.normalize({ backendUrl: "http://localhost:8000/", suspiciousThreshold: "25", dangerousThreshold: 70 });
  assert.equal(custom.backendUrl, "http://localhost:8000");
  assert.equal(custom.suspiciousThreshold, 25);
});
