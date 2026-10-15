// Cross-language parity: the JavaScript rules and the Python feature extractor
// must agree on brand detection, registrable domains and keyword lists.

const test = require("node:test");
const assert = require("node:assert/strict");
const path = require("node:path");
const { spawnSync } = require("node:child_process");

const ROOT = path.resolve(__dirname, "..", "..");
const Scoring = require(path.join(ROOT, "shared", "scoring.js"));

const HOSTS = [
  "paypal.com", "www.paypal.com", "paypal-secure-login.com", "paypa1.com", "paypa1-login.top",
  "rnicrosoft.com", "microsoft.com", "login.microsoftonline.com", "amaz0n-support.net", "amazon.co.uk",
  "goggle.com", "google.com", "phase.com", "chase.com", "chase-verify.net", "applesauce.com",
  "apple-id-support.com", "icloud-unlock.xyz", "netflix-billing.com", "my-account-center.com",
  "a.b.example.co.uk", "example.com", "github.io", "someone.github.io", "bank-of-america.com",
  "fedex-tracking.top", "dhl.de", "usps-delivery.info", "127.0.0.1", "binance-wallet.io"
];

function pythonResults(hosts) {
  const code = [
    "import json, sys",
    `sys.path.insert(0, ${JSON.stringify(path.join(ROOT, "ml"))})`,
    "from feature_extractor import detect_brand_abuse, registrable_domain, CONFIG",
    "hosts = json.loads(sys.stdin.read())",
    "out = {h: {'brand': detect_brand_abuse(h), 'reg': registrable_domain(h)} for h in hosts}",
    "print(json.dumps(out))"
  ].join("\n");
  const run = spawnSync(process.env.PYTHON || "python", ["-I", "-c", code], {
    input: JSON.stringify(hosts),
    encoding: "utf8"
  });
  if (run.status !== 0) throw new Error("Python failed: " + run.stderr);
  return JSON.parse(run.stdout);
}

test("brand detection and registrable domains match the Python implementation", () => {
  const py = pythonResults(HOSTS);
  for (const host of HOSTS) {
    assert.deepEqual(Scoring.detectBrandAbuse(host), py[host].brand, `brand mismatch for ${host}`);
    assert.equal(Scoring.registrableDomain(host), py[host].reg, `registrable mismatch for ${host}`);
  }
});

test("keyword list is a single shared list", () => {
  const run = spawnSync(
    process.env.PYTHON || "python",
    ["-I", "-c", `import sys; sys.path.insert(0, ${JSON.stringify(path.join(ROOT, "ml"))});` +
      "from feature_extractor import SUSPICIOUS_KEYWORDS, SHORTENER_DOMAINS; import json;" +
      "print(json.dumps([SUSPICIOUS_KEYWORDS, SHORTENER_DOMAINS]))"],
    { encoding: "utf8" }
  );
  assert.equal(run.status, 0, run.stderr);
  const [keywords, shorteners] = JSON.parse(run.stdout);
  assert.deepEqual(keywords, Scoring.CONFIG.keywords);
  assert.deepEqual(shorteners, Scoring.CONFIG.shorteners);
});
