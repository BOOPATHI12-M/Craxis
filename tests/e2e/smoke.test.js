// End-to-end smoke test: loads the real extension in Chromium, starts the Flask
// backend, opens each local test page (TC01 to TC10) and checks the result.
//
// Usage:  node tests/e2e/smoke.test.js [--report]
// Needs:  npm install, npx playwright install chromium, Python deps installed.

const { chromium } = require("playwright");
const { spawn } = require("node:child_process");
const path = require("node:path");
const fs = require("node:fs");
const os = require("node:os");

const ROOT = path.resolve(__dirname, "..", "..");
const BACKEND = "http://127.0.0.1:5000";
const SUITE = require(path.join(ROOT, "test-pages", "test-config.js"));

const REPORT_ONLY = process.argv.includes("--report");

async function backendUp() {
  try {
    const res = await fetch(BACKEND + "/health");
    return res.ok;
  } catch (e) {
    return false;
  }
}

async function startBackend() {
  if (await backendUp()) return null;
  const python = process.env.PYTHON || "python";
  const child = spawn(python, [path.join(ROOT, "ml", "app.py")], {
    cwd: ROOT,
    stdio: ["ignore", "pipe", "pipe"],
    env: { ...process.env, PYTHONWARNINGS: "ignore" }
  });
  child.stderr.on("data", () => {});
  child.stdout.on("data", () => {});
  for (let i = 0; i < 60; i++) {
    if (await backendUp()) return child;
    await new Promise((r) => setTimeout(r, 500));
  }
  child.kill();
  throw new Error("Backend did not start.");
}

function allowed(expected) {
  return String(expected)
    .split(/\s+or\s+/i)
    .map((s) => s.trim().toUpperCase());
}

async function getServiceWorker(context) {
  let [worker] = context.serviceWorkers();
  if (!worker) worker = await context.waitForEvent("serviceworker", { timeout: 15000 });
  return worker;
}

async function readHistory(worker) {
  return worker.evaluate(async () => {
    const data = await chrome.storage.local.get("aiphish_scan_history");
    return data.aiphish_scan_history || [];
  });
}

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

/** Finds the tab for a target URL (or its warning page) and returns its scan. */
async function scanFor(worker, target) {
  return worker.evaluate(async (url) => {
    const tabs = await chrome.tabs.query({});
    const tab = tabs.find(
      (t) => t.url === url || (t.url && t.url.includes("warning.html") && t.url.includes(encodeURIComponent(url)))
    );
    if (!tab) return null;
    const scan = await getTabScan(tab.id);
    return { tabUrl: tab.url, scan };
  }, target);
}

async function waitForScan(worker, target, timeoutMs = 12000) {
  const end = Date.now() + timeoutMs;
  while (Date.now() < end) {
    const found = await scanFor(worker, target);
    if (found && found.scan && found.scan.status === "completed") return found;
    await sleep(400);
  }
  return null;
}

async function openAndWait(context, worker, target) {
  const page = await context.newPage();
  await page.goto(target, { waitUntil: "load", timeout: 15000 }).catch(() => {});
  const found = await waitForScan(worker, target);
  return { page, found };
}

async function runFlows(context, worker) {
  const checks = [];
  const check = (name, ok, detail) => checks.push({ name, ok: !!ok, detail: detail || "" });
  const extId = new URL(worker.url()).host;
  const tc10 = BACKEND + "/test-pages/critical-risk-test.html";
  const tc09 = BACKEND + "/test-pages/multiple-indicators-test.html";
  const tc01 = BACKEND + "/test-pages/safe-https-test.html";

  const reset = async (settings) => {
    await worker.evaluate(async (s) => {
      await chrome.storage.session.remove(["aiphish_bypass"]);
      await AIPhishSettings.save(s);
      settingsCache = AIPhishSettings.normalize(s);
    }, settings);
  };

  // Flow 1: dangerous page is blocked, then Proceed anyway works and is remembered.
  await reset({});
  let { page, found } = await openAndWait(context, worker, tc10);
  const blocked = page.url().includes("warning.html");
  check("Dangerous page shows the blocking warning page", blocked, page.url().slice(0, 80));
  if (blocked) {
    const shownTarget = await page.locator("#targetText").innerText();
    check("Warning page shows the blocked address", shownTarget === tc10, shownTarget);
    const reasons = await page.locator("#reasonsList li").count();
    check("Warning page lists reasons", reasons >= 1, String(reasons));
    await page.reload({ waitUntil: "domcontentloaded" });
    check("Proceed is disabled at first", await page.locator("#proceedBtn").isDisabled());
    await page.waitForFunction(() => !document.getElementById("proceedBtn").disabled, null, { timeout: 9000 });
    await page.locator("#proceedBtn").click();
    await page.waitForURL(tc10, { timeout: 10000 }).catch(() => {});
    check("Proceed anyway loads the original page", page.url() === tc10, page.url());
    await sleep(2500);
    const again = await context.newPage();
    await again.goto(tc10, { waitUntil: "load" }).catch(() => {});
    await sleep(2000);
    check("Proceed choice is remembered for the site", again.url() === tc10, again.url());
    await again.close();
  }
  await page.close();

  // Flow 2: blocking switched off -> banner instead of warning page.
  await reset({ blockDangerous: false });
  ({ page, found } = await openAndWait(context, worker, tc09));
  check("Blocking can be disabled in settings", !page.url().includes("warning.html"), page.url().slice(0, 80));
  check(
    "Dangerous result is still classified DANGEROUS",
    found && found.scan.result.statusLevel === "DANGEROUS",
    found ? found.scan.result.statusLevel : "no result"
  );
  await sleep(500);
  const banner = await page.locator("#aiphish-guard-root").count();
  check("In-page banner is shown when not blocking", banner === 1, String(banner));
  await page.close();

  // Flow 3: trusted site is never blocked and its score is capped.
  await reset({ userAllowlist: ["127.0.0.1"] });
  ({ page, found } = await openAndWait(context, worker, tc10));
  check("Trusted site is not blocked", !page.url().includes("warning.html"), page.url().slice(0, 80));
  check(
    "Trusted site is capped to SAFE",
    found && found.scan.result.statusLevel === "SAFE" && found.scan.result.trusted === "user",
    found ? `${found.scan.result.statusLevel} trusted=${found.scan.result.trusted}` : "no result"
  );
  await page.close();

  // Flow 4: local addresses get the AI answer too, shown but not counted in the score.
  await reset({});
  ({ page, found } = await openAndWait(context, worker, tc01));
  {
    const r = found && found.scan.result;
    check(
      "Local address shows the AI result but does not count it",
      r && r.hasAIData === true && r.aiAdvisory === true && r.aiContrib === 0 && r.urlWeight === 0.6,
      r ? JSON.stringify({ ai: r.hasAIData, advisory: r.aiAdvisory, contrib: r.aiContrib, urlWeight: r.urlWeight }) : "no result"
    );
  }
  await page.close();

  // Flow 6: permission requests. HTTPS is used because camera APIs do not exist
  // on insecure pages. Pages are served from the test itself through routing.
  const permCases = [
    { host: "perm-a.example.test", click: true, expect: (r) => r.reasons.length === 0 && r.kinds.includes("camera"),
      name: "Camera after a click on an ordinary page is not flagged",
      body: "<h1>Meeting</h1><button id=b>Start</button><script>document.getElementById('b').onclick=()=>navigator.mediaDevices.getUserMedia({video:true}).catch(()=>{});</script>" },
    { host: "perm-b.example.test", click: true, expect: (r) => r.reasons.some((x) => x.includes("should not need")),
      name: "Camera requested by a login page is flagged (+10)",
      body: "<form><input type=password></form><button id=b>Verify</button><script>document.getElementById('b').onclick=()=>navigator.mediaDevices.getUserMedia({video:true}).catch(()=>{});</script>" },
    { host: "perm-c.example.test", click: false, expect: (r) => r.reasons.some((x) => x.includes("without any user action")),
      name: "Location requested on load is flagged (+20)",
      body: "<h1>Weather</h1><script>navigator.geolocation.getCurrentPosition(()=>{},()=>{});</script>" },
    { host: "perm-d.example.test", click: false, expect: (r) => r.reasons.some((x) => x.includes("notifications")),
      name: "Notification request on load is flagged (+10)",
      body: "<h1>News</h1><script>Notification.requestPermission();</script>" },
    { host: "perm-e.example.test", click: false, expect: (r) => r.reasons.length === 0 && r.kinds.length === 0,
      name: "Ordinary page has no permission signal",
      body: "<h1>Hello</h1>" }
  ];
  for (const c of permCases) {
    const url = `https://${c.host}/`;
    const pg = await context.newPage();
    await pg.route(url, (route) => route.fulfill({ contentType: "text/html", body: `<!doctype html><title>${c.host}</title><body>${c.body}</body>` }));
    await pg.goto(url, { waitUntil: "load" }).catch(() => {});
    await sleep(1500);
    if (c.click) {
      await pg.click("#b");
      await sleep(500);
    }
    await sleep(4500);
    const res = await worker.evaluate(async (u) => {
      const tabs = await chrome.tabs.query({});
      const tab = tabs.find((t) => t.url === u);
      const scan = tab ? await getTabScan(tab.id) : null;
      const page = scan && scan.result && scan.result.pageResult;
      return page ? { reasons: page.reasons.filter((x) => /permission|access|notification|camera|microphone|asked|login page/i.test(x) && !/password field/.test(x)), kinds: (page.permissionRequests || []).map((x) => x.kind) } : null;
    }, url);
    check(c.name, res && c.expect(res), JSON.stringify(res));
    await pg.close();
  }

  // Flow 7: a private-network portal is analysed by the AI, with a per-website explanation.
  {
    const portal = "http://172.16.0.1:8090/httpclient.html";
    const pg = await context.newPage();
    await pg.route(portal, (route) => route.fulfill({
      contentType: "text/html",
      body: "<!doctype html><title>College Web Portal</title><form action='/login'><input name=u><input type=password name=p></form>"
    }));
    await pg.goto(portal, { waitUntil: "load" }).catch(() => {});
    const found = await waitForScan(worker, portal);
    const portalBlocked = pg.url().includes("warning.html");
    const res = found && found.scan.result;
    check("Private network address is analysed by the AI", res && res.hasAIData === true && res.aiSkipped === false,
      res ? JSON.stringify({ ai: res.hasAIData, skipped: res.aiSkipped }) : "no result");
    check("The AI answer is advisory there and the portal is not blocked",
      res && res.aiAdvisory === true && res.aiContrib === 0 && res.statusLevel !== "DANGEROUS" && !portalBlocked,
      res ? JSON.stringify({ advisory: res.aiAdvisory, contrib: res.aiContrib, level: res.statusLevel, final: res.finalScore }) : "no result");
    const feats = res && res.aiResult && res.aiResult.explanation ? res.aiResult.explanation.features : [];
    check("AI explanation lists parts of this address", feats.length > 0 && feats.every((f) => typeof f.effect_points === "number"),
      JSON.stringify(feats.slice(0, 2)));
    const details = await context.newPage();
    await details.goto(`chrome-extension://${extId}/history.html?details=${encodeURIComponent(portal)}`, { waitUntil: "load" });
    await sleep(1200);
    const modalText = await details.locator("#modalBody").innerText().catch(() => "");
    check("Scan details show the AI analysis", /AI analysis of this website/.test(modalText) && /pts/.test(modalText),
      modalText.replace(/\s+/g, " ").slice(0, 160));
    await details.close();
    await pg.close();
  }

  // Flow 5: extension pages load without script errors.
  for (const name of ["popup.html", "options.html", "history.html", "dashboard.html"]) {
    const ext = await context.newPage();
    const errors = [];
    ext.on("pageerror", (e) => errors.push(e.message));
    await ext.goto(`chrome-extension://${extId}/${name}`, { waitUntil: "load" });
    await sleep(800);
    check(`${name} loads without errors`, errors.length === 0, errors.join("; ").slice(0, 120));
    if (name === "options.html") {
      await ext.fill("#suspiciousThreshold", "25");
      await ext.fill("#dangerousThreshold", "70");
      await ext.click("#saveBtn");
      await sleep(600);
      const saved = await worker.evaluate(() => AIPhishSettings.load());
      check("Options page saves thresholds", saved.suspiciousThreshold === 25 && saved.dangerousThreshold === 70, JSON.stringify([saved.suspiciousThreshold, saved.dangerousThreshold]));
    }
    await ext.close();
  }
  await reset({});

  console.log("\nFlow checks");
  console.log("-".repeat(86));
  let failed = 0;
  for (const c of checks) {
    if (!c.ok) failed++;
    console.log(`${c.ok ? "PASS" : "FAIL"}  ${c.name}${c.ok ? "" : "  -> " + c.detail}`);
  }
  console.log(`${checks.length - failed}/${checks.length} flow checks passed`);
  return failed;
}

async function main() {
  const backend = await startBackend();
  const userDataDir = fs.mkdtempSync(path.join(os.tmpdir(), "aiphish-e2e-"));

  const context = await chromium.launchPersistentContext(userDataDir, {
    headless: false,
    args: [
      "--headless=new",
      `--disable-extensions-except=${ROOT}`,
      `--load-extension=${ROOT}`,
      "--no-first-run"
    ]
  });

  const results = [];
  let flowFailures = 0;
  try {
    const worker = await getServiceWorker(context);
    await worker.evaluate(() => chrome.storage.local.remove("aiphish_scan_history"));

    for (const tc of SUITE) {
      const target = BACKEND + tc.file;
      const page = await context.newPage();
      let blocked = false;
      try {
        await page.goto(target, { waitUntil: "load", timeout: 15000 });
      } catch (e) {
        // A blocked navigation is replaced by the warning page.
      }

      let entry = null;
      for (let i = 0; i < 40 && !entry; i++) {
        await new Promise((r) => setTimeout(r, 400));
        if (page.url().includes("warning.html")) blocked = true;
        const history = await readHistory(worker);
        entry = history.find((h) => h.url === target) || null;
        if (!entry && blocked && i > 10) break;
      }
      if (page.url().includes("warning.html")) blocked = true;

      const badge = await page
        .evaluate(() => {
          const root = document.getElementById("aiphish-guard-root");
          const el = root ? (root.shadowRoot || root) : null;
          return el ? el.textContent.replace(/\s+/g, " ").trim().slice(0, 90) : null;
        })
        .catch(() => null);

      results.push({
        id: tc.id,
        name: tc.name,
        expected: tc.expectedClassification,
        actual: entry ? entry.classification : "NO RESULT",
        score: entry ? entry.riskScore : null,
        url: entry ? entry.urlScore : null,
        page: entry ? entry.webpageScore : null,
        ai: entry ? entry.aiScore : null,
        blocked,
        badge
      });
      await page.close();
    }
    flowFailures = await runFlows(context, worker);
  } finally {
    await context.close();
    if (backend) backend.kill();
    fs.rmSync(userDataDir, { recursive: true, force: true });
  }

  console.log("\nID    Expected               Actual       Score  URL   Page  AI    Blocked");
  console.log("-".repeat(86));
  let failures = 0;
  for (const r of results) {
    const ok = allowed(r.expected).includes(String(r.actual).toUpperCase());
    if (!ok) failures++;
    console.log(
      `${r.id.padEnd(5)} ${String(r.expected).padEnd(22)} ${String(r.actual).padEnd(12)} ` +
        `${String(r.score).padEnd(6)} ${String(r.url).padEnd(5)} ${String(r.page).padEnd(5)} ` +
        `${String(r.ai).padEnd(5)} ${r.blocked ? "yes" : "no "}  ${ok ? "PASS" : "FAIL"}`
    );
  }
  console.log(`\n${results.length - failures}/${results.length} passed`);
  if (REPORT_ONLY) return 0;
  return failures === 0 && flowFailures === 0 ? 0 : 1;
}

main()
  .then((code) => process.exit(code))
  .catch((err) => {
    console.error(err);
    process.exit(2);
  });
