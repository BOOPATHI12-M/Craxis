// dashboard.js - Craxis Security Intelligence Dashboard (Level 15)

document.addEventListener("DOMContentLoaded", () => {
  const emptyState = document.getElementById("emptyState");
  const dashboardContent = document.getElementById("dashboardContent");
  const closeBtn = document.getElementById("closeBtn");

  // Load scan history from Chrome Local Storage API
  loadDashboardData();

  function sanitizeHistoryEntry(item) {
    if (!item || typeof item !== "object") return null;
    if (!item.url || typeof item.url !== "string") return null;

    let rawScore = typeof item.riskScore === "number" && !isNaN(item.riskScore) ? item.riskScore : 0;
    rawScore = Math.min(Math.max(Math.round(rawScore), 0), 100);

    let classif = (item.classification || "").toUpperCase();
    if (classif !== "SAFE" && classif !== "SUSPICIOUS" && classif !== "DANGEROUS") {
      if (rawScore >= 60) classif = "DANGEROUS";
      else if (rawScore >= 30) classif = "SUSPICIOUS";
      else classif = "SAFE";
    }

    let host = item.hostname;
    if (!host || typeof host !== "string") {
      try {
        host = new URL(item.url).hostname || item.url;
      } catch (e) {
        host = item.url;
      }
    }

    return {
      ...item,
      url: item.url,
      hostname: host,
      riskScore: rawScore,
      classification: classif,
      formattedTime: item.formattedTime || item.timestamp || "Recently Scanned",
      reasons: Array.isArray(item.reasons) ? item.reasons : ["No suspicious indicators detected."],
      aiPrediction: item.aiPrediction || "N/A"
    };
  }

  function loadDashboardData() {
    if (!chrome.storage || !chrome.storage.local) {
      showEmptyState();
      return;
    }

    chrome.storage.local.get(["aiphish_scan_history"], (data) => {
      if (chrome.runtime.lastError) {
        console.error("Error reading scan history for dashboard:", chrome.runtime.lastError);
        showEmptyState();
        return;
      }

      const rawList = Array.isArray(data.aiphish_scan_history) ? data.aiphish_scan_history : [];
      const history = rawList.map(sanitizeHistoryEntry).filter((item) => item !== null);

      if (history.length === 0) {
        showEmptyState();
        return;
      }

      showDashboardContent();
      renderDashboard(history);
    });
  }

  function showEmptyState() {
    if (emptyState) emptyState.classList.remove("hidden");
    if (dashboardContent) dashboardContent.style.display = "none";
    document.getElementById("statTotalScans").textContent = "0";
    document.getElementById("statSafeScans").textContent = "0";
    document.getElementById("statSuspiciousScans").textContent = "0";
    document.getElementById("statDangerousScans").textContent = "0";
    document.getElementById("statAvgRisk").textContent = "0 / 100";
    document.getElementById("freshnessUpdated").textContent = new Date().toLocaleTimeString();
    document.getElementById("freshnessLatest").textContent = "No scans available.";
  }

  function showDashboardContent() {
    if (emptyState) emptyState.classList.add("hidden");
    if (dashboardContent) dashboardContent.style.display = "flex";
  }

  function renderDashboard(history) {
    const total = history.length;
    const safeCount = history.filter((h) => h.classification === "SAFE").length;
    const suspiciousCount = history.filter((h) => h.classification === "SUSPICIOUS").length;
    const dangerousCount = history.filter((h) => h.classification === "DANGEROUS").length;

    const totalRiskScore = history.reduce((sum, h) => sum + (typeof h.riskScore === "number" ? h.riskScore : 0), 0);
    const avgRisk = total > 0 ? Math.round(totalRiskScore / total) : 0;

    // 1. Render Top Summary Cards
    document.getElementById("statTotalScans").textContent = total;
    document.getElementById("statSafeScans").textContent = safeCount;
    document.getElementById("statSuspiciousScans").textContent = suspiciousCount;
    document.getElementById("statDangerousScans").textContent = dangerousCount;
    document.getElementById("statAvgRisk").textContent = `${avgRisk} / 100`;

    // 2. Render Risk Classification Distribution Bars
    renderClassificationDistribution(total, safeCount, suspiciousCount, dangerousCount);

    // 3. Render Risk Score Bins (0-20, 21-40, 41-60, 61-80, 81-100)
    renderRiskScoreBins(total, history);

    // 4. Render Chronological Risk Trend
    renderRiskTrend(history);

    // 5. Render AI Prediction Summary
    renderAISummary(history);

    // 6. Render Common Detection Indicators Frequency
    renderIndicatorFrequency(history);

    // 7. Render Top 5 Highest Risk Scans & Recent 5 Activity
    renderHighestRiskScans(history);
    renderRecentActivity(history);

    // 8. Render Security Overview & Freshness Timestamps
    document.getElementById("healthTotal").textContent = total;
    document.getElementById("healthRisky").textContent = suspiciousCount + dangerousCount;
    document.getElementById("healthSafe").textContent = safeCount;
    document.getElementById("healthAvg").textContent = `${avgRisk} / 100`;

    document.getElementById("freshnessUpdated").textContent = new Date().toLocaleTimeString("en-US", {
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
      hour12: true
    });

    const latestScan = history[0];
    document.getElementById("freshnessLatest").textContent = latestScan ? (latestScan.formattedTime || latestScan.timestamp) : "No scans available.";
  }

  function renderClassificationDistribution(total, safe, suspicious, dangerous) {
    const container = document.getElementById("classDistBars");
    if (!container) return;
    container.innerHTML = "";

    const safePct = total > 0 ? ((safe / total) * 100).toFixed(1) : 0;
    const suspPct = total > 0 ? ((suspicious / total) * 100).toFixed(1) : 0;
    const dangPct = total > 0 ? ((dangerous / total) * 100).toFixed(1) : 0;

    const items = [
      { label: "🟢 SAFE (< 30)", count: safe, pct: safePct, color: "#34d399" },
      { label: "🟠 SUSPICIOUS (30-59)", count: suspicious, pct: suspPct, color: "#fde047" },
      { label: "🔴 DANGEROUS (60+)", count: dangerous, pct: dangPct, color: "#fca5a5" }
    ];

    items.forEach((item) => {
      const div = document.createElement("div");
      div.className = "bar-item";
      div.innerHTML = `
        <div class="bar-header">
          <span>${item.label}</span>
          <span><strong>${item.count}</strong> (${item.pct}%)</span>
        </div>
        <div class="progress-track">
          <div class="progress-fill" style="width: ${item.pct}%; background-color: ${item.color};"></div>
        </div>
      `;
      container.appendChild(div);
    });
  }

  function renderRiskScoreBins(total, history) {
    const container = document.getElementById("riskBinsBars");
    if (!container) return;
    container.innerHTML = "";

    const bins = { "0–20": 0, "21–40": 0, "41–60": 0, "61–80": 0, "81–100": 0 };

    history.forEach((h) => {
      const s = typeof h.riskScore === "number" ? h.riskScore : 0;
      if (s <= 20) bins["0–20"]++;
      else if (s <= 40) bins["21–40"]++;
      else if (s <= 60) bins["41–60"]++;
      else if (s <= 80) bins["61–80"]++;
      else bins["81–100"]++;
    });

    Object.keys(bins).forEach((rangeKey) => {
      const count = bins[rangeKey];
      const pct = total > 0 ? ((count / total) * 100).toFixed(1) : 0;
      const div = document.createElement("div");
      div.className = "bar-item";
      div.innerHTML = `
        <div class="bar-header">
          <span>Score Range <strong>${rangeKey}</strong></span>
          <span><strong>${count}</strong> (${pct}%)</span>
        </div>
        <div class="progress-track">
          <div class="progress-fill" style="width: ${pct}%; background-color: #a78bfa;"></div>
        </div>
      `;
      container.appendChild(div);
    });
  }

  function renderRiskTrend(history) {
    const container = document.getElementById("riskTrendBox");
    if (!container) return;
    container.innerHTML = "";

    if (history.length < 2) {
      container.innerHTML = `<p style="font-size: 0.85rem; color: #94a3b8; text-align: center;">Not enough scan data to display a trend. (Minimum 2 scans required)</p>`;
      return;
    }

    const trendItems = history.slice(0, 10).reverse();

    const dotsList = document.createElement("div");
    dotsList.className = "trend-dots-list";

    trendItems.forEach((item) => {
      const score = item.riskScore ?? 0;
      const heightPct = Math.max(score, 8);
      const isDangerous = score >= 60;
      const isSuspicious = score >= 30 && score < 60;
      const color = isDangerous ? "#ef4444" : isSuspicious ? "#f59e0b" : "#10b981";

      const col = document.createElement("div");
      col.className = "trend-col";

      const label = document.createElement("span");
      label.style.cssText = "font-size: 9px; font-weight: 700; color: " + color;
      label.textContent = score;

      const bar = document.createElement("div");
      bar.className = "trend-bar-fill";
      bar.style.cssText = `height: ${heightPct}%; background-color: ${color};`;

      const hostLabel = document.createElement("span");
      hostLabel.className = "trend-lbl";
      hostLabel.textContent = (item.hostname || "site").substring(0, 5);

      col.appendChild(label);
      col.appendChild(bar);
      col.appendChild(hostLabel);
      dotsList.appendChild(col);
    });

    container.appendChild(dotsList);
  }

  // Local and private-network addresses are never sent to the AI model.
  function isLocalUrl(url) {
    try {
      const h = new URL(url).hostname.toLowerCase().replace(/^\[|\]$/g, "");
      return h === "localhost" || h.endsWith(".localhost") || h === "::1" || /^127\./.test(h);
    } catch (e) {
      return false;
    }
  }

  // Older history entries have no aiStatus, so it is worked out from the data.
  function aiStatusOf(h) {
    const pred = (h.aiPrediction || "").toUpperCase();
    if (pred === "LEGITIMATE" || pred === "PHISHING") return "ok";
    if (h.aiStatus === "skipped_local" || h.aiStatus === "unavailable") return h.aiStatus;
    return isLocalUrl(h.url) ? "skipped_local" : "unavailable";
  }

  function renderAISummary(history) {
    let legit = 0;
    let phish = 0;
    let skipped = 0;
    let unavail = 0;

    history.forEach((h) => {
      const status = aiStatusOf(h);
      if (status === "ok") {
        if ((h.aiPrediction || "").toUpperCase() === "PHISHING") phish++;
        else legit++;
      } else if (status === "skipped_local") {
        skipped++;
      } else {
        unavail++;
      }
    });

    document.getElementById("aiLegitCount").textContent = legit;
    document.getElementById("aiPhishCount").textContent = phish;
    document.getElementById("aiSkippedCount").textContent = skipped;
    document.getElementById("aiUnavailCount").textContent = unavail;
  }

  function renderIndicatorFrequency(history) {
    const container = document.getElementById("indicatorsContainer");
    if (!container) return;
    container.innerHTML = "";

    const freqMap = {};

    history.forEach((h) => {
      if (Array.isArray(h.reasons)) {
        h.reasons.forEach((r) => {
          if (typeof r === "string" && r.trim()) {
            const cleanReason = r.replace(/^\+\d+\s*/, "").trim();
            freqMap[cleanReason] = (freqMap[cleanReason] || 0) + 1;
          }
        });
      }
    });

    const sorted = Object.keys(freqMap)
      .map((k) => ({ text: k, count: freqMap[k] }))
      .sort((a, b) => b.count - a.count);

    if (sorted.length === 0) {
      container.innerHTML = `<p style="font-size: 0.85rem; color: #94a3b8;">No detection indicators recorded yet.</p>`;
      return;
    }

    sorted.slice(0, 6).forEach((item) => {
      const row = document.createElement("div");
      row.className = "indicator-row";
      row.innerHTML = `
        <span><span style="color: #f59e0b; margin-right: 6px;">•</span> ${escapeHTML(item.text)}</span>
        <span class="tc-badge" style="background: #2a1f5c; color: #a78bfa; padding: 2px 8px; border-radius: 4px; font-weight: 700;">Occurrences: ${item.count}</span>
      `;
      container.appendChild(row);
    });
  }

  function renderHighestRiskScans(history) {
    const container = document.getElementById("highestRiskList");
    if (!container) return;
    container.innerHTML = "";

    const sorted = [...history].sort((a, b) => (b.riskScore || 0) - (a.riskScore || 0));

    sorted.slice(0, 5).forEach((item, idx) => {
      const isDangerous = item.classification === "DANGEROUS";
      const isSuspicious = item.classification === "SUSPICIOUS";
      const color = isDangerous ? "#fca5a5" : isSuspicious ? "#fde047" : "#34d399";

      const div = document.createElement("div");
      div.className = "site-item";
      div.innerHTML = `
        <div>
          <div class="site-host">${idx + 1}. ${escapeHTML(item.hostname || item.url)}</div>
          <div class="site-url-sub">${escapeHTML(item.url)}</div>
        </div>
        <div style="text-align: right;">
          <strong style="color: ${color}; font-size: 0.95rem;">${item.riskScore} / 100</strong><br>
          <small style="color: ${color}; font-weight: 700;">${item.classification}</small>
        </div>
      `;
      container.appendChild(div);
    });
  }

  function renderRecentActivity(history) {
    const container = document.getElementById("recentActivityList");
    if (!container) return;
    container.innerHTML = "";

    history.slice(0, 5).forEach((item) => {
      const isDangerous = item.classification === "DANGEROUS";
      const isSuspicious = item.classification === "SUSPICIOUS";
      const color = isDangerous ? "#fca5a5" : isSuspicious ? "#fde047" : "#34d399";

      const div = document.createElement("div");
      div.className = "site-item";
      div.innerHTML = `
        <div>
          <div class="site-host">${escapeHTML(item.hostname || item.url)}</div>
          <div class="site-url-sub">${escapeHTML(item.formattedTime || item.timestamp)}</div>
        </div>
        <div style="text-align: right;">
          <strong style="color: ${color};">${item.riskScore} / 100</strong><br>
          <small style="color: ${color}; font-weight: 700;">${item.classification}</small>
        </div>
      `;
      container.appendChild(div);
    });
  }

  function escapeHTML(str) {
    if (typeof str !== "string") return String(str || "Unavailable");
    return str.replace(/[&<>'"]/g, (tag) => ({
      "&": "&amp;",
      "<": "&lt;",
      ">": "&gt;",
      "'": "&#39;",
      '"': "&quot;"
    }[tag] || tag));
  }

  if (closeBtn) {
    closeBtn.onclick = () => window.close();
  }
});
