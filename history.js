// history.js - Craxis Security Scan History Dashboard (Level 15)

document.addEventListener("DOMContentLoaded", () => {
  let allHistory = [];
  let currentFilter = "ALL";
  let searchQuery = "";

  const historyGrid = document.getElementById("historyGrid");
  const emptyState = document.getElementById("emptyState");
  const searchInput = document.getElementById("searchInput");
  const tabBtns = document.querySelectorAll(".tab-btn");

  const countAll = document.getElementById("countAll");
  const countSafe = document.getElementById("countSafe");
  const countSuspicious = document.getElementById("countSuspicious");
  const countDangerous = document.getElementById("countDangerous");

  const detailModal = document.getElementById("detailModal");
  const modalBody = document.getElementById("modalBody");
  const closeModalBtn = document.getElementById("closeModalBtn");

  const clearBtn = document.getElementById("clearBtn");
  const clearModal = document.getElementById("clearModal");
  const cancelClearBtn = document.getElementById("cancelClearBtn");
  const confirmClearBtn = document.getElementById("confirmClearBtn");
  const closeBtn = document.getElementById("closeBtn");

  // Load Scan History from Chrome Storage API
  loadHistory();

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
      aiPrediction: item.aiPrediction || "N/A",
      aiStatus: item.aiStatus || ""
    };
  }

  function loadHistory() {
    if (!chrome.storage || !chrome.storage.local) {
      alert("Chrome Extension Storage API is unavailable.");
      return;
    }

    chrome.storage.local.get(["aiphish_scan_history"], (data) => {
      if (chrome.runtime.lastError) {
        console.error("Error reading scan history:", chrome.runtime.lastError);
        return;
      }

      const rawList = Array.isArray(data.aiphish_scan_history) ? data.aiphish_scan_history : [];
      allHistory = rawList.map(sanitizeHistoryEntry).filter((item) => item !== null);

      updateCounts();
      renderGrid();
      openRequestedDetails();
    });
  }

  // history.html?details=<address> opens that scan's details automatically.
  function openRequestedDetails() {
    const wanted = new URLSearchParams(window.location.search).get("details");
    if (!wanted) return;

    let match = allHistory.find((h) => h.url === wanted);
    if (!match) {
      let host = "";
      try {
        host = new URL(wanted).hostname;
      } catch (e) {
        host = "";
      }
      match = allHistory.find((h) => host && h.hostname === host);
      if (!match && host && searchInput) {
        searchInput.value = host;
        searchQuery = host;
        renderGrid();
      }
    }
    if (match) openDetailsModal(match);
  }

  function updateCounts() {
    const total = allHistory.length;
    const safe = allHistory.filter((h) => h.classification === "SAFE").length;
    const suspicious = allHistory.filter((h) => h.classification === "SUSPICIOUS").length;
    const dangerous = allHistory.filter((h) => h.classification === "DANGEROUS").length;

    if (countAll) countAll.textContent = total;
    if (countSafe) countSafe.textContent = safe;
    if (countSuspicious) countSuspicious.textContent = suspicious;
    if (countDangerous) countDangerous.textContent = dangerous;
  }

  function renderGrid() {
    historyGrid.innerHTML = "";

    const filtered = allHistory.filter((item) => {
      if (currentFilter !== "ALL" && item.classification !== currentFilter) {
        return false;
      }
      if (searchQuery.trim() !== "") {
        const q = searchQuery.toLowerCase().trim();
        const host = (item.hostname || "").toLowerCase();
        const url = (item.url || "").toLowerCase();
        return host.includes(q) || url.includes(q);
      }
      return true;
    });

    if (filtered.length === 0) {
      emptyState.classList.remove("hidden");
      historyGrid.style.display = "none";
      return;
    }

    emptyState.classList.add("hidden");
    historyGrid.style.display = "grid";

    filtered.forEach((item) => {
      const card = createCardElement(item);
      historyGrid.appendChild(card);
    });
  }

  function createCardElement(item) {
    const card = document.createElement("div");
    card.className = "card";

    const isDangerous = item.classification === "DANGEROUS";
    const isSuspicious = item.classification === "SUSPICIOUS";
    const badgeClass = isDangerous ? "badge-dangerous" : isSuspicious ? "badge-suspicious" : "badge-safe";
    const badgeIcon = isDangerous ? "🔴 " : isSuspicious ? "🟠 " : "🟢 ";

    const header = document.createElement("div");
    header.className = "card-header";

    const titleBox = document.createElement("div");
    const h2 = document.createElement("div");
    h2.className = "hostname";
    h2.textContent = item.hostname || item.url || "Unknown Webpage";

    const sub = document.createElement("div");
    sub.className = "url-sub";
    sub.textContent = item.url || "";

    titleBox.appendChild(h2);
    titleBox.appendChild(sub);

    const badge = document.createElement("span");
    badge.className = `badge ${badgeClass}`;
    badge.textContent = `${badgeIcon}${item.classification}`;

    header.appendChild(titleBox);
    header.appendChild(badge);
    card.appendChild(header);

    const scoreRow = document.createElement("div");
    scoreRow.className = "score-row";

    const scoreSpan = document.createElement("span");
    scoreSpan.innerHTML = `Risk Score: <strong style="color: ${isDangerous ? '#fca5a5' : isSuspicious ? '#fde047' : '#34d399'};">${item.riskScore} / 100</strong>`;

    const timeSpan = document.createElement("span");
    timeSpan.className = "time-stamp";
    timeSpan.textContent = item.formattedTime || "Recently Scanned";

    scoreRow.appendChild(scoreSpan);
    scoreRow.appendChild(timeSpan);
    card.appendChild(scoreRow);

    const viewBtn = document.createElement("button");
    viewBtn.className = "detail-btn";
    viewBtn.textContent = "View Details";
    viewBtn.onclick = () => openDetailsModal(item);

    card.appendChild(viewBtn);

    return card;
  }

  // Explains why a scan has no AI prediction instead of showing a bare "N/A".
  function describeAI(item) {
    const pred = (item.aiPrediction || "").toUpperCase();
    if (pred === "LEGITIMATE" || pred === "PHISHING") return item.aiPrediction;
    if (item.aiStatus === "skipped_local") return "Not applied (local address)";
    if (item.aiStatus === "unavailable") return "Unavailable (AI server did not answer)";
    let local = false;
    try {
      const h = new URL(item.url).hostname.toLowerCase();
      local = h === "localhost" || /^127\./.test(h) || /^10\./.test(h) || /^192\.168\./.test(h);
    } catch (e) {
      local = false;
    }
    return local ? "Not applied (local address)" : "Unavailable (AI server did not answer)";
  }

  function openDetailsModal(item) {
    modalBody.innerHTML = "";

    const isDangerous = item.classification === "DANGEROUS";
    const isSuspicious = item.classification === "SUSPICIOUS";
    const color = isDangerous ? "#fca5a5" : isSuspicious ? "#fde047" : "#34d399";

    const summaryBox = document.createElement("div");
    summaryBox.style.cssText = "background: #0b0b1a; padding: 1rem; border-radius: 6px; border: 1px solid #2a2a47; display: flex; flex-direction: column; gap: 0.5rem;";
    summaryBox.innerHTML = `
      <div><span>Website URL:</span> <strong style="color: #a78bfa; word-break: break-all;">${escapeHTML(item.url)}</strong></div>
      <div><span>Domain Hostname:</span> <strong>${escapeHTML(item.hostname)}</strong></div>
      <div><span>Classification:</span> <strong style="color: ${color};">${item.classification}</strong></div>
      <div><span>Risk Score:</span> <strong style="color: ${color};">${item.riskScore} / 100</strong></div>
      <div><span>Scanned Time:</span> <strong>${escapeHTML(item.formattedTime || item.timestamp)}</strong></div>
      <div><span>AI Prediction:</span> <strong>${escapeHTML(describeAI(item))}</strong></div>
    `;

    const scoreBox = document.createElement("div");
    scoreBox.style.cssText = "background: #0b0b1a; padding: 0.75rem; border-radius: 6px; border: 1px solid #2a2a47; display: grid; grid-template-columns: repeat(3, 1fr); gap: 0.5rem; text-align: center;";
    scoreBox.innerHTML = `
      <div><small style="color: #94a3b8;">URL Score (30%)</small><br><strong>${item.urlScore ?? "Unavailable"}</strong></div>
      <div><small style="color: #94a3b8;">Page Score (20%)</small><br><strong>${item.webpageScore ?? "Unavailable"}</strong></div>
      <div><small style="color: #94a3b8;">AI Score (50%)</small><br><strong>${item.aiScore ?? "Unavailable"}</strong></div>
    `;

    const reasonsTitle = document.createElement("h4");
    reasonsTitle.style.cssText = "color: #a78bfa; margin-top: 0.5rem;";
    reasonsTitle.textContent = "Detection Reasons:";

    const reasonsList = document.createElement("ul");
    reasonsList.style.cssText = "list-style: none; display: flex; flex-direction: column; gap: 0.35rem; background: #0b0b1a; padding: 0.75rem; border-radius: 6px; border: 1px solid #2a2a47;";

    if (Array.isArray(item.reasons) && item.reasons.length > 0) {
      item.reasons.forEach((r) => {
        const li = document.createElement("li");
        li.innerHTML = `<span style="color: #f59e0b;">•</span> ${escapeHTML(r)}`;
        reasonsList.appendChild(li);
      });
    } else {
      const li = document.createElement("li");
      li.textContent = "• No suspicious indicators recorded.";
      reasonsList.appendChild(li);
    }

    modalBody.appendChild(summaryBox);
    modalBody.appendChild(scoreBox);
    modalBody.appendChild(reasonsTitle);
    modalBody.appendChild(reasonsList);

    detailModal.classList.remove("hidden");
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

  tabBtns.forEach((btn) => {
    btn.addEventListener("click", () => {
      tabBtns.forEach((b) => {
        b.classList.remove("active");
        b.setAttribute("aria-pressed", "false");
      });
      btn.classList.add("active");
      btn.setAttribute("aria-pressed", "true");
      currentFilter = btn.getAttribute("data-filter") || "ALL";
      renderGrid();
    });
  });

  if (searchInput) {
    searchInput.addEventListener("input", (e) => {
      searchQuery = e.target.value;
      renderGrid();
    });
  }

  if (closeModalBtn) {
    closeModalBtn.onclick = () => detailModal.classList.add("hidden");
  }

  if (clearBtn) {
    clearBtn.onclick = () => clearModal.classList.remove("hidden");
  }
  if (cancelClearBtn) {
    cancelClearBtn.onclick = () => clearModal.classList.add("hidden");
  }
  if (confirmClearBtn) {
    confirmClearBtn.onclick = () => {
      chrome.storage.local.remove(["aiphish_scan_history"], () => {
        allHistory = [];
        clearModal.classList.add("hidden");
        updateCounts();
        renderGrid();
      });
    };
  }

  if (closeBtn) {
    closeBtn.onclick = () => window.close();
  }
});
