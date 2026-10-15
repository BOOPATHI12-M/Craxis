// warning.js - Craxis blocking page.
// All values come from the query string and are rendered with textContent.

(function () {
  "use strict";

  var PROCEED_DELAY_SECONDS = 5;

  var params = new URLSearchParams(window.location.search);
  var target = params.get("target") || "";
  var score = params.get("score") || "-";
  var reasons = [];
  try {
    var parsed = JSON.parse(params.get("reasons") || "[]");
    if (Array.isArray(parsed)) reasons = parsed.filter(function (r) { return typeof r === "string"; }).slice(0, 8);
  } catch (e) {
    reasons = [];
  }

  var targetIsValid = /^https?:\/\//i.test(target);
  var host = "";
  try {
    host = new URL(target).hostname.toLowerCase();
  } catch (e) {
    host = "";
  }

  document.getElementById("targetText").textContent = targetIsValid ? target : "Unknown address";
  document.getElementById("scoreText").textContent = String(score).replace(/[^0-9.]/g, "") || "-";

  var list = document.getElementById("reasonsList");
  if (reasons.length === 0) reasons = ["Multiple phishing indicators were detected."];
  reasons.forEach(function (reason) {
    var li = document.createElement("li");
    li.textContent = reason;
    list.appendChild(li);
  });

  var safetyBtn = document.getElementById("safetyBtn");
  var trustBtn = document.getElementById("trustBtn");
  var proceedBtn = document.getElementById("proceedBtn");

  function send(message) {
    return new Promise(function (resolve) {
      chrome.runtime.sendMessage(message, function (response) {
        resolve(response || { success: false });
      });
    });
  }

  safetyBtn.addEventListener("click", function () {
    send({ action: "GO_TO_SAFETY" });
  });

  trustBtn.addEventListener("click", function () {
    if (!host || !targetIsValid) return;
    trustBtn.disabled = true;
    send({ action: "TRUST_SITE", host: host }).then(function () {
      return send({ action: "PROCEED_ANYWAY", url: target });
    });
  });

  proceedBtn.addEventListener("click", function () {
    if (!targetIsValid) return;
    proceedBtn.disabled = true;
    send({ action: "PROCEED_ANYWAY", url: target });
  });

  if (!targetIsValid) {
    trustBtn.disabled = true;
    proceedBtn.textContent = "Proceed anyway";
    return;
  }

  // Short delay before "Proceed anyway" becomes available.
  var remaining = PROCEED_DELAY_SECONDS;
  var timer = setInterval(function () {
    remaining -= 1;
    if (remaining <= 0) {
      clearInterval(timer);
      proceedBtn.disabled = false;
      proceedBtn.textContent = "Proceed anyway";
    } else {
      proceedBtn.textContent = "Proceed anyway (" + remaining + ")";
    }
  }, 1000);
})();
