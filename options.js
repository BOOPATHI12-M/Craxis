// options.js - AI Phishing Guard settings page.

(function () {
  "use strict";

  var Settings = self.AIPhishSettings;
  var Api = self.AIPhishApi;

  var els = {
    autoScan: document.getElementById("autoScan"),
    blockDangerous: document.getElementById("blockDangerous"),
    suspiciousThreshold: document.getElementById("suspiciousThreshold"),
    dangerousThreshold: document.getElementById("dangerousThreshold"),
    backendUrl: document.getElementById("backendUrl"),
    useIntel: document.getElementById("useIntel"),
    allowlistInput: document.getElementById("allowlistInput"),
    allowlist: document.getElementById("allowlist"),
    saveStatus: document.getElementById("saveStatus"),
    backendStatus: document.getElementById("backendStatus")
  };

  var current = Settings.normalize(null);

  function setStatus(el, text, kind) {
    el.textContent = text;
    el.className = "status" + (kind ? " " + kind : "");
  }

  function renderAllowlist() {
    els.allowlist.textContent = "";
    if (current.userAllowlist.length === 0) {
      var empty = document.createElement("li");
      empty.textContent = "No trusted sites yet.";
      els.allowlist.appendChild(empty);
      return;
    }
    current.userAllowlist.forEach(function (host) {
      var li = document.createElement("li");
      var label = document.createElement("span");
      label.textContent = host;
      var remove = document.createElement("button");
      remove.type = "button";
      remove.textContent = "Remove";
      remove.addEventListener("click", function () {
        current.userAllowlist = current.userAllowlist.filter(function (h) { return h !== host; });
        renderAllowlist();
      });
      li.appendChild(label);
      li.appendChild(remove);
      els.allowlist.appendChild(li);
    });
  }

  function render() {
    els.autoScan.checked = current.autoScan;
    els.blockDangerous.checked = current.blockDangerous;
    els.suspiciousThreshold.value = current.suspiciousThreshold;
    els.dangerousThreshold.value = current.dangerousThreshold;
    els.backendUrl.value = current.backendUrl;
    els.useIntel.checked = current.useIntel;
    renderAllowlist();
  }

  function readForm() {
    return Settings.normalize({
      autoScan: els.autoScan.checked,
      blockDangerous: els.blockDangerous.checked,
      suspiciousThreshold: els.suspiciousThreshold.value,
      dangerousThreshold: els.dangerousThreshold.value,
      backendUrl: els.backendUrl.value,
      useIntel: els.useIntel.checked,
      userAllowlist: current.userAllowlist
    });
  }

  document.getElementById("addAllowBtn").addEventListener("click", function () {
    var raw = els.allowlistInput.value.trim().toLowerCase();
    var host = raw;
    try {
      host = new URL(/^https?:\/\//.test(raw) ? raw : "https://" + raw).hostname;
    } catch (e) {
      host = "";
    }
    if (!host) {
      setStatus(els.saveStatus, "Enter a valid domain such as example.com.", "bad");
      return;
    }
    if (current.userAllowlist.indexOf(host) === -1) current.userAllowlist.push(host);
    els.allowlistInput.value = "";
    renderAllowlist();
  });

  document.getElementById("saveBtn").addEventListener("click", function () {
    var form = readForm();
    var thresholdsChanged =
      Number(els.suspiciousThreshold.value) !== form.suspiciousThreshold ||
      Number(els.dangerousThreshold.value) !== form.dangerousThreshold;
    Settings.save(form).then(function (saved) {
      current = saved;
      render();
      setStatus(
        els.saveStatus,
        thresholdsChanged ? "Saved. Thresholds were adjusted to valid values." : "Saved.",
        "ok"
      );
    });
  });

  document.getElementById("resetBtn").addEventListener("click", function () {
    var keep = current.userAllowlist;
    current = Settings.normalize({ userAllowlist: keep });
    render();
    setStatus(els.saveStatus, "Defaults restored. Click Save to apply.", "");
  });

  document.getElementById("testBackendBtn").addEventListener("click", function () {
    var form = readForm();
    setStatus(els.backendStatus, "Testing...", "");
    Api.health(form, 3000).then(function (res) {
      if (res.ok) {
        var version = res.data && res.data.version ? " (model " + res.data.version + ")" : "";
        setStatus(els.backendStatus, "Connected" + version, "ok");
      } else {
        setStatus(els.backendStatus, "Backend not reachable at " + form.backendUrl, "bad");
      }
    });
  });

  Settings.load().then(function (loaded) {
    current = loaded;
    render();
  });
})();
