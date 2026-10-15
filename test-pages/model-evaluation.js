// model-evaluation.js - ML model evaluation dashboard.
// External file (not inline) so the page also works when opened as a
// chrome-extension:// page, where inline scripts are blocked by the CSP.
//
// Data sources, in order:
//   1. the backend API   http://127.0.0.1:5000/api/model-evaluation
//   2. the bundled file  ../ml/evaluation_results.json  (works from the extension)

document.addEventListener("DOMContentLoaded", async () => {
  const setText = (id, value) => {
    const el = document.getElementById(id);
    if (el) el.textContent = value;
  };

  const pct = (value) => (typeof value === "number" ? (value * 100).toFixed(1) + "%" : "-");

  async function loadJson(url, timeoutMs) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
      const resp = await fetch(url, { signal: controller.signal });
      clearTimeout(timer);
      return resp.ok ? await resp.json() : null;
    } catch (e) {
      clearTimeout(timer);
      return null;
    }
  }

  let source = "backend API";
  let data = await loadJson("http://127.0.0.1:5000/api/model-evaluation", 3000);
  if (!data) {
    source = "bundled file ml/evaluation_results.json";
    data = await loadJson("../ml/evaluation_results.json", 3000);
  }

  if (!data) {
    setText("infoModel", "Evaluation results unavailable");
    setText("infoVersion", "Start the backend with: python ml/app.py");
    setText("infoDataset", "or run: python ml/evaluate_model.py");
    ["metricAcc", "metricPrec", "metricRec", "metricF1"].forEach((id) => setText(id, "n/a"));
    return;
  }

  const m = data.metrics || {};
  const cm = data.confusion_matrix || {};

  setText("metricAcc", pct(m.accuracy));
  setText("metricPrec", pct(m.precision));
  setText("metricRec", pct(m.recall));
  setText("metricF1", pct(m.f1_score));

  setText("cmTN", cm.true_negative ?? 0);
  setText("cmFP", cm.false_positive ?? 0);
  setText("cmFN", cm.false_negative ?? 0);
  setText("cmTP", cm.true_positive ?? 0);

  setText("infoModel", data.model || "Random Forest");
  setText("infoVersion", data.version || "unknown");
  setText("infoDataset", data.dataset || "unknown");
  setText("infoTotal", data.total_samples ?? "-");
  setText("infoTrain", data.training_samples ?? "-");
  setText("infoTest", data.testing_samples ?? "-");

  const dist = data.dataset_distribution || {};
  setText("distLegit", dist.legitimate ?? "-");
  setText("distPhish", dist.phishing ?? "-");

  const bars = document.getElementById("featureBarsContainer");
  if (bars && Array.isArray(data.top_features)) {
    bars.textContent = "";
    data.top_features.forEach((feat, idx) => {
      const value = ((feat.importance || 0) * 100).toFixed(1);

      const item = document.createElement("div");
      item.className = "feature-bar-item";

      const header = document.createElement("div");
      header.className = "feature-bar-header";
      const label = document.createElement("span");
      label.appendChild(document.createTextNode(`${idx + 1}. `));
      const name = document.createElement("strong");
      name.textContent = String(feat.name);
      label.appendChild(name);
      const amount = document.createElement("span");
      amount.textContent = `${value}%`;
      header.appendChild(label);
      header.appendChild(amount);

      const track = document.createElement("div");
      track.className = "progress-track";
      const fill = document.createElement("div");
      fill.className = "progress-fill";
      fill.style.width = `${value}%`;
      track.appendChild(fill);

      item.appendChild(header);
      item.appendChild(track);
      bars.appendChild(item);
    });
  }

  const note = document.getElementById("evalSourceNote");
  if (note) note.textContent = `Loaded from the ${source}.`;
});
