// evaluation.js - Developer evaluation table.
// External file with no inline event handlers, so it also works when the page
// is opened as a chrome-extension:// page.

document.addEventListener("DOMContentLoaded", () => {
  const tbody = document.getElementById("evalTableBody");
  const statTotal = document.getElementById("statTotal");
  const statPassed = document.getElementById("statPassed");
  const statFailed = document.getElementById("statFailed");
  const statPassRate = document.getElementById("statPassRate");
  if (!tbody || typeof TEST_SUITE_CONFIG === "undefined") return;

  const STORAGE_KEY = "aiphish_level10_eval";
  let savedData = {};
  try {
    savedData = JSON.parse(localStorage.getItem(STORAGE_KEY) || "{}");
  } catch (e) {
    savedData = {};
  }

  function cell(tr) {
    const td = document.createElement("td");
    tr.appendChild(td);
    return td;
  }

  function textInput(id, key, value, width) {
    const input = document.createElement("input");
    input.type = "text";
    input.value = value;
    input.dataset.id = id;
    input.dataset.key = key;
    if (width) input.style.width = width;
    return input;
  }

  function renderTable() {
    tbody.textContent = "";
    let passed = 0;
    let failed = 0;

    TEST_SUITE_CONFIG.forEach((test) => {
      const state = savedData[test.id] || {
        actual: test.expectedIndicator,
        score: "0 / 0 / 0 / 0",
        result: "PASS"
      };
      if (state.result === "PASS") passed++;
      else failed++;

      const tr = document.createElement("tr");

      const idCell = cell(tr);
      const idStrong = document.createElement("strong");
      idStrong.textContent = test.id;
      idCell.appendChild(idStrong);

      const nameCell = cell(tr);
      const nameStrong = document.createElement("strong");
      nameStrong.textContent = test.name;
      nameCell.appendChild(nameStrong);
      nameCell.appendChild(document.createElement("br"));
      const cat = document.createElement("small");
      cat.style.color = "#94a3b8";
      cat.textContent = test.category;
      nameCell.appendChild(cat);

      const expCell = cell(tr);
      const exp = document.createElement("small");
      exp.style.color = "#fde047";
      exp.textContent = test.expectedIndicator;
      expCell.appendChild(exp);

      cell(tr).appendChild(textInput(test.id, "actual", state.actual));
      cell(tr).appendChild(textInput(test.id, "score", state.score, "120px"));

      const select = document.createElement("select");
      select.dataset.id = test.id;
      select.dataset.key = "result";
      ["PASS", "FAIL"].forEach((value) => {
        const option = document.createElement("option");
        option.value = value;
        option.textContent = value;
        option.selected = state.result === value;
        select.appendChild(option);
      });
      cell(tr).appendChild(select);

      tbody.appendChild(tr);
    });

    statTotal.textContent = TEST_SUITE_CONFIG.length;
    statPassed.textContent = passed;
    statFailed.textContent = failed;
    statPassRate.textContent = `${((passed / TEST_SUITE_CONFIG.length) * 100).toFixed(1)}%`;
  }

  // One listener for every input and select in the table.
  tbody.addEventListener("change", (event) => {
    const el = event.target;
    const id = el.dataset && el.dataset.id;
    const key = el.dataset && el.dataset.key;
    if (!id || !key) return;
    if (!savedData[id]) savedData[id] = {};
    savedData[id][key] = el.value;
    renderTable();
  });

  document.getElementById("saveEvalBtn").addEventListener("click", () => {
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(savedData));
      alert("Evaluation state saved successfully.");
    } catch (e) {
      alert("Could not save: browser storage is unavailable.");
    }
  });

  renderTable();
});
