// index.js - Local Test Center cards.
// External file (not inline) so the page also works when opened as a
// chrome-extension:// page, where inline scripts are blocked by the CSP.

document.addEventListener("DOMContentLoaded", () => {
  const grid = document.getElementById("testGrid");
  if (!grid || typeof TEST_SUITE_CONFIG === "undefined") {
    return;
  }

  const BACKEND = "http://127.0.0.1:5000";

  function addText(parent, tag, className, text) {
    const el = document.createElement(tag);
    if (className) el.className = className;
    el.textContent = text;
    parent.appendChild(el);
    return el;
  }

  TEST_SUITE_CONFIG.forEach((test) => {
    const targetUrl = test.file.startsWith("http")
      ? test.file
      : BACKEND + (test.file.startsWith("/") ? test.file : "/" + test.file);

    const card = document.createElement("div");
    card.className = "card";

    const top = document.createElement("div");
    addText(top, "div", "category-tag", test.category);
    const header = document.createElement("div");
    header.className = "card-header";
    addText(header, "span", "tc-name", test.name);
    addText(header, "span", "tc-badge", test.id);
    top.appendChild(header);
    addText(top, "p", "description", test.description);
    card.appendChild(top);

    const expected = document.createElement("div");
    expected.className = "expected-box";
    addText(expected, "span", "", "Expected Indicator:");
    expected.appendChild(document.createTextNode(" "));
    addText(expected, "strong", "", test.expectedIndicator);
    card.appendChild(expected);

    const link = document.createElement("a");
    link.className = "launch-btn";
    link.href = targetUrl;
    link.target = "_blank";
    link.rel = "noopener";
    link.textContent = `Launch Test Page (${test.id})`;
    card.appendChild(link);

    grid.appendChild(card);
  });
});
