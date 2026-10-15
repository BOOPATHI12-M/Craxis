// no-submit.js - blocks submission of the harmless test forms.
// External file instead of inline onsubmit handlers, so the pages also load
// without Content Security Policy errors. Each form carries data-test-message.
document.addEventListener("submit", (event) => {
  const form = event.target;
  if (!form || !form.hasAttribute || !form.hasAttribute("data-test-message")) return;
  event.preventDefault();
  alert(form.getAttribute("data-test-message"));
});
