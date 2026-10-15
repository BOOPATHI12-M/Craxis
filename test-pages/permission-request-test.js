// TC11 - requests camera access on load, with no user action. Harmless:
// any stream is stopped immediately and nothing is recorded or sent.
(function () {
  "use strict";
  if (!navigator.mediaDevices || !navigator.mediaDevices.getUserMedia) return;
  navigator.mediaDevices
    .getUserMedia({ video: true })
    .then(function (stream) {
      stream.getTracks().forEach(function (track) { track.stop(); });
    })
    .catch(function () {
      // Blocked, dismissed or no camera. Nothing to do.
    });
})();
