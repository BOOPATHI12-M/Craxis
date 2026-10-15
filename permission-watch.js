// permission-watch.js - Craxis permission request watcher.
//
// Runs in the page's own JavaScript world at document_start so it sees calls
// made by the page's scripts. It records ONLY that a sensitive browser feature
// was requested and whether a user action preceded it. It never reads media,
// positions, clipboard text or any other data, and it always calls the
// original function unchanged.
//
// The record is stored in the data-craxis-permissions attribute of <html> and
// announced with a "craxis-permission" event, which content.js reads.

(function () {
  "use strict";

  if (window.__craxisPermissionWatch) return;
  window.__craxisPermissionWatch = true;

  var ATTRIBUTE = "data-craxis-permissions";
  var requests = [];

  function userGesture() {
    try {
      return !!(navigator.userActivation && navigator.userActivation.isActive);
    } catch (e) {
      return false;
    }
  }

  function record(kinds) {
    try {
      var gesture = userGesture();
      var changed = false;
      kinds.forEach(function (kind) {
        var existing = null;
        for (var i = 0; i < requests.length; i++) {
          if (requests[i].kind === kind) existing = requests[i];
        }
        if (!existing) {
          requests.push({ kind: kind, gesture: gesture });
          changed = true;
        } else if (existing.gesture && !gesture) {
          // Keep the worst case: a request without any user action.
          existing.gesture = false;
          changed = true;
        }
      });
      if (!changed) return;
      var root = document.documentElement;
      if (root) root.setAttribute(ATTRIBUTE, JSON.stringify(requests));
      window.dispatchEvent(new CustomEvent("craxis-permission", { detail: JSON.stringify(requests) }));
    } catch (e) {
      // Never interfere with the page.
    }
  }

  function wrap(target, name, kindsFor) {
    try {
      var original = target && target[name];
      if (typeof original !== "function") return;
      target[name] = function () {
        try {
          record(kindsFor.apply(null, arguments));
        } catch (e) {
          // ignore
        }
        return original.apply(this, arguments);
      };
      try {
        Object.defineProperty(target[name], "name", { value: name });
      } catch (e) {
        // ignore
      }
    } catch (e) {
      // ignore
    }
  }

  function mediaKinds(constraints) {
    var kinds = [];
    var c = constraints || {};
    if (c.video) kinds.push("camera");
    if (c.audio) kinds.push("microphone");
    return kinds.length ? kinds : ["camera"];
  }

  if (typeof MediaDevices !== "undefined") {
    wrap(MediaDevices.prototype, "getUserMedia", mediaKinds);
    wrap(MediaDevices.prototype, "getDisplayMedia", function () { return ["screen"]; });
  }
  if (typeof Geolocation !== "undefined") {
    wrap(Geolocation.prototype, "getCurrentPosition", function () { return ["location"]; });
    wrap(Geolocation.prototype, "watchPosition", function () { return ["location"]; });
  }
  if (typeof Notification !== "undefined") {
    wrap(Notification, "requestPermission", function () { return ["notifications"]; });
  }
  if (typeof Clipboard !== "undefined") {
    wrap(Clipboard.prototype, "readText", function () { return ["clipboard"]; });
    wrap(Clipboard.prototype, "read", function () { return ["clipboard"]; });
  }
})();
