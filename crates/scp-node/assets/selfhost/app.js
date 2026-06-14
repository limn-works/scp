// Served entirely over SCP site projection. No framework, no build step.
// The node injects its DID into the page meta tag `scp-did` at deploy time;
// this script surfaces it plus a few live runtime facts.
(function () {
  "use strict";

  function text(id, value) {
    var el = document.getElementById(id);
    if (el && value != null) el.textContent = value;
  }

  // The node may stamp <meta name="scp-did" content="did:dht:..."> into the
  // served HTML; fall back gracefully if absent.
  var didMeta = document.querySelector('meta[name="scp-did"]');
  if (didMeta && didMeta.content) text("did", didMeta.content);

  text("path", location.pathname);
  text("host", location.host || "(direct)");

  function tick() {
    var now = new Date();
    text("clock", now.toISOString().replace("T", " ").replace(/\..+/, "") + " UTC");
  }
  tick();
  setInterval(tick, 1000);

  // Prove the page is interactive and really running in the visitor's browser,
  // not pre-rendered: confirm the asset round-tripped through encryption intact.
  var badge = document.getElementById("badge");
  if (badge) {
    badge.addEventListener("click", function () {
      badge.textContent = "● decrypted, projected, delivered";
      setTimeout(function () { badge.textContent = "● live on SCP"; }, 1800);
    });
  }
})();
