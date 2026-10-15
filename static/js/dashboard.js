/* ShopSafe SOC dashboard — progressive enhancement only.
   All data comes from the server APIs; no data is fabricated client-side. */

(function () {
  "use strict";

  function esc(value) {
    return String(value == null ? "" : value).replace(/[&<>"']/g, function (ch) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[ch];
    });
  }

  /* Toasts ---------------------------------------------------------------- */

  var region = document.getElementById("toast-region");

  function toast(message, kind) {
    if (!region) return;
    var el = document.createElement("div");
    el.className = "toast toast-" + (kind || "info");
    el.textContent = message;
    region.appendChild(el);
    window.setTimeout(function () {
      el.remove();
    }, 5200);
  }

  /* Severity bars (CSP forbids inline styles, so widths are set here) ----- */

  document.querySelectorAll("[data-bar-width]").forEach(function (bar) {
    var width = Number(bar.getAttribute("data-bar-width")) || 0;
    window.requestAnimationFrame(function () {
      bar.style.width = Math.max(0, Math.min(100, width)) + "%";
    });
  });

  /* Analyze logs ---------------------------------------------------------- */

  var analyzeButtons = [];
  var topbarBtn = document.getElementById("analyze-btn");
  if (topbarBtn) analyzeButtons.push(topbarBtn);
  document.querySelectorAll("[data-analyze]").forEach(function (btn) {
    analyzeButtons.push(btn);
  });

  function setAnalyzing(busy) {
    analyzeButtons.forEach(function (btn) {
      btn.disabled = busy;
      var spinner = btn.querySelector(".btn-spinner");
      if (spinner) spinner.hidden = !busy;
      var label = btn.querySelector(".analyze-label");
      if (label) label.textContent = busy ? "Analyzing…" : "Analyze Logs";
    });
  }

  function runAnalysis() {
    setAnalyzing(true);
    toast("Analysis started — reading JSONL access logs…", "info");
    fetch("/api/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: "{}",
      credentials: "same-origin",
    })
      .then(function (response) {
        return response.json().then(function (data) {
          return { status: response.status, data: data };
        });
      })
      .then(function (result) {
        if (result.status === 200 && result.data.status === "ok") {
          var s = result.data.report || {};
          toast(
            "Analysis complete: " +
              (s.total_requests != null ? s.total_requests : "?") +
              " requests, " +
              (s.total_alerts != null ? s.total_alerts : "?") +
              " alerts. Refreshing…",
            "success"
          );
          window.setTimeout(function () {
            window.location.reload();
          }, 900);
        } else if (result.status === 409) {
          toast(result.data.message || "An analysis run is already in progress.", "warn");
          setAnalyzing(false);
        } else {
          toast(result.data.message || "Analysis failed.", "error");
          setAnalyzing(false);
        }
      })
      .catch(function () {
        toast("Analysis failed: could not reach the dashboard server.", "error");
        setAnalyzing(false);
      });
  }

  analyzeButtons.forEach(function (btn) {
    btn.addEventListener("click", runAnalysis);
  });

  /* Alert details dialog --------------------------------------------------- */

  var dialog = document.getElementById("alert-dialog");
  var dialogBody = document.getElementById("dialog-body");
  var dialogTitle = document.getElementById("dialog-title");

  function renderAlertDetails(alert) {
    dialogTitle.textContent = (alert.id || "Alert") + " · " + (alert.rule_name || "");
    dialogBody.innerHTML =
      '<dl class="detail-grid">' +
      "<dt>Alert ID</dt><dd class='mono'>" + esc(alert.id) + "</dd>" +
      "<dt>Timestamp</dt><dd class='mono'>" + esc(alert.timestamp) + "</dd>" +
      "<dt>Website</dt><dd>" + esc(alert.source_label) + "</dd>" +
      "<dt>Source IP</dt><dd class='mono'>" + esc(alert.source_ip) + "</dd>" +
      "<dt>Rule</dt><dd><span class='mono'>" + esc(alert.rule_id) + "</span> — " + esc(alert.rule_name) + "</dd>" +
      "<dt>Severity</dt><dd><span class='badge badge-" + esc(alert.severity) + "'>" + esc(alert.severity) + "</span></dd>" +
      "<dt>Method</dt><dd class='mono'>" + esc(alert.method) + "</dd>" +
      "<dt>Status</dt><dd class='mono'>" + esc(alert.status_code) + "</dd>" +
      "<dt>Path</dt><dd class='mono'>" + esc(alert.path) + "</dd>" +
      "</dl>" +
      '<div class="detail-block"><h3>Evidence</h3><p>' + esc(alert.evidence) + "</p></div>" +
      '<div class="detail-block"><h3>Recommendation</h3><p>' + esc(alert.recommendation) + "</p></div>";
  }

  function openDetails(alertId) {
    if (!dialog || !dialogBody) return;
    dialogBody.innerHTML = "<p class='muted'>Loading…</p>";
    if (typeof dialog.showModal === "function") dialog.showModal();
    fetch("/api/alerts/" + encodeURIComponent(alertId), { credentials: "same-origin" })
      .then(function (response) {
        if (!response.ok) throw new Error("not found");
        return response.json();
      })
      .then(function (data) {
        if (data.alert) renderAlertDetails(data.alert);
        else throw new Error("missing");
      })
      .catch(function () {
        dialogBody.innerHTML =
          "<p class='muted'>This alert could not be loaded. It may belong to a superseded report — run Analyze Logs and try again.</p>";
      });
  }

  document.addEventListener("click", function (event) {
    var btn = event.target.closest(".details-btn");
    if (btn) {
      openDetails(btn.getAttribute("data-alert-id"));
      return;
    }
    if (event.target.closest("[data-dialog-close]") && dialog) {
      dialog.close();
    }
  });

  /* Live search on the alerts page (enhances the server-rendered table) --- */

  var table = document.getElementById("alerts-table");
  var searchInput = document.getElementById("filter-q");
  var countEl = document.getElementById("alert-count");

  if (table && searchInput) {
    var debounceTimer = null;
    var currentQuery = searchInput.value;

    function filtersFromForm() {
      var params = new URLSearchParams();
      var q = searchInput.value.trim();
      if (q) params.set("q", q);
      ["severity", "source", "rule"].forEach(function (name) {
        var el = document.getElementById("filter-" + name);
        if (el && el.value) params.set(name, el.value);
      });
      return params;
    }

    function rowHtml(alert) {
      return (
        "<tr data-alert-id='" + esc(alert.id) + "'>" +
        "<td class='mono nowrap'>" + esc(alert.timestamp) + "</td>" +
        "<td>" + esc(alert.source_label) + "</td>" +
        "<td><span class='mono'>" + esc(alert.rule_id) + "</span>" +
        "<span class='rule-name'>" + esc(alert.rule_name) + "</span></td>" +
        "<td><span class='badge badge-" + esc(alert.severity) + "'>" + esc(alert.severity) + "</span></td>" +
        "<td class='mono path-cell'>" + esc(alert.path) + "</td>" +
        "<td class='cell-truncate'>" + esc(alert.evidence) + "</td>" +
        "<td class='cell-truncate'>" + esc(alert.recommendation) + "</td>" +
        "<td><button class='btn btn-small btn-outline details-btn' type='button' data-alert-id='" +
        esc(alert.id) + "'>Details</button></td>" +
        "</tr>"
      );
    }

    function refresh() {
      var query = searchInput.value.trim();
      if (query === currentQuery) return;
      currentQuery = query;
      var params = filtersFromForm();
      fetch("/api/alerts?" + params.toString(), { credentials: "same-origin" })
        .then(function (response) {
          if (!response.ok) throw new Error("bad response");
          return response.json();
        })
        .then(function (data) {
          var tbody = table.querySelector("tbody");
          if (!data.alerts || data.alerts.length === 0) {
            tbody.innerHTML =
              "<tr><td colspan='8' class='empty-inline'>No alerts match the current search.</td></tr>";
          } else {
            tbody.innerHTML = data.alerts.map(rowHtml).join("");
          }
          if (countEl) {
            countEl.textContent = data.total + " shown" + (query || data.filters && Object.keys(data.filters).length ? " (filtered)" : "");
          }
        })
        .catch(function () {
          toast("Live search failed; press Enter to search server-side.", "error");
        });
    }

    searchInput.addEventListener("input", function () {
      window.clearTimeout(debounceTimer);
      debounceTimer = window.setTimeout(refresh, 300);
    });
  }
})();
