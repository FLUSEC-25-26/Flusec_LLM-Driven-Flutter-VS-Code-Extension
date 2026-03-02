// src/web/ivd/js/dashboard.js

// VS Code webview API
const vscode = acquireVsCodeApi();

// Global findings array
let findings = [];

// Wire up buttons once DOM is ready
document.addEventListener("DOMContentLoaded", () => {
  const btnRefresh = document.getElementById("btnRefresh");
  if (btnRefresh) {
    btnRefresh.addEventListener("click", () => {
      vscode.postMessage({ command: "refresh" });
    });
  }

  const btnRescan = document.getElementById("btnRescan");
  if (btnRescan) {
    btnRescan.addEventListener("click", () => {
      vscode.postMessage({ command: "rescanActiveFile" });
    });
  }
});

// Listen for messages from extension
window.addEventListener("message", (e) => {
  const { command, data } = e.data || {};
  if (command === "loadFindings") {
    findings = Array.isArray(data) ? data : [];
    render();
  }
});

// Main render entrypoint
function render() {
  renderCounters();
  renderFindingsTable();
  renderCharts();
}

function renderCounters() {
  const total = findings.length;
  const err = findings.filter(
    (f) => (f.severity || "").toLowerCase() === "error"
  ).length;
  const warn = total - err;

  const counters = document.getElementById("counters");
  counters.innerHTML = `
    <div class="kpi-row">
      <div class="kpi">
        <span class="kpi-label">Total IVD findings</span>
        <span class="kpi-value">${total}</span>
      </div>
      <div class="kpi">
        <span class="kpi-label">Critical Vulnerabilities</span>
        <span class="kpi-value" style="color:#f44747">${err}</span>
      </div>
      <div class="kpi">
        <span class="kpi-label">Warnings</span>
        <span class="kpi-value" style="color:#e5e510">${warn}</span>
      </div>
    </div>
  `;
}

function renderFindingsTable() {
  const tbody = document.querySelector("#tbl tbody");
  if (!tbody) return;
  tbody.innerHTML = "";

  findings.forEach((f) => {
    const tr = document.createElement("tr");

    tr.innerHTML = `
      <td>${escapeHtml(f.severity || "")}</td>
      <td>${escapeHtml(f.ruleName || f.ruleId || "Input Validation")}</td>
      <td>${escapeHtml(f.message || "")}</td>
      <td>
        <a href="#"
            onclick="reveal('${f.file}', ${f.line || 1}, ${f.column || 1}); return false;">
          ${escapeHtml(shorten(f.file || ""))}
        </a>
      </td>
      <td>${f.line || ""}</td>
      <td>${escapeHtml(f.functionName || "")}</td>
    `;

    tbody.appendChild(tr);
  });
}

function renderCharts() {
  drawBar(
    "chartRules",
    topCounts(findings, (x) => x.ruleName || x.ruleId, 8)
  );
  drawBar(
    "chartFiles",
    topCounts(findings, (x) => x.file, 8, (lab) => shorten(lab, 40))
  );
}

function topCounts(arr, keyFn, topN = 8, mapLbl = (x) => x) {
  const m = new Map();
  for (const a of arr) {
    const k = keyFn(a) || "unknown";
    m.set(k, (m.get(k) || 0) + 1);
  }
  const rows = Array.from(m.entries())
    .sort((a, b) => b[1] - a[1])
    .slice(0, topN);
  return {
    labels: rows.map((r) => mapLbl(r[0])),
    values: rows.map((r) => r[1]),
  };
}

function drawBar(id, data) {
  const cvs = document.getElementById(id);
  if (!cvs) return;

  const ctx = cvs.getContext("2d");
  const W = (cvs.width = cvs.clientWidth);
  const H = (cvs.height = 160);

  ctx.clearRect(0, 0, W, H);

  const pad = 24;
  const max = Math.max(1, ...data.values);
  const n = data.values.length || 1;
  const bw = ((W - pad * 2) / n) * 0.8;
  const gap = ((W - pad * 2) / n) * 0.2;

  ctx.fillStyle = "#ccc";
  ctx.font = "12px Segoe UI";

  data.values.forEach((v, i) => {
    const x = pad + i * (bw + gap);
    const h = Math.round((H - 2 * pad) * (v / max));
    const y = H - pad - h;

    ctx.fillStyle = "#4fc1ff";
    ctx.fillRect(x, y, bw, h);

    ctx.fillStyle = "#ddd";
    const lbl = data.labels[i] || "";
    ctx.save();
    ctx.translate(x + bw / 2, H - 6);
    ctx.rotate(-Math.PI / 6);
    ctx.fillText(lbl, -ctx.measureText(lbl).width / 2, 0);
    ctx.restore();
  });
}

function escapeHtml(s) {
  return String(s)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function shorten(s, n = 60) {
  if (!s) return "";
  return s.length > n ? "…" + s.slice(-n) : s;
}

function reveal(file, line, column) {
  vscode.postMessage({ command: "reveal", file, line, column });
}