// src/web/hsd/js/dashboard.js

// VS Code webview API
const vscode = acquireVsCodeApi();

// Global findings array
let findings = [];

// Listen for messages from extension (dashboard.ts)
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
  renderHotspots();
  renderCharts();
}

function renderCounters() {
  const total = findings.length;
  const err = findings.filter((f) => (f.severity || "").toLowerCase() === "error").length;
  const warn = total - err;

  // Complexity buckets based on numeric complexity
  let lowCx = 0,
    medCx = 0,
    highCx = 0;

  findings.forEach((f) => {
    const cx = typeof f.complexity === "number" ? f.complexity : 0;
    if (cx > 0 && cx <= 5) {lowCx++;}
    else if (cx > 5 && cx <= 10) {medCx++;}
    else if (cx > 10) {highCx++;}
  });

  // Secrets inside *_test.dart
  const testSecrets = findings.filter((f) =>
    String(f.file || "").endsWith("_test.dart")
  ).length;

  const counters = document.getElementById("counters");
  counters.innerHTML = `
    <div><strong>Total findings:</strong> ${total}</div>
    <div>
      <span style="color:#f44747"><strong>Errors:</strong> ${err}</span> |
      <span style="color:#e5e510"><strong>Warnings:</strong> ${warn}</span>
    </div>
    <div style="margin-top:4px;">
      <strong>Secrets by function complexity:</strong>
      low: ${lowCx}, medium: ${medCx}, high: ${highCx}
    </div>
    <div style="margin-top:4px;">
      <strong>Secrets in test files:</strong> ${testSecrets}
      <span style="color:#999;">( *_test.dart )</span>
    </div>
  `;
}

function renderFindingsTable() {
  const tbody = document.querySelector("#tbl tbody");
  tbody.innerHTML = "";

  findings.forEach((f) => {
    const tr = document.createElement("tr");

    const cx = typeof f.complexity === "number" ? `Cx=${f.complexity}` : "";
    const depth =
      typeof f.nestingDepth === "number" ? `,Depth=${f.nestingDepth}` : "";
    const size =
      typeof f.functionLoc === "number" ? `,Size=${f.functionLoc} LOC` : "";

    const metrics = cx || depth || size ? cx + depth + size : "";

    tr.innerHTML = `
      <td>${escapeHtml(f.severity || "")}</td>
      <td>${escapeHtml(f.ruleName || f.ruleId || "")}</td>
      <td>${escapeHtml(f.message || "")}</td>
      <td>
        <a href="#"
           onclick="reveal('${f.file}', ${f.line || 1}, ${
      f.column || 1
    }); return false;">
          ${escapeHtml(shorten(f.file || ""))}
        </a>
      </td>
      <td>${f.line || ""}</td>
      <td>${escapeHtml(f.functionName || "")}</td>
      <td>${escapeHtml(metrics)}</td>
    `;

    tbody.appendChild(tr);
  });
}

function renderHotspots() {
  const tbody = document.querySelector("#tblHotspots tbody");
  tbody.innerHTML = "";

  // 1) Only findings that have complexity > 0
  const candidates = findings.filter((f) => {
    return typeof f.complexity === "number" && f.complexity > 0;
  });

  if (candidates.length === 0) {
    const tr = document.createElement("tr");
    tr.innerHTML =
      '<td colspan="6" style="color:#aaa;">No complexity data available.</td>';
    tbody.appendChild(tr);
    return;
  }

  // 2) Sort by complexity (desc), then nesting depth (desc)
  candidates.sort((a, b) => {
    const cxA = typeof a.complexity === "number" ? a.complexity : 0;
    const cxB = typeof b.complexity === "number" ? b.complexity : 0;
    if (cxB !== cxA) {return cxB - cxA;}

    const dA = typeof a.nestingDepth === "number" ? a.nestingDepth : 0;
    const dB = typeof b.nestingDepth === "number" ? b.nestingDepth : 0;
    return dB - dA;
  });

  // 3) Take top 15 worst functions
  const hotspots = candidates.slice(0, 15);

  hotspots.forEach((f) => {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${escapeHtml(f.functionName || "<anonymous>")}</td>
      <td>${escapeHtml(shorten(f.file || ""))}</td>
      <td>${f.line || ""}</td>
      <td>${typeof f.complexity === "number" ? f.complexity : ""}</td>
      <td>${typeof f.nestingDepth === "number" ? f.nestingDepth : ""}</td>
      <td>${typeof f.functionLoc === "number" ? f.functionLoc : ""}</td>
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
  if (!s) {return "";}
  return s.length > n ? "…" + s.slice(-n) : s;
}

function reveal(file, line, column) {
  vscode.postMessage({ command: "reveal", file, line, column });
}


