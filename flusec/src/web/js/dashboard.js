// src/web/js/dashboard.js

// VS Code webview API
const vscode = acquireVsCodeApi();

// Global findings array
let findings = [];
let currentFilter = "all";

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

  // Filter tabs (All Findings table)
  const filters = document.querySelectorAll("#findingsFilters .filter-tab");
  filters.forEach((btn) => {
    btn.addEventListener("click", () => {
      filters.forEach((b) => b.classList.remove("active"));
      btn.classList.add("active");
      currentFilter = btn.getAttribute("data-filter") || "all";
      renderFindingsTable();
    });
  });
});

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
  renderTaintFlowDetails();
  renderCharts();
}

// ---------------------------------------------------------------------------
// Bucket computations
// ---------------------------------------------------------------------------

function computeBuckets() {
  let lowCx = 0, medCx = 0, highCx = 0;
  let lowDepth = 0, medDepth = 0, highDepth = 0;
  let smallSize = 0, medSize = 0, largeSize = 0;

  findings.forEach((f) => {
    const cx = typeof f.complexity === "number" ? f.complexity : 0;
    if (cx > 0 && cx <= 5) { lowCx++; }
    else if (cx > 5 && cx <= 10) { medCx++; }
    else if (cx > 10) { highCx++; }

    const depth = typeof f.nestingDepth === "number" ? f.nestingDepth : undefined;
    if (typeof depth === "number") {
      if (depth <= 2) { lowDepth++; }
      else if (depth <= 4) { medDepth++; }
      else { highDepth++; }
    }

    const size = typeof f.functionLoc === "number" ? f.functionLoc : undefined;
    if (typeof size === "number") {
      if (size <= 20) { smallSize++; }
      else if (size <= 50) { medSize++; }
      else { largeSize++; }
    }
  });

  return { lowCx, medCx, highCx, lowDepth, medDepth, highDepth, smallSize, medSize, largeSize };
}

// ---------------------------------------------------------------------------
// Secret type computations
// ---------------------------------------------------------------------------

function computeSecretTypeCounts() {
  const counts = new Map();
  for (const f of findings) {
    const st = f.secretType || "UNKNOWN";
    counts.set(st, (counts.get(st) || 0) + 1);
  }
  const sorted = Array.from(counts.entries()).sort((a, b) => b[1] - a[1]);
  return {
    labels: sorted.map((r) => formatSecretTypeLabel(r[0])),
    values: sorted.map((r) => r[1]),
  };
}

function computeSecretTypeSeverityCounts() {
  const errorCounts = new Map();
  const warnCounts = new Map();

  for (const f of findings) {
    const st = f.secretType || "UNKNOWN";
    const isError = (f.severity || "").toLowerCase() === "error";
    if (isError) {
      errorCounts.set(st, (errorCounts.get(st) || 0) + 1);
    } else {
      warnCounts.set(st, (warnCounts.get(st) || 0) + 1);
    }
  }

  const allTypes = new Set([...errorCounts.keys(), ...warnCounts.keys()]);
  const sorted = Array.from(allTypes).sort((a, b) => {
    const totalA = (errorCounts.get(a) || 0) + (warnCounts.get(a) || 0);
    const totalB = (errorCounts.get(b) || 0) + (warnCounts.get(b) || 0);
    return totalB - totalA;
  });

  return {
    labels: sorted.map((t) => formatSecretTypeLabel(t)),
    errors: sorted.map((t) => errorCounts.get(t) || 0),
    warnings: sorted.map((t) => warnCounts.get(t) || 0),
  };
}

function formatSecretTypeLabel(st) {
  const map = {
    API_KEY: "API Key",
    SECRET_KEY: "Secret Key",
    JWT_TOKEN: "JWT Token",
    PASSWORD: "Password",
    DATABASE_CREDENTIAL: "DB Credential",
    OAUTH_SECRET: "OAuth Secret",
    FIREBASE_KEY: "Firebase Key",
    ENCRYPTION_KEY: "Encryption Key",
    GENERIC_SECRET: "Generic",
    UNKNOWN: "Unknown",
  };
  return map[st] || st;
}

// ---------------------------------------------------------------------------
// Taint flow computations
// ---------------------------------------------------------------------------

function computeTaintSinkCounts() {
  const counts = new Map();
  let totalFlows = 0;

  for (const f of findings) {
    if (!Array.isArray(f.taintFlow) || f.taintFlow.length === 0) {continue;}
    for (const step of f.taintFlow) {
      const type = step.type || "UNKNOWN";
      counts.set(type, (counts.get(type) || 0) + 1);
      totalFlows++;
    }
  }

  const sorted = Array.from(counts.entries()).sort((a, b) => b[1] - a[1]);
  return {
    labels: sorted.map((r) => formatTaintSinkLabel(r[0])),
    values: sorted.map((r) => r[1]),
    totalFlows,
  };
}

function formatTaintSinkLabel(type) {
  const map = {
    NETWORK_REQUEST: "Network Request",
    FUNCTION_ARGUMENT: "Function Arg",
    RETURN_VALUE: "Return Value",
    ASSIGNMENT: "Assignment",
    MAP_VALUE: "Map Value",
    STRING_INTERPOLATION: "String Interp",
    UNKNOWN: "Unknown",
  };
  return map[type] || type;
}

function findingsWithTaint() {
  return findings.filter(
    (f) => Array.isArray(f.taintFlow) && f.taintFlow.length > 0
  );
}

// ---------------------------------------------------------------------------
// Split label into two lines for charts
// ---------------------------------------------------------------------------

function splitLabel(label, maxSingle) {
  if (!label) { return [""]; }
  const limit = maxSingle || 12;
  if (label.length <= limit) { return [label]; }

  const mid = Math.floor(label.length / 2);
  const breakChars = [".", "_", "-", " ", "/"];

  let bestBreak = -1;
  for (let offset = 0; offset <= mid; offset++) {
    if (mid + offset < label.length && breakChars.includes(label[mid + offset])) {
      bestBreak = mid + offset;
      break;
    }
    if (mid - offset >= 0 && breakChars.includes(label[mid - offset])) {
      bestBreak = mid - offset;
      break;
    }
  }

  if (bestBreak > 0 && bestBreak < label.length - 1) {
    return [label.substring(0, bestBreak + 1).trim(), label.substring(bestBreak + 1).trim()];
  }

  return [label.substring(0, mid), label.substring(mid)];
}

// ---------------------------------------------------------------------------
// Render: Counters
// ---------------------------------------------------------------------------

function renderCounters() {
  const total = findings.length;
  const err = findings.filter((f) => (f.severity || "").toLowerCase() === "error").length;
  const warn = total - err;

  const { lowCx, medCx, highCx, lowDepth, medDepth, highDepth, smallSize, medSize, largeSize } = computeBuckets();

  const testSecrets = findings.filter((f) => String(f.file || "").endsWith("_test.dart")).length;

  const typeCounts = computeSecretTypeCounts();
  const topType = typeCounts.labels.length > 0 ? typeCounts.labels[0] : "N/A";
  const topTypeCount = typeCounts.values.length > 0 ? typeCounts.values[0] : 0;
  const uniqueTypes = typeCounts.labels.length;

  // Taint stats
  const taintedFindings = findingsWithTaint();
  const taintedCount = taintedFindings.length;
  const taintSinkData = computeTaintSinkCounts();

  const counters = document.getElementById("counters");
  counters.innerHTML = `
    <div class="kpi-row">
      <div class="kpi">
        <span class="kpi-label">Total findings</span>
        <span class="kpi-value">${total}</span>
      </div>
      <div class="kpi">
        <span class="kpi-label">Errors</span>
        <span class="kpi-value" style="color:#f97373">${err}</span>
      </div>
      <div class="kpi">
        <span class="kpi-label">Warnings</span>
        <span class="kpi-value" style="color:#facc15">${warn}</span>
      </div>
    </div>

    <div class="kpi-row">
      <div class="kpi">
        <span class="kpi-label">Secret types detected</span>
        <span class="kpi-value">${uniqueTypes}</span>
      </div>
      <div class="kpi">
        <span class="kpi-label">Most common type</span>
        <span class="kpi-value">${topType} <span style="color:#9ca3af;">(${topTypeCount})</span></span>
      </div>
      <div class="kpi">
        <span class="kpi-label">Secrets with taint flows</span>
        <span class="kpi-value" style="color:#fb923c">${taintedCount} <span style="color:#9ca3af;">/ ${total}</span></span>
      </div>
    </div>

    <div class="kpi-row">
      <div class="kpi">
        <span class="kpi-label">Complexity buckets (Cx)</span>
        <span class="kpi-value">low: ${lowCx} • medium: ${medCx} • high: ${highCx}</span>
      </div>
      <div class="kpi">
        <span class="kpi-label">Nesting depth buckets</span>
        <span class="kpi-value">shallow: ${lowDepth} • medium: ${medDepth} • deep: ${highDepth}</span>
      </div>
    </div>

    <div class="kpi-row">
      <div class="kpi">
        <span class="kpi-label">Function size (LOC)</span>
        <span class="kpi-value">small: ${smallSize} • medium: ${medSize} • large: ${largeSize}</span>
      </div>
      <div class="kpi">
        <span class="kpi-label">Secrets in test files</span>
        <span class="kpi-value">${testSecrets} <span style="color:#9ca3af;">( *_test.dart )</span></span>
      </div>
    </div>
  `;

  // Taint summary card
  const taintSummary = document.getElementById("taintSummary");
  if (taintSummary) {
    if (taintedCount === 0) {
      taintSummary.innerHTML = `
        <div class="kpi-row">
          <div class="kpi">
            <span class="kpi-label">Status</span>
            <span class="kpi-value" style="color:#34d399">No taint flows detected</span>
          </div>
        </div>
      `;
    } else {
      taintSummary.innerHTML = `
        <div class="kpi-row">
          <div class="kpi">
            <span class="kpi-label">Secrets with flows</span>
            <span class="kpi-value" style="color:#fb923c">${taintedCount}</span>
          </div>
          <div class="kpi">
            <span class="kpi-label">Total sink usages</span>
            <span class="kpi-value">${taintSinkData.totalFlows}</span>
          </div>
        </div>
        <div class="kpi-row">
          <div class="kpi">
            <span class="kpi-label">Network request sinks</span>
            <span class="kpi-value" style="color:#f97373">${countSinkType("NETWORK_REQUEST")}</span>
          </div>
          <div class="kpi">
            <span class="kpi-label">Function argument sinks</span>
            <span class="kpi-value">${countSinkType("FUNCTION_ARGUMENT")}</span>
          </div>
          <div class="kpi">
            <span class="kpi-label">Return value sinks</span>
            <span class="kpi-value">${countSinkType("RETURN_VALUE")}</span>
          </div>
        </div>
      `;
    }
  }
}

function countSinkType(type) {
  let count = 0;
  for (const f of findings) {
    if (!Array.isArray(f.taintFlow)) {continue;}
    for (const step of f.taintFlow) {
      if (step.type === type) {count++;}
    }
  }
  return count;
}

// ---------------------------------------------------------------------------
// Render: Findings table
// ---------------------------------------------------------------------------

function filteredFindingsForTable() {
  return findings.filter((f) => {
    const cx = typeof f.complexity === "number" ? f.complexity : 0;
    const file = String(f.file || "");
    const hasTaint = Array.isArray(f.taintFlow) && f.taintFlow.length > 0;

    switch (currentFilter) {
      case "highCx": return cx > 10;
      case "mediumCx": return cx > 5 && cx <= 10;
      case "lowCx": return cx > 0 && cx <= 5;
      case "hasTaint": return hasTaint;
      case "tests": return file.endsWith("_test.dart");
      case "all":
      default: return true;
    }
  });
}

function renderFindingsTable() {
  const tbody = document.querySelector("#tbl tbody");
  if (!tbody) { return; }

  tbody.innerHTML = "";
  const rows = filteredFindingsForTable();

  rows.forEach((f) => {
    const tr = document.createElement("tr");

    const cx = typeof f.complexity === "number" ? `Cx=${f.complexity}` : "";
    const depth = typeof f.nestingDepth === "number" ? `,Depth=${f.nestingDepth}` : "";
    const size = typeof f.functionLoc === "number" ? `,Size=${f.functionLoc} LOC` : "";
    const metrics = cx || depth || size ? cx + depth + size : "";

    const secretTypeLabel = f.secretType ? formatSecretTypeLabel(f.secretType) : "";

    // Taint column
    const hasTaint = Array.isArray(f.taintFlow) && f.taintFlow.length > 0;
    const taintBadge = hasTaint
      ? `<span style="color:#fb923c;font-weight:600;">${f.taintFlow.length} flow(s)</span>`
      : '<span style="color:#6b7280;">—</span>';

    tr.innerHTML = `
      <td>${escapeHtml(f.severity || "")}</td>
      <td>${escapeHtml(f.ruleName || f.ruleId || "")}</td>
      <td>${escapeHtml(secretTypeLabel)}</td>
      <td>${escapeHtml(f.message || "")}</td>
      <td>
        <a href="#"
           onclick="reveal('${f.file}', ${f.line || 1}, ${f.column || 1}); return false;">
          ${escapeHtml(fileNameFromPath(f.file || ""))}
        </a>
      </td>
      <td>${f.line || ""}</td>
      <td>${escapeHtml(f.functionName || "")}</td>
      <td>${escapeHtml(metrics)}</td>
      <td>${taintBadge}</td>
    `;

    tbody.appendChild(tr);
  });

  if (rows.length === 0) {
    const tr = document.createElement("tr");
    tr.innerHTML = '<td colspan="9" style="color:#9ca3af;">No findings for this filter.</td>';
    tbody.appendChild(tr);
  }
}

// ---------------------------------------------------------------------------
// Render: Hotspots
// ---------------------------------------------------------------------------

function renderHotspots() {
  const tbody = document.querySelector("#tblHotspots tbody");
  if (!tbody) { return; }
  tbody.innerHTML = "";

  const candidates = findings.filter((f) => typeof f.complexity === "number" && f.complexity > 0);

  if (candidates.length === 0) {
    const tr = document.createElement("tr");
    tr.innerHTML = '<td colspan="6" style="color:#aaa;">No complexity data available.</td>';
    tbody.appendChild(tr);
    return;
  }

  candidates.sort((a, b) => {
    const cxA = typeof a.complexity === "number" ? a.complexity : 0;
    const cxB = typeof b.complexity === "number" ? b.complexity : 0;
    if (cxB !== cxA) { return cxB - cxA; }
    const dA = typeof a.nestingDepth === "number" ? a.nestingDepth : 0;
    const dB = typeof b.nestingDepth === "number" ? b.nestingDepth : 0;
    return dB - dA;
  });

  const hotspots = candidates.slice(0, 15);

  hotspots.forEach((f) => {
    const tr = document.createElement("tr");
    tr.innerHTML = `
      <td>${escapeHtml(f.functionName || "<anonymous>")}</td>
      <td>${escapeHtml(fileNameFromPath(f.file || ""))}</td>
      <td>${f.line || ""}</td>
      <td>${typeof f.complexity === "number" ? f.complexity : ""}</td>
      <td>${typeof f.nestingDepth === "number" ? f.nestingDepth : ""}</td>
      <td>${typeof f.functionLoc === "number" ? f.functionLoc : ""}</td>
    `;
    tbody.appendChild(tr);
  });
}

// ---------------------------------------------------------------------------
// Render: Taint flow details table
// ---------------------------------------------------------------------------

function renderTaintFlowDetails() {
  const tbody = document.querySelector("#tblTaintFlows tbody");
  if (!tbody) { return; }
  tbody.innerHTML = "";

  const tainted = findingsWithTaint();

  if (tainted.length === 0) {
    const tr = document.createElement("tr");
    tr.innerHTML = '<td colspan="5" style="color:#9ca3af;">No taint flows detected.</td>';
    tbody.appendChild(tr);
    return;
  }

  // Sort by number of flows (most dangerous first)
  tainted.sort((a, b) => (b.taintFlow?.length || 0) - (a.taintFlow?.length || 0));

  tainted.forEach((f) => {
    const tr = document.createElement("tr");

    const secretTypeLabel = f.secretType ? formatSecretTypeLabel(f.secretType) : "Generic";

    // Build flow path description
    const flowParts = f.taintFlow.map((step) => {
      const icon = getTaintSinkIcon(step.type);
      return `${icon} L${step.line}: ${escapeHtml(step.description)}`;
    });
    const flowHtml = flowParts.join('<br>');

    tr.innerHTML = `
      <td>${escapeHtml(f.ruleId || "")}</td>
      <td>
        <a href="#"
           onclick="reveal('${f.file}', ${f.line || 1}, ${f.column || 1}); return false;">
          ${escapeHtml(fileNameFromPath(f.file || ""))}
        </a>
      </td>
      <td>${f.line || ""}</td>
      <td>${escapeHtml(secretTypeLabel)}</td>
      <td style="font-size:12px;">${flowHtml}</td>
    `;

    tbody.appendChild(tr);
  });
}

function getTaintSinkIcon(type) {
  const icons = {
    NETWORK_REQUEST: "🌐",
    FUNCTION_ARGUMENT: "📤",
    RETURN_VALUE: "↩️",
    ASSIGNMENT: "📋",
    MAP_VALUE: "🗺️",
    STRING_INTERPOLATION: "📝",
  };
  return icons[type] || "•";
}

// ---------------------------------------------------------------------------
// Render: Charts
// ---------------------------------------------------------------------------

function renderCharts() {
  drawBar("chartRules", topCounts(findings, (x) => x.ruleName || x.ruleId, 8, (lab) => shorten(lab, 20)));
  drawBar("chartFiles", topCounts(findings, (x) => x.file, 8, (lab) => shorten(fileNameFromPath(lab), 28)));

  drawBar("chartSecretTypes", computeSecretTypeCounts());
  drawStackedBar("chartSecretTypeSeverity", computeSecretTypeSeverityCounts());

  // Taint sink distribution chart
  const taintData = computeTaintSinkCounts();
  drawBar("chartTaintSinks", { labels: taintData.labels, values: taintData.values });

  const { lowCx, medCx, highCx, lowDepth, medDepth, highDepth, smallSize, medSize, largeSize } = computeBuckets();

  drawBar("chartCxBuckets", { labels: ["Low", "Medium", "High"], values: [lowCx, medCx, highCx] });
  drawBar("chartDepthBuckets", { labels: ["Shallow", "Medium", "Deep"], values: [lowDepth, medDepth, highDepth] });
  drawBar("chartSizeBuckets", { labels: ["Small", "Medium", "Large"], values: [smallSize, medSize, largeSize] });
}

function topCounts(arr, keyFn, topN = 8, mapLbl = (x) => x) {
  const m = new Map();
  for (const a of arr) {
    const k = keyFn(a) || "unknown";
    m.set(k, (m.get(k) || 0) + 1);
  }
  const rows = Array.from(m.entries()).sort((a, b) => b[1] - a[1]).slice(0, topN);
  return {
    labels: rows.map((r) => mapLbl(r[0])),
    values: rows.map((r) => r[1]),
  };
}

// ---------------------------------------------------------------------------
// Draw: Bar chart with multi-line X labels
// ---------------------------------------------------------------------------

function drawBar(id, data) {
  const cvs = document.getElementById(id);
  if (!cvs) { return; }

  const ctx = cvs.getContext("2d");
  const W = (cvs.width = cvs.clientWidth);
  const H = (cvs.height = 180);

  ctx.clearRect(0, 0, W, H);

  if (!data || !data.values || data.values.length === 0) {
    ctx.fillStyle = "#9ca3af";
    ctx.font = "12px Segoe UI";
    ctx.textAlign = "center";
    ctx.textBaseline = "middle";
    ctx.fillText("No data", W / 2, H / 2);
    return;
  }

  const padTop = 16;
  const padBottom = 52;
  const chartHeight = H - padTop - padBottom;
  const max = Math.max(1, ...data.values);
  const n = data.values.length || 1;
  const totalWidth = W - 32;
  const bw = (totalWidth / n) * 0.7;
  const gap = (totalWidth / n) * 0.3;
  const maxLabelChars = Math.max(8, Math.floor(bw / 6));

  ctx.font = "11px Segoe UI";
  ctx.textAlign = "center";

  data.values.forEach((v, i) => {
    const x = 16 + i * (bw + gap);
    const h = Math.round(chartHeight * (v / max));
    const y = padTop + (chartHeight - h);

    const palette = ["#4fc3f7", "#34d399", "#f97373", "#facc15", "#a855f7", "#fb923c", "#38bdf8", "#f472b6", "#818cf8"];
    ctx.fillStyle = palette[i % palette.length];
    ctx.fillRect(x, y, bw, h);

    ctx.fillStyle = "#e5e5e5";
    ctx.textBaseline = "bottom";
    ctx.font = "12px Segoe UI";
    ctx.fillText(String(v), x + bw / 2, y - 2);

    ctx.fillStyle = "#d1d5db";
    ctx.textBaseline = "top";
    ctx.font = "11px Segoe UI";

    const lbl = data.labels[i] || "";
    const lines = splitLabel(lbl, maxLabelChars);
    const lineHeight = 13;
    const labelStartY = H - padBottom + 8;
    lines.forEach((line, lineIdx) => {
      ctx.fillText(line, x + bw / 2, labelStartY + lineIdx * lineHeight);
    });
  });
}

// ---------------------------------------------------------------------------
// Draw: Stacked bar chart
// ---------------------------------------------------------------------------

function drawStackedBar(id, data) {
  const cvs = document.getElementById(id);
  if (!cvs) { return; }

  const ctx = cvs.getContext("2d");
  const W = (cvs.width = cvs.clientWidth);
  const H = (cvs.height = 180);

  ctx.clearRect(0, 0, W, H);

  if (!data || !data.labels || data.labels.length === 0) {
    ctx.fillStyle = "#9ca3af";
    ctx.font = "12px Segoe UI";
    ctx.textAlign = "center";
    ctx.textBaseline = "middle";
    ctx.fillText("No data", W / 2, H / 2);
    return;
  }

  const padTop = 16;
  const padBottom = 52;
  const chartHeight = H - padTop - padBottom;

  const totals = data.labels.map((_, i) => (data.errors[i] || 0) + (data.warnings[i] || 0));
  const max = Math.max(1, ...totals);

  const n = data.labels.length;
  const totalWidth = W - 32;
  const bw = (totalWidth / n) * 0.7;
  const gap = (totalWidth / n) * 0.3;
  const maxLabelChars = Math.max(8, Math.floor(bw / 6));

  ctx.font = "11px Segoe UI";
  ctx.textAlign = "center";

  data.labels.forEach((lbl, i) => {
    const x = 16 + i * (bw + gap);
    const errVal = data.errors[i] || 0;
    const warnVal = data.warnings[i] || 0;
    const total = errVal + warnVal;

    const warnH = Math.round(chartHeight * (warnVal / max));
    const warnY = padTop + chartHeight - warnH;
    ctx.fillStyle = "#facc15";
    ctx.fillRect(x, warnY, bw, warnH);

    const errH = Math.round(chartHeight * (errVal / max));
    const errY = warnY - errH;
    ctx.fillStyle = "#f97373";
    ctx.fillRect(x, errY, bw, errH);

    ctx.fillStyle = "#e5e5e5";
    ctx.textBaseline = "bottom";
    ctx.font = "12px Segoe UI";
    ctx.fillText(String(total), x + bw / 2, errY - 2);

    ctx.fillStyle = "#d1d5db";
    ctx.textBaseline = "top";
    ctx.font = "11px Segoe UI";

    const lines = splitLabel(lbl, maxLabelChars);
    const lineHeight = 13;
    const labelStartY = H - padBottom + 8;
    lines.forEach((line, lineIdx) => {
      ctx.fillText(line, x + bw / 2, labelStartY + lineIdx * lineHeight);
    });
  });

  // Legend
  ctx.font = "10px Segoe UI";
  ctx.textAlign = "left";
  ctx.fillStyle = "#f97373";
  ctx.fillRect(W - 120, 4, 8, 8);
  ctx.fillStyle = "#d1d5db";
  ctx.fillText("Error", W - 108, 5);
  ctx.fillStyle = "#facc15";
  ctx.fillRect(W - 60, 4, 8, 8);
  ctx.fillStyle = "#d1d5db";
  ctx.fillText("Warning", W - 48, 5);
}

// ---------------------------------------------------------------------------
// Utilities
// ---------------------------------------------------------------------------

function escapeHtml(s) {
  return String(s)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function shorten(s, n = 60) {
  if (!s) { return ""; }
  return s.length > n ? "…" + s.slice(-n) : s;
}

function fileNameFromPath(p) {
  const s = String(p || "");
  if (!s) { return ""; }
  const parts = s.split(/[\\/]/);
  return parts[parts.length - 1] || s;
}

function reveal(file, line, column) {
  vscode.postMessage({ command: "reveal", file, line, column });
}