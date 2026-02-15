// src/web/hsd/js/dashboard.js

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
  renderCharts();
}

function computeBuckets() {
  // Complexity buckets
  let lowCx = 0,
    medCx = 0,
    highCx = 0;

  // Nesting depth buckets
  let lowDepth = 0,
    medDepth = 0,
    highDepth = 0;

  // Function size buckets (LOC)
  let smallSize = 0,
    medSize = 0,
    largeSize = 0;

  findings.forEach((f) => {
    const cx = typeof f.complexity === "number" ? f.complexity : 0;
    if (cx > 0 && cx <= 5) {
      lowCx++;
    } else if (cx > 5 && cx <= 10) {
      medCx++;
    } else if (cx > 10) {
      highCx++;
    }

    const depth =
      typeof f.nestingDepth === "number" ? f.nestingDepth : undefined;
    if (typeof depth === "number") {
      if (depth <= 2) {
        lowDepth++;
      } else if (depth <= 4) {
        medDepth++;
      } else {
        highDepth++;
      }
    }

    const size =
      typeof f.functionLoc === "number" ? f.functionLoc : undefined;
    if (typeof size === "number") {
      if (size <= 20) {
        smallSize++;
      } else if (size <= 50) {
        medSize++;
      } else {
        largeSize++;
      }
    }
  });

  return {
    lowCx,
    medCx,
    highCx,
    lowDepth,
    medDepth,
    highDepth,
    smallSize,
    medSize,
    largeSize,
  };
}

function renderCounters() {
  const total = findings.length;
  const err = findings.filter(
    (f) => (f.severity || "").toLowerCase() === "error"
  ).length;
  const warn = total - err;

  const {
    lowCx,
    medCx,
    highCx,
    lowDepth,
    medDepth,
    highDepth,
    smallSize,
    medSize,
    largeSize,
  } = computeBuckets();

  // Secrets inside *_test.dart
  const testSecrets = findings.filter((f) =>
    String(f.file || "").endsWith("_test.dart")
  ).length;

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
        <span class="kpi-label">Complexity buckets (Cx)</span>
        <span class="kpi-value">
          low: ${lowCx} • medium: ${medCx} • high: ${highCx}
        </span>
      </div>
      <div class="kpi">
        <span class="kpi-label">Nesting depth buckets</span>
        <span class="kpi-value">
          shallow: ${lowDepth} • medium: ${medDepth} • deep: ${highDepth}
        </span>
      </div>
    </div>

    <div class="kpi-row">
      <div class="kpi">
        <span class="kpi-label">Function size (LOC)</span>
        <span class="kpi-value">
          small: ${smallSize} • medium: ${medSize} • large: ${largeSize}
        </span>
      </div>
      <div class="kpi">
        <span class="kpi-label">Secrets in test files</span>
        <span class="kpi-value">
          ${testSecrets} <span style="color:#9ca3af;">( *_test.dart )</span>
        </span>
      </div>
    </div>
  `;
}

function filteredFindingsForTable() {
  return findings.filter((f) => {
    const cx = typeof f.complexity === "number" ? f.complexity : 0;
    const file = String(f.file || "");

    switch (currentFilter) {
      case "highCx":
        return cx > 10;
      case "mediumCx":
        return cx > 5 && cx <= 10;
      case "lowCx":
        return cx > 0 && cx <= 5;
      case "tests":
        return file.endsWith("_test.dart");
      case "all":
      default:
        return true;
    }
  });
}

function renderFindingsTable() {
  const tbody = document.querySelector("#tbl tbody");
  if (!tbody) {return;}

  tbody.innerHTML = "";
  const rows = filteredFindingsForTable();

  rows.forEach((f) => {
    const tr = document.createElement("tr");

    const cx =
      typeof f.complexity === "number" ? `Cx=${f.complexity}` : "";
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
          ${escapeHtml(fileNameFromPath(f.file || ""))}
        </a>
      </td>
      <td>${f.line || ""}</td>
      <td>${escapeHtml(f.functionName || "")}</td>
      <td>${escapeHtml(metrics)}</td>
    `;

    tbody.appendChild(tr);
  });

  if (rows.length === 0) {
    const tr = document.createElement("tr");
    tr.innerHTML =
      '<td colspan="7" style="color:#9ca3af;">No findings for this filter.</td>';
    tbody.appendChild(tr);
  }
}

function renderHotspots() {
  const tbody = document.querySelector("#tblHotspots tbody");
  if (!tbody) {return;}
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
    if (cxB !== cxA) {
      return cxB - cxA;
    }

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
      <td>${escapeHtml(fileNameFromPath(f.file || ""))}</td>
      <td>${f.line || ""}</td>
      <td>${typeof f.complexity === "number" ? f.complexity : ""}</td>
      <td>${typeof f.nestingDepth === "number" ? f.nestingDepth : ""}</td>
      <td>${typeof f.functionLoc === "number" ? f.functionLoc : ""}</td>
    `;
    tbody.appendChild(tr);
  });
}

function renderCharts() {
  // Secrets by rule / file
  drawBar(
    "chartRules",
    topCounts(findings, (x) => x.ruleName || x.ruleId, 8, (lab) =>
      shorten(lab, 20)
    )
  );
  drawBar(
    "chartFiles",
    topCounts(findings, (x) => x.file, 8, (lab) =>
      shorten(fileNameFromPath(lab), 28)
    )
  );

  // Maintainability charts
  const {
    lowCx,
    medCx,
    highCx,
    lowDepth,
    medDepth,
    highDepth,
    smallSize,
    medSize,
    largeSize,
  } = computeBuckets();

  drawBar("chartCxBuckets", {
    labels: ["Low", "Medium", "High"],
    values: [lowCx, medCx, highCx],
  });

  drawBar("chartDepthBuckets", {
    labels: ["Shallow", "Medium", "Deep"],
    values: [lowDepth, medDepth, highDepth],
  });

  drawBar("chartSizeBuckets", {
    labels: ["Small", "Medium", "Large"],
    values: [smallSize, medSize, largeSize],
  });
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
  if (!cvs) {return;}

  const ctx = cvs.getContext("2d");
  const W = (cvs.width = cvs.clientWidth);
  const H = (cvs.height = 160);

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
  const padBottom = 42; // space for labels
  const chartHeight = H - padTop - padBottom;
  const max = Math.max(1, ...data.values);
  const n = data.values.length || 1;
  const totalWidth = W - 32;
  const bw = (totalWidth / n) * 0.7;
  const gap = (totalWidth / n) * 0.3;

  ctx.font = "12px Segoe UI";
  ctx.textAlign = "center";

  data.values.forEach((v, i) => {
    const x = 16 + i * (bw + gap);
    const h = Math.round(chartHeight * (v / max));
    const y = padTop + (chartHeight - h);

    // Bar colours
    const palette = ["#4fc3f7", "#34d399", "#f97373", "#facc15", "#a855f7"];
    ctx.fillStyle = palette[i % palette.length];
    ctx.fillRect(x, y, bw, h);

    // Value label on top of bar
    ctx.fillStyle = "#e5e5e5";
    ctx.textBaseline = "bottom";
    ctx.fillText(String(v), x + bw / 2, y - 2);

    // X-axis label (horizontal)
    ctx.textBaseline = "top";
    const lbl = data.labels[i] || "";
    ctx.fillStyle = "#d1d5db";
    ctx.fillText(lbl, x + bw / 2, H - padBottom + 20);
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
  if (!s) {
    return "";
  }
  return s.length > n ? "…" + s.slice(-n) : s;
}

function fileNameFromPath(p) {
  const s = String(p || "");
  if (!s) {return "";}
  const parts = s.split(/[\\/]/); // works for Windows + POSIX
  return parts[parts.length - 1] || s;
}

function reveal(file, line, column) {
  vscode.postMessage({ command: "reveal", file, line, column });
}
