(() => {
  "use strict";

  const vscode = acquireVsCodeApi();
  const component = String(document.body.dataset.component || "").toLowerCase();

  const COMPONENTS = {
    hsd: {
      emptyTitle: "No hardcoded-secret findings",
      emptyMessage:
        "No hardcoded credentials or secret material were detected in the latest scan.",
    },
    net: {
      emptyTitle: "No network-security findings",
      emptyMessage:
        "No insecure network communication or transport configuration findings were detected in the latest scan.",
    },
    ids: {
      emptyTitle: "No insecure-storage findings",
      emptyMessage:
        "No sensitive-data storage weaknesses were detected in the latest scan.",
    },
    iiv: {
      emptyTitle: "No input-validation findings",
      emptyMessage:
        "No targeted input-validation weaknesses were detected in the latest scan.",
    },
  };

  const severityRank = { critical: 4, high: 3, medium: 2, low: 1 };
  const confidenceRank = { high: 3, medium: 2, low: 1 };

  const state = {
    findings: [],
    status: "no-scan-data",
    statusMessage: "",
    search: "",
    severity: "",
    confidence: "",
    sort: "severity",
    extraFilters: {},
    coupling: null,
  };

  document.addEventListener("DOMContentLoaded", () => {
    bindControls();
    setupTabs();
    render();
    vscode.postMessage({ command: "ready" });
  });

  window.addEventListener("message", (event) => {
    const message = event.data || {};

    if (message.type === "flusec:findings") {
      const payload = message.payload || {};
      state.status = String(payload.status || "ready");
      state.statusMessage = String(payload.message || "");
      state.findings = Array.isArray(payload.findings) ? payload.findings : [];
      populateExtraFilters();
      render();
      return;
    }

    if (message.type === "coupling-data") {
      state.coupling = message.payload || null;
      renderCoupling();
    }
  });

  function bindControls() {
    document.getElementById("btnRefresh")?.addEventListener("click", () => {
      vscode.postMessage({ command: "refresh" });
    });

    document.getElementById("searchInput")?.addEventListener("input", (event) => {
      state.search = String(event.target?.value || "").trim().toLowerCase();
      renderFindings();
    });

    document.getElementById("severityFilter")?.addEventListener("change", (event) => {
      state.severity = String(event.target?.value || "").toLowerCase();
      renderFindings();
    });

    document.getElementById("confidenceFilter")?.addEventListener("change", (event) => {
      state.confidence = String(event.target?.value || "").toLowerCase();
      renderFindings();
    });

    document.getElementById("sortFilter")?.addEventListener("change", (event) => {
      state.sort = String(event.target?.value || "severity");
      renderFindings();
    });

    const moreButton = document.getElementById("btnMoreFilters");
    const moreRegion = document.getElementById("moreFilters");
    moreButton?.addEventListener("click", () => {
      if (!moreRegion) {return;}
      const willOpen = moreRegion.hidden;
      moreRegion.hidden = !willOpen;
      moreButton.setAttribute("aria-expanded", String(willOpen));
    });

    document.getElementById("moreFilters")?.addEventListener("change", (event) => {
      const target = event.target;
      if (!(target instanceof HTMLSelectElement)) {return;}
      const key = target.dataset.filterKey;
      if (!key) {return;}
      state.extraFilters[key] = target.value;
      renderFindings();
    });

    document.getElementById("findingsList")?.addEventListener("click", (event) => {
      const target = event.target;
      if (!(target instanceof Element)) {return;}
      const button = target.closest("[data-open-index]");
      if (!(button instanceof HTMLElement)) {return;}

      const index = Number(button.dataset.openIndex);
      const finding = state.findings[index];
      if (!finding) {return;}

      vscode.postMessage({
        command: "reveal",
        file: finding.file,
        line: finding.line,
        column: finding.column,
      });
    });
  }

  function setupTabs() {
    const tabs = Array.from(document.querySelectorAll("[role='tab']"));
    if (!tabs.length) {return;}

    tabs.forEach((tab) => {
      tab.addEventListener("click", () => activateTab(tab));
      tab.addEventListener("keydown", (event) => {
        if (event.key !== "ArrowLeft" && event.key !== "ArrowRight") {return;}
        event.preventDefault();
        const index = tabs.indexOf(tab);
        const delta = event.key === "ArrowRight" ? 1 : -1;
        const next = tabs[(index + delta + tabs.length) % tabs.length];
        activateTab(next);
        next.focus();
      });
    });
  }

  function activateTab(tab) {
    const targetId = tab.getAttribute("aria-controls");
    if (!targetId) {return;}

    document.querySelectorAll("[role='tab']").forEach((item) => {
      item.setAttribute("aria-selected", String(item === tab));
    });

    document.querySelectorAll(".flusec-tab-panel").forEach((panel) => {
      panel.hidden = panel.id !== targetId;
    });
  }

  function render() {
    renderSummary();
    renderFindings();
    if (component === "net") {renderCoupling();}
  }

  function renderSummary() {
    const counts = { critical: 0, high: 0, medium: 0, low: 0 };
    state.findings.forEach((finding) => {
      const severity = normalizeSeverity(finding.securitySeverity);
      if (Object.prototype.hasOwnProperty.call(counts, severity)) {
        counts[severity] += 1;
      }
    });

    setText("summaryTotal", state.findings.length);
    setText("summaryCritical", counts.critical);
    setText("summaryHigh", counts.high);
    setText("summaryMedium", counts.medium);
    setText("summaryLow", counts.low);
  }

  function renderFindings() {
    const list = document.getElementById("findingsList");
    const stateContainer = document.getElementById("findingsState");
    const resultCount = document.getElementById("resultCount");
    if (!list || !stateContainer) {return;}

    const filtered = filteredAndSortedFindings();
    resultCount.textContent = `${filtered.length} of ${state.findings.length} finding${state.findings.length === 1 ? "" : "s"}`;

    if (state.status === "no-workspace") {
      list.innerHTML = "";
      stateContainer.hidden = false;
      stateContainer.innerHTML = stateMarkup(
        "Workspace required",
        state.statusMessage || "Open a workspace folder to view FLUSEC findings."
      );
      return;
    }

    if (state.status === "no-scan-data") {
      list.innerHTML = "";
      stateContainer.hidden = false;
      stateContainer.innerHTML = stateMarkup(
        "No scan data yet",
        state.statusMessage || "Run a FLUSEC scan to populate this dashboard."
      );
      return;
    }

    if (state.status === "error") {
      list.innerHTML = "";
      stateContainer.hidden = false;
      stateContainer.innerHTML = stateMarkup(
        "Unable to load findings",
        state.statusMessage || "The FLUSEC findings file could not be read."
      );
      return;
    }

    if (state.findings.length === 0) {
      list.innerHTML = "";
      stateContainer.hidden = false;
      const cfg = COMPONENTS[component] || COMPONENTS.hsd;
      stateContainer.innerHTML = `
        <div class="flusec-empty">
          <h2 class="flusec-empty__title"><span class="flusec-empty__icon">✓</span>${escapeHtml(cfg.emptyTitle)}</h2>
          <p>${escapeHtml(cfg.emptyMessage)}</p>
        </div>
      `;
      return;
    }

    if (filtered.length === 0) {
      list.innerHTML = "";
      stateContainer.hidden = false;
      stateContainer.innerHTML = stateMarkup(
        "No matching findings",
        "Try changing the search text or filters."
      );
      return;
    }

    stateContainer.hidden = true;
    stateContainer.innerHTML = "";
    list.innerHTML = filtered.map(({ finding, index }) => renderFinding(finding, index)).join("");
  }

  function stateMarkup(title, message) {
    return `
      <div class="flusec-state">
        <h2 class="flusec-state__title">${escapeHtml(title)}</h2>
        <p>${escapeHtml(message)}</p>
      </div>
    `;
  }

  function filteredAndSortedFindings() {
    const items = state.findings
      .map((finding, index) => ({ finding, index }))
      .filter(({ finding }) => matchesFinding(finding));

    items.sort((left, right) => compareFindings(left.finding, right.finding));
    return items;
  }

  function matchesFinding(finding) {
    const severity = normalizeSeverity(finding.securitySeverity);
    const confidence = normalizeConfidence(finding.confidence);

    if (state.severity && severity !== state.severity) {return false;}
    if (state.confidence && confidence !== state.confidence) {return false;}

    for (const [key, selected] of Object.entries(state.extraFilters)) {
      if (!selected) {continue;}
      if (extraFilterValue(finding, key) !== selected) {return false;}
    }

    if (!state.search) {return true;}

    const evidence = finding.evidence && typeof finding.evidence === "object"
      ? JSON.stringify(finding.evidence)
      : "";
    const haystack = [
      finding.ruleId,
      finding.message,
      finding.file,
      finding.functionName,
      finding.cwe,
      finding.category,
      finding.secretType,
      finding.dataType,
      finding.storageContext,
      evidence,
    ]
      .filter(Boolean)
      .join(" ")
      .toLowerCase();

    return haystack.includes(state.search);
  }

  function compareFindings(a, b) {
    if (state.sort === "confidence") {
      const diff = confidenceRank[normalizeConfidence(b.confidence)] - confidenceRank[normalizeConfidence(a.confidence)];
      if (diff) {return diff;}
    } else if (state.sort === "file") {
      const diff = displayPath(a.file).localeCompare(displayPath(b.file));
      if (diff) {return diff;}
    } else if (state.sort === "rule") {
      const diff = String(a.ruleId || "").localeCompare(String(b.ruleId || ""));
      if (diff) {return diff;}
    } else {
      const diff = severityRank[normalizeSeverity(b.securitySeverity)] - severityRank[normalizeSeverity(a.securitySeverity)];
      if (diff) {return diff;}
      const confidenceDiff = confidenceRank[normalizeConfidence(b.confidence)] - confidenceRank[normalizeConfidence(a.confidence)];
      if (confidenceDiff) {return confidenceDiff;}
    }

    const fileDiff = displayPath(a.file).localeCompare(displayPath(b.file));
    if (fileDiff) {return fileDiff;}
    return Number(a.line || 0) - Number(b.line || 0);
  }

  function renderFinding(finding, index) {
    const severity = normalizeSeverity(finding.securitySeverity);
    const confidence = normalizeConfidence(finding.confidence);
    const line = Number(finding.line || 1);
    const column = Number(finding.column || 1);
    const location = `${displayPath(finding.file)}:${line}`;
    const functionName = finding.functionName ? `${finding.functionName}()` : "";
    const remediation = finding.remediation
      ? `
        <div class="flusec-remediation">
          <div class="flusec-remediation__label">Recommended remediation</div>
          <p>${escapeHtml(finding.remediation)}</p>
        </div>
      `
      : "";

    const taintDetails = component === "hsd" && Array.isArray(finding.taintFlow) && finding.taintFlow.length
      ? renderTaintDetails(finding)
      : "";

    return `
      <article class="flusec-finding" data-severity="${severity}">
        <div class="flusec-finding__main">
          <div class="flusec-finding__topline">
            <span class="flusec-severity" data-severity="${severity}">${escapeHtml(severity.toUpperCase())}</span>
            <span class="flusec-confidence">${escapeHtml(capitalize(confidence))} confidence</span>
          </div>
          <span class="flusec-rule">${escapeHtml(finding.ruleId || "Unknown rule")}</span>
          <h2 class="flusec-finding__message">${escapeHtml(finding.message || "Security finding")}</h2>
          <div class="flusec-location">
            ${functionName ? `<span><code>${escapeHtml(functionName)}</code></span>` : ""}
            <span><code>${escapeHtml(location)}</code></span>
          </div>
          ${remediation}
          <div class="flusec-finding__actions">
            <button class="flusec-button" type="button" data-open-index="${index}">Open in Editor</button>
          </div>
        </div>
        <div class="flusec-details">
          ${renderEvidenceDetails(finding)}
          ${renderMaintainabilityDetails(finding)}
          ${taintDetails}
          ${renderTechnicalDetails(finding, line, column)}
        </div>
      </article>
    `;
  }

  function renderEvidenceDetails(finding) {
    const rows = component === "hsd"
      ? hsdEvidenceRows(finding)
      : component === "ids"
        ? idsEvidenceRows(finding)
        : component === "iiv"
          ? iivEvidenceRows(finding)
          : netEvidenceRows(finding);

    return detailsBlock("Evidence", detailGrid(rows, "flusec-evidence"));
  }

  function hsdEvidenceRows(finding) {
    const e = objectValue(finding.evidence);
    return compactRows([
      ["Provider", e.provider],
      ["Secret Type", humanize(finding.secretType)],
      ["Detection", humanize(e.detectionMethod)],
      ["Context", codeValue(e.context)],
      ["Masked Value", codeValue(e.maskedValue)],
      ["Entropy", numberValue(e.entropy)],
      ["Value Length", numberValue(e.valueLength)],
    ]);
  }

  function idsEvidenceRows(finding) {
    const e = objectValue(finding.evidence);
    const protection = typeof e.protectionDetected === "boolean"
      ? `<span class="flusec-status-text">${e.protectionDetected ? "Detected" : "Not detected"}</span>`
      : undefined;

    return compactRows([
      ["Data Type", humanize(finding.dataType || e.dataType)],
      ["Storage Context", humanize(finding.storageContext || e.storageContext)],
      ["Sink", codeValue(e.sink)],
      ["Storage Key", codeValue(e.storageKey)],
      ["Browser Storage", codeValue(e.browserStorage)],
      ["Protection", protection, true],
      ["Value", e.valueRedacted === true ? "Redacted" : undefined],
      ["Sensitive Evidence", e.sensitiveEvidence],
      ["Analysis Scope", humanize(e.analysisScope)],
    ]);
  }

  function iivEvidenceRows(finding) {
    const e = objectValue(finding.evidence);
    return compactRows([
      ["Check", humanize(e.checkKey)],
      ["Source", codeValue(e.source)],
      ["Sink", codeValue(e.sink)],
      ["Widget", codeValue(e.widget)],
      ["Query Expression", codeValue(e.queryExpression)],
      ["Parameter List", detectedStatus(e.parameterListDetected)],
      ["Dynamic Arguments", arrayValue(e.dynamicArguments)],
      ["File Type", codeValue(e.fileType)],
      ["Allowed Extensions", detectedStatus(e.allowedExtensionsDetected)],
      ["Deep-link Variables", arrayValue(e.deepLinkVariables)],
      ["Direct Source to Sink", yesNo(e.directSourceToSink)],
      ["Validation Guard", detectedStatus(e.validationGuardDetected)],
      ["Validator", detectedStatus(e.validatorDetected)],
      ["Read Only", yesNo(e.readOnly)],
      ["Enabled", yesNo(e.enabled)],
      ["Analysis Scope", humanize(e.analysisScope)],
      ["Note", e.note],
    ]);
  }

  function netEvidenceRows(finding) {
    const e = objectValue(finding.evidence);
    return compactRows([
      ["Type", humanize(e.type)],
      ["Scheme", codeValue(e.scheme)],
      ["Endpoint", codeValue(e.url || e.fallbackUrl)],
      ["API", codeValue(e.api)],
      ["Behavior", humanize(e.behavior)],
      ["Configuration", codeValue(e.configuration)],
      ["Credentials Redacted", yesNo(e.credentialsRedacted)],
    ]);
  }

  function renderMaintainabilityDetails(finding) {
    const hasContext = [
      finding.complexity,
      finding.nestingDepth,
      finding.functionLoc,
      finding.maintainabilityScore,
    ].some((value) => typeof value === "number");

    if (!hasContext) {
      return detailsBlock(
        "Maintainability Context",
        `<p class="flusec-maintainability-note">Maintainability context is unavailable because this finding is outside a recognized executable function/method scope.</p>`
      );
    }

    const rows = compactRows([
      ["MCS", typeof finding.maintainabilityScore === "number" ? `${finding.maintainabilityScore} / 100` : undefined],
      ["Level", capitalize(finding.maintainabilityLevel)],
      ["Cyclomatic Complexity", numberValue(finding.complexity)],
      ["Nesting Depth", numberValue(finding.nestingDepth)],
      ["Function LOC", numberValue(finding.functionLoc)],
    ]);

    return detailsBlock(
      "Maintainability Context",
      `${detailGrid(rows)}<p class="flusec-maintainability-note">Maintainability context is independent of security severity and detection confidence.</p>`
    );
  }

  function renderTaintDetails(finding) {
    const steps = [
      {
        type: "SOURCE",
        line: finding.line,
        column: finding.column,
        description: finding.functionName
          ? `Hardcoded secret source in ${finding.functionName}()`
          : "Hardcoded secret source",
      },
      ...finding.taintFlow,
    ];

    const items = steps.map((step) => `
      <li class="flusec-taint__step">
        <div class="flusec-taint__type">${escapeHtml(humanize(step.type) || "Flow step")}</div>
        <div class="flusec-taint__meta">Line ${escapeHtml(String(step.line || "—"))}${step.column ? `, column ${escapeHtml(String(step.column))}` : ""}</div>
        ${step.description ? `<div class="flusec-taint__description">${escapeHtml(step.description)}</div>` : ""}
      </li>
    `).join("");

    return detailsBlock(
      `Taint Flow · ${steps.length} steps`,
      `<ol class="flusec-taint">${items}</ol>`
    );
  }

  function renderTechnicalDetails(finding, line, column) {
    const e = objectValue(finding.evidence);
    const rows = compactRows([
      ["Rule ID", codeValue(finding.ruleId)],
      ["Component", String(finding.component || component).toUpperCase()],
      ["CWE", codeValue(finding.cwe)],
      ["Category", humanize(finding.category)],
      ["Fingerprint", codeValue(finding.fingerprint)],
      ["File", codeValue(finding.file)],
      ["Line / Column", `${line} / ${column}`],
      ["Analysis Scope", humanize(e.analysisScope)],
    ]);

    return detailsBlock("Technical Details", detailGrid(rows, "flusec-tech"));
  }

  function detailsBlock(title, content) {
    return `
      <details>
        <summary>${escapeHtml(title)}</summary>
        <div class="flusec-details__content">${content}</div>
      </details>
    `;
  }

  function detailGrid(rows, className = "") {
    if (!rows.length) {
      return `<p class="flusec-maintainability-note">No additional structured evidence is available for this finding.</p>`;
    }

    return `
      <dl class="flusec-detail-grid ${className}">
        ${rows.map(([label, value, raw]) => {
          const renderedValue = isHtmlValue(value)
            ? value.html
            : raw
              ? String(value)
              : escapeHtml(String(value));
          return `
            <dt>${escapeHtml(label)}</dt>
            <dd>${renderedValue}</dd>
          `;
        }).join("")}
      </dl>
    `;
  }

  function compactRows(rows) {
    return rows.filter((row) => row[1] !== undefined && row[1] !== null && row[1] !== "");
  }

  function codeValue(value) {
    if (value === undefined || value === null || value === "") {return undefined;}
    return htmlValue(`<code>${escapeHtml(String(value))}</code>`);
  }

  function htmlValue(html) {
    return { __flusecHtml: true, html };
  }

  function isHtmlValue(value) {
    return Boolean(value && typeof value === "object" && value.__flusecHtml === true);
  }

  function detectedStatus(value) {
    if (typeof value !== "boolean") {return undefined;}
    return value ? "Detected" : "Not detected";
  }

  function yesNo(value) {
    if (typeof value !== "boolean") {return undefined;}
    return value ? "Yes" : "No";
  }

  function arrayValue(value) {
    if (!Array.isArray(value) || value.length === 0) {return undefined;}
    return value.map((item) => String(item)).join(", ");
  }

  function numberValue(value) {
    return typeof value === "number" && Number.isFinite(value) ? String(value) : undefined;
  }

  function objectValue(value) {
    return value && typeof value === "object" && !Array.isArray(value) ? value : {};
  }

  function populateExtraFilters() {
    const region = document.getElementById("moreFilters");
    const button = document.getElementById("btnMoreFilters");
    if (!region || !button) {return;}

    const definitions = extraFilterDefinitions();
    if (!definitions.length) {
      region.hidden = true;
      button.hidden = true;
      return;
    }

    button.hidden = false;
    region.innerHTML = definitions.map((definition) => {
      const values = Array.from(new Set(
        state.findings
          .map((finding) => extraFilterValue(finding, definition.key))
          .filter(Boolean)
      )).sort((a, b) => a.localeCompare(b));

      const selectedValue = String(state.extraFilters[definition.key] || "");
      const options = [
        `<option value=""${selectedValue ? "" : " selected"}>All</option>`,
        ...values.map((value) => `<option value="${escapeAttr(value)}"${selectedValue === value ? " selected" : ""}>${escapeHtml(humanize(value) || value)}</option>`),
      ].join("");

      return `
        <div class="flusec-filter-field">
          <label for="extra-${escapeAttr(definition.key)}">${escapeHtml(definition.label)}</label>
          <select id="extra-${escapeAttr(definition.key)}" class="flusec-select" data-filter-key="${escapeAttr(definition.key)}">
            ${options}
          </select>
        </div>
      `;
    }).join("");
  }

  function extraFilterDefinitions() {
    if (component === "hsd") {
      return [
        { key: "secretType", label: "Secret Type" },
        { key: "provider", label: "Provider" },
      ];
    }
    if (component === "ids") {
      return [
        { key: "dataType", label: "Data Type" },
        { key: "storageContext", label: "Storage Context" },
      ];
    }
    if (component === "iiv") {
      return [
        { key: "category", label: "Category" },
        { key: "ruleId", label: "Rule" },
      ];
    }
    if (component === "net") {
      return [
        { key: "findingType", label: "Finding Type" },
        { key: "ruleId", label: "Rule" },
      ];
    }
    return [];
  }

  function extraFilterValue(finding, key) {
    const evidence = objectValue(finding.evidence);
    switch (key) {
      case "provider":
        return String(evidence.provider || "");
      case "findingType":
        return String(evidence.type || "");
      default:
        return String(finding[key] || "");
    }
  }

  function renderCoupling() {
    if (component !== "net") {return;}

    const container = document.getElementById("couplingContent");
    if (!container) {return;}

    const payload = state.coupling;
    if (!payload) {
      container.innerHTML = stateMarkup(
        "Loading architecture context",
        "FLUSEC is calculating network coupling from the current workspace."
      );
      return;
    }

    const modules = Array.isArray(payload.modules) ? payload.modules : [];
    const services = Array.isArray(payload.services) ? payload.services : [];
    const cdOut = objectValue(payload.cdOut);
    const afferent = objectValue(payload.afferent);
    const avgOut = average(modules.map((name) => Number(cdOut[name] || 0)));
    const avgIn = average(services.map((name) => Number(afferent[name] || 0)));

    container.innerHTML = `
      <div class="flusec-coupling-summary">
        ${couplingSummaryItem("Modules", modules.length)}
        ${couplingSummaryItem("Services", services.length)}
        ${couplingSummaryItem("Avg. outgoing", formatDecimal(avgOut))}
        ${couplingSummaryItem("Avg. incoming", formatDecimal(avgIn))}
      </div>
      <p class="flusec-coupling-note">Coupling metrics describe architectural dependency characteristics. They do not change security severity, detection confidence, or Maintainability Context Score.</p>
      <div class="flusec-coupling-grid">
        <section class="flusec-coupling-card">
          <h3>Outgoing coupling by module</h3>
          ${barList(modules, cdOut, "No literal network dependencies were found for project modules.")}
        </section>
        <section class="flusec-coupling-card">
          <h3>Incoming coupling by service</h3>
          ${barList(services, afferent, "No literal service dependencies were found in the scanned scope.")}
        </section>
      </div>
    `;
  }

  function couplingSummaryItem(label, value) {
    return `
      <div class="flusec-coupling-summary__item">
        <span class="flusec-coupling-summary__label">${escapeHtml(label)}</span>
        <span class="flusec-coupling-summary__value">${escapeHtml(String(value))}</span>
      </div>
    `;
  }

  function barList(labels, values, emptyMessage) {
    if (!labels.length) {
      return `<p class="flusec-coupling-note">${escapeHtml(emptyMessage)}</p>`;
    }

    const numeric = labels.map((label) => Number(values[label] || 0));
    const max = Math.max(1, ...numeric);

    return `
      <div class="flusec-bar-list">
        ${labels.map((label) => {
          const value = Number(values[label] || 0);
          const width = Math.max(2, Math.round((value / max) * 100));
          return `
            <div class="flusec-bar-row" title="${escapeAttr(label)}: ${value}">
              <span class="flusec-bar-row__label">${escapeHtml(label)}</span>
              <span class="flusec-bar-row__track"><span class="flusec-bar-row__fill" style="width:${width}%"></span></span>
              <span class="flusec-bar-row__value">${value}</span>
            </div>
          `;
        }).join("")}
      </div>
    `;
  }

  function average(values) {
    if (!values.length) {return 0;}
    return values.reduce((sum, value) => sum + value, 0) / values.length;
  }

  function formatDecimal(value) {
    return Number.isInteger(value) ? String(value) : value.toFixed(2);
  }

  function normalizeSeverity(value) {
    const raw = String(value || "low").toLowerCase();
    return severityRank[raw] ? raw : "low";
  }

  function normalizeConfidence(value) {
    const raw = String(value || "low").toLowerCase();
    return confidenceRank[raw] ? raw : "low";
  }

  function humanize(value) {
    if (value === undefined || value === null || value === "") {return "";}
    return String(value)
      .replace(/[_-]+/g, " ")
      .replace(/\s+/g, " ")
      .trim()
      .replace(/\b\w/g, (char) => char.toUpperCase());
  }

  function capitalize(value) {
    const text = String(value || "");
    return text ? text.charAt(0).toUpperCase() + text.slice(1).toLowerCase() : "";
  }

  function displayPath(value) {
    const text = String(value || "");
    if (!text) {return "Unknown file";}
    const parts = text.replace(/\\/g, "/").split("/").filter(Boolean);
    return parts.slice(-2).join("/") || text;
  }

  function setText(id, value) {
    const element = document.getElementById(id);
    if (element) {element.textContent = String(value);}
  }

  function escapeHtml(value) {
    return String(value ?? "")
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }

  function escapeAttr(value) {
    return escapeHtml(value);
  }
})();
