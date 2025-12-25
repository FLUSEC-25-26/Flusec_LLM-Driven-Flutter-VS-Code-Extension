
// src/netChartScript.ts
// return the exact inline messaging + Chart.js script as a string.
// Runs in the webview (browser) when injected into the HTML.
// No build step needed for this file.

export function getNetChartMessagingScript(nonce: string): string {
  return `
<script nonce="${nonce}">
  // The VS Code webview API is injected globally.
  const vscode = acquireVsCodeApi();

  function send(type, payload) {
    vscode.postMessage({ type, payload });
  }

  // Charts and state
  let findingsChart; // warnings per rule
  let cdOutChart, cdInChart; // coupling charts
  let lastItems = [];

  // ---- Bootstrap ----
  window.addEventListener('DOMContentLoaded', () => {
    const btnRescan = document.getElementById('btnRescan');
    const btnRefresh = document.getElementById('btnRefresh');
    const filterInput = document.getElementById('filterInput');

    btnRescan?.addEventListener('click', () => send('rescanActiveFile'));
    btnRefresh?.addEventListener('click', () => send('refreshFindings'));

    filterInput?.addEventListener('input', (e) => {
      const q = (e.target?.value ?? '').toLowerCase();
      filterList(q);
    });

    // Notify extension ready
    send('ready');
  });

  // ---- Message handling from extension ----
  window.addEventListener('message', (event) => {
    const msg = event.data;
    if (!msg) return;

    if (msg.type === 'diagnostics') {
      const items = msg.payload ?? [];
      renderFindings(items);       // list
      renderWarningsChart(items);  // chart
    }

    if (msg.type === 'coupling-data') {
      const p = msg.payload ?? {};
      // KPI: Health Index
      const kpi = document.getElementById('kpi-health-index');
      if (kpi) {
        kpi.textContent = (p.healthIndex != null)
          ? String(Math.round(p.healthIndex))
          : '—';
        if (p.healthComponents) {
          const c = p.healthComponents;
          kpi.title = \`Outgoing risk: \${Math.round(c.riskOut)}
Incoming risk: \${Math.round(c.riskIn)}
Redundancy: \${Math.round(((c.redundancyRatio ?? 0) * 100))}%\`;
        }
      }
      renderCouplingCharts(p);
    }
  });

  // ---- Findings list (unchanged) ----
  function renderFindings(items) {
    lastItems = items;
    const list = document.getElementById('issues-list');
    const countEl = document.getElementById('issues-count');

    if (countEl) countEl.textContent = String(items.length);
    if (!list) return;

    list.innerHTML = '';
    for (const it of items) {
      const li = document.createElement('li');
      li.className = 'issue-item';
      li.innerHTML = \`
        <div class="issue-head">
          <span class="badge badge-\${it.severity}">\${it.severity}</span>
          <span class="issue-message">\${escapeHtml(it.message)}</span>
        </div>
        <div class="issue-meta">
          <code class="file">\${escapeHtml(it.file)}</code>
          <span>Line \${it.line}, Col \${it.column}</span>
          \${it.code ? \`<span class="rule">[\${escapeHtml(String(it.code))}]</span>\` : ''}
          <button class="open-btn" aria-label="Open file">Open</button>
        </div>
      \`;
      li.querySelector('.open-btn')?.addEventListener('click', () => {
        send('openFile', it.file);
      });
      list.appendChild(li);
    }
  }

  function filterList(q) {
    const list = document.getElementById('issues-list');
    if (!list) return;

    list.innerHTML = '';
    const filtered = !q ? lastItems : lastItems.filter(it =>
      String(it.message).toLowerCase().includes(q) ||
      String(it.file).toLowerCase().includes(q) ||
      String(it.code ?? '').toLowerCase().includes(q)
    );

    for (const it of filtered) {
      const li = document.createElement('li');
      li.className = 'issue-item';
      li.innerHTML = \`
        <div class="issue-head">
          <span class="badge badge-\${it.severity}">\${it.severity}</span>
          <span class="issue-message">\${escapeHtml(it.message)}</span>
        </div>
        <div class="issue-meta">
          <code class="file">\${escapeHtml(it.file)}</code>
          <span>Line \${it.line}, Col \${it.column}</span>
          \${it.code ? \`<span class="rule">[\${escapeHtml(String(it.code))}]</span>\` : ''}
          <button class="open-btn" aria-label="Open file">Open</button>
        </div>
      \`;
      li.querySelector('.open-btn')?.addEventListener('click', () => {
        send('openFile', it.file);
      });
      list.appendChild(li);
    }

    const countEl = document.getElementById('issues-count');
    if (countEl) countEl.textContent = String(filtered.length);

    // 🔄 Update warnings chart with filtered set
    renderWarningsChart(filtered);
  }

  function escapeHtml(str) {
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/\\\"/g, '&quot;')
      .replace(/'/g, '&#039;');
  }

  // ---- Warnings per Rule (bar) ----
  function renderWarningsChart(items) {
    // Only warnings
    const warnings = (items ?? []).filter(it =>
      String(it.severity).toLowerCase() === 'warning'
    );

    // Aggregate by rule (code)
    const ruleCounts = {};
    for (const it of warnings) {
      const key = String(it.code ?? 'unknown');
      ruleCounts[key] = (ruleCounts[key] ?? 0) + 1;
    }

    const labels = Object.keys(ruleCounts);
    const data = labels.map(k => ruleCounts[k]);

    const ctx = document.getElementById('chart-findings-by-rule');
    if (!ctx || typeof Chart === 'undefined') return;

    const fg = getComputedStyle(document.documentElement).getPropertyValue('--fg') || '#e0e0e0';

    if (findingsChart) findingsChart.destroy();
    findingsChart = new Chart(ctx, {
      type: 'bar',
      data: {
        labels,
        datasets: [{
          label: 'Warnings',
          data,
          backgroundColor: 'rgba(245, 158, 11, 0.45)', // orange
          borderColor: 'rgb(245, 158, 11)',
          borderWidth: 1
        }]
      },
      options: {
        scales: {
          x: { ticks: { color: fg } },
          y: { ticks: { color: fg }, beginAtZero: true, precision: 0 }
        },
        plugins: {
          legend: { labels: { color: fg } },
          tooltip: { enabled: true }
        },
        animation: { duration: 200 }
      }
    });
  }

  // ---- Coupling charts (Outgoing per module, Incoming per service) ----
  function renderCouplingCharts(payload) {
    if (!payload) return;

    const fg = getComputedStyle(document.documentElement).getPropertyValue('--fg') || '#e0e0e0';
    const modules = payload.modules ?? [];
    const services = payload.services ?? [];
    const outData = modules.map(m => payload.cdOut?.[m] ?? 0);
    const inData = services.map(s => payload.afferent?.[s] ?? 0);

    // Outgoing (modules)
    const ctxOut = document.getElementById('chart-cd-out');
    if (ctxOut && typeof Chart !== 'undefined') {
      cdOutChart?.destroy();
      cdOutChart = new Chart(ctxOut, {
        type: 'bar',
        data: {
          labels: modules,
          datasets: [{
            label: 'Outgoing deps',
            data: outData,
            backgroundColor: 'rgba(54, 162, 235, 0.5)',
            borderColor: 'rgb(54, 162, 235)',
            borderWidth: 1
          }]
        },
        options: {
          scales: {
            x: { ticks: { color: fg } },
            y: { ticks: { color: fg }, beginAtZero: true, precision: 0 }
          },
          plugins: { legend: { labels: { color: fg } } },
          animation: { duration: 200 }
        }
      });
    }

    // Incoming (services, horizontal)
    const ctxIn = document.getElementById('chart-cd-in');
    if (ctxIn && typeof Chart !== 'undefined') {
      cdInChart?.destroy();
      cdInChart = new Chart(ctxIn, {
        type: 'bar',
        data: {
          labels: services,
          datasets: [{
            label: 'Incoming deps',
            data: inData,
            backgroundColor: 'rgba(16, 185, 129, 0.45)',
            borderColor: 'rgb(16, 185, 129)',
            borderWidth: 1
          }]
        },
        options: {
          indexAxis: 'y',
          scales: {
            x: { ticks: { color: fg }, beginAtZero: true, precision: 0 },
            y: { ticks: { color: fg } }
          },
          plugins: { legend: { labels: { color: fg } } },
          animation: { duration: 200 }
        }
      });
    }
  }
</script>
  `;
}
