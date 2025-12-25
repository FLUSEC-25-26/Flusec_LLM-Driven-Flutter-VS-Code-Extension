
import * as vscode from 'vscode';
import { spawn } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
// If you already have this LLM feedback function, keep it. Otherwise you can comment this import out.
import { getLLMFeedback } from './llm';
import { computeAndPostCoupling } from './couplingAnalysis'; // NEW

const collection = vscode.languages.createDiagnosticCollection('flusec');
const out = vscode.window.createOutputChannel('FLUSEC');

const tempPathToUntitledUri = new Map<string, vscode.Uri>();
// Shadow map to feed the dashboard with a snapshot of current diagnostics.
const currentDiagnostics = new Map<string, vscode.Diagnostic[]>();

export function activate(context: vscode.ExtensionContext) {
  logAnalyzerLocations(context); // logs analyzer candidates to Output: FLUSEC

  // Example existing command
  const scanCmd = vscode.commands.registerCommand('flusec.helloWorld', () => scanAll(context));
  context.subscriptions.push(scanCmd);

  // ✅ Dashboard command (opens src/web/dashboard.html)
  const openDashboardCmd = vscode.commands.registerCommand('flusec.openDashboard', async () => {
    const panel = vscode.window.createWebviewPanel(
      'flusecDashboard',
      'FLUSEC – Network Dashboard',
      vscode.ViewColumn.One,
      {
        enableScripts: true,
        retainContextWhenHidden: true,
        localResourceRoots: [
          vscode.Uri.file(path.join(context.extensionPath, 'src', 'web')), // allow files from src/web
        ],
      }
    );

    // Compute webview-safe URIs for assets
    const htmlPath = path.join(context.extensionPath, 'src', 'web', 'dashboard.html');
    const rawHtml = fs.readFileSync(htmlPath, 'utf8');
    const styleHref = panel.webview.asWebviewUri(
      vscode.Uri.file(path.join(context.extensionPath, 'src', 'web', 'style.css'))
    ).toString();

    // ✅ Local Chart.js (UMD/minified). Place file at src/web/chart.min.js
    const chartHref = panel.webview.asWebviewUri(
      vscode.Uri.file(path.join(context.extensionPath, 'src', 'web', 'chart.min.js'))
    ).toString();

    // Build final HTML (inject CSP + messaging script + hrefs + nonce)
    panel.webview.html = buildDashboardHtml(panel.webview, rawHtml, { styleHref, chartHref });

    // Receive messages from dashboard
    panel.webview.onDidReceiveMessage(async (msg) => {
      switch (msg?.type) {
        case 'ready': {
          panel.webview.postMessage({
            type: 'diagnostics',
            payload: collectCurrentDiagnostics(),
          });
          await computeAndPostCoupling(panel); // NEW: send coupling + health
          break;
        }
        case 'rescanActiveFile': {
          const active = vscode.window.activeTextEditor?.document;
          if (active && active.languageId === 'dart') {
            await scanDocument(context, active);
          }
          panel.webview.postMessage({
            type: 'diagnostics',
            payload: collectCurrentDiagnostics(),
          });
          await computeAndPostCoupling(panel); // NEW
          break;
        }
        case 'refreshFindings': {
          panel.webview.postMessage({
            type: 'diagnostics',
            payload: collectCurrentDiagnostics(),
          });
          await computeAndPostCoupling(panel); // NEW
          break;
        }
        case 'openFile': {
          const fsPath: string | undefined = msg?.payload;
          if (fsPath) {
            const doc = await vscode.workspace.openTextDocument(vscode.Uri.file(fsPath));
            await vscode.window.showTextDocument(doc, vscode.ViewColumn.One);
          }
          break;
        }
        default:
          break;
      }
    });
  });
  context.subscriptions.push(openDashboardCmd);

  // Hover provider for LLM feedback (optional, keep if you already have llm.ts)
  const hoverProvider = vscode.languages.registerHoverProvider({ language: 'dart' }, {
    provideHover: async (doc, pos) => {
      const diags = collection.get(doc.uri) ?? [];
      const diag = diags.find(d => d.range.contains(pos));
      if (!diag) return;
      const feedback = await getLLMFeedback(diag.message);
      const md = new vscode.MarkdownString();
      md.isTrusted = true;
      md.appendCodeblock(feedback, 'json');
      return new vscode.Hover(md);
    }
  });
  context.subscriptions.push(hoverProvider);

  // Events: open/save/active editor
  context.subscriptions.push(vscode.workspace.onDidOpenTextDocument(doc => {
    if (doc.languageId === 'dart') scanDocument(context, doc);
  }));
  context.subscriptions.push(vscode.workspace.onDidSaveTextDocument(doc => {
    if (doc.languageId === 'dart') scanDocument(context, doc);
  }));
  context.subscriptions.push(vscode.window.onDidChangeActiveTextEditor(ed => {
    const doc = ed?.document;
    if (doc?.languageId === 'dart') scanDocument(context, doc);
  }));

  // Debounced typing scan
  let debounce: NodeJS.Timeout | undefined;
  context.subscriptions.push(vscode.workspace.onDidChangeTextDocument(e => {
    if (e.document.languageId !== 'dart') return;
    if (debounce) clearTimeout(debounce);
    debounce = setTimeout(() => scanDocument(context, e.document), 250);
  }));

  // Watcher for .dart files
  const watcher = vscode.workspace.createFileSystemWatcher('**/*.dart');
  context.subscriptions.push(watcher);
  watcher.onDidCreate(uri => runAnalyzerForPath(context, uri.fsPath));
  watcher.onDidChange(uri => runAnalyzerForPath(context, uri.fsPath));
  watcher.onDidDelete(uri => {
    collection.delete(uri);
    currentDiagnostics.delete(uri.fsPath);
  });

  // Initial scan
  scanAll(context);
}

export function deactivate() {}

/** Scan all open Dart docs */
async function scanAll(context: vscode.ExtensionContext) {
  for (const doc of vscode.workspace.textDocuments.filter(d => d.languageId === 'dart')) {
    await scanDocument(context, doc);
  }
}

/** Scan a single document (active or saved). */
async function scanDocument(context: vscode.ExtensionContext, doc: vscode.TextDocument) {
  if (!doc || doc.languageId !== 'dart') return;

  // Smoke test warning for 'http://'
  smokeTestDiagnostics(doc);

  if (!doc.isUntitled) {
    await runAnalyzer(context, [doc.uri.fsPath]);
    return;
  }

  // Untitled docs: write to a temp file and analyze
  const tmpPath = path.join(os.tmpdir(), `flusec_${Date.now()}.dart`);
  try {
    fs.writeFileSync(tmpPath, doc.getText(), 'utf8');
    tempPathToUntitledUri.set(tmpPath, doc.uri);
    await runAnalyzer(context, [tmpPath]);
  } catch (err) {
    vscode.window.showErrorMessage(`FLUSEC: failed to analyze untitled doc (${String(err)})`);
  } finally {
    setTimeout(() => { try { fs.unlinkSync(tmpPath); } catch { /* ignore */ } }, 1500);
  }
}

/** Run analyzer for a given path (single file). */
function runAnalyzerForPath(context: vscode.ExtensionContext, fsPath: string) {
  return runAnalyzer(context, [fsPath], path.dirname(fsPath));
}

/** Resolve analyzer command (exe or dart script). */
function resolveAnalyzerCommand(context: vscode.ExtensionContext): { cmd: string; args: string[] } | null {
  const candidates = [
    context.asAbsolutePath('bin/analyzer.exe'),
    context.asAbsolutePath('bin/analyzer'),
    context.asAbsolutePath('bin/analyzer.dart'),
    context.asAbsolutePath('dart-analyzer/bin/analyzer.exe'),
    context.asAbsolutePath('dart-analyzer/bin/analyzer'),
    context.asAbsolutePath('dart-analyzer/bin/analyzer.dart'),
  ];
  for (const c of candidates) {
    if (fs.existsSync(c)) {
      if (c.endsWith('.dart')) return { cmd: 'dart', args: ['run', c] };
      return { cmd: c, args: [] };
    }
  }
  return null;
}

/**
 * Spawn analyzer.
 * @param analyzerArgs We pass ONLY the file path (no "--src").
 * @param cwd Optional working directory.
 */
async function runAnalyzer(context: vscode.ExtensionContext, analyzerArgs: string[], cwd?: string): Promise<void> {
  const cmd = resolveAnalyzerCommand(context);
  if (!cmd) {
    vscode.window.showErrorMessage('FLUSEC: analyzer not found. Put dart_analyzer(.exe) in flusec/bin/ or dart-analyzer/bin/.');
    return;
  }

  out.appendLine(`[runAnalyzer] cmd=${cmd.cmd}`);
  out.appendLine(`[runAnalyzer] args=${JSON.stringify([...cmd.args, ...analyzerArgs])}`);
  if (cwd) out.appendLine(`[runAnalyzer] cwd=${cwd}`);

  const child = spawn(cmd.cmd, [...cmd.args, ...analyzerArgs], { cwd, shell: false });
  let stdout = '';
  let stderr = '';

  child.stdout.on('data', d => (stdout += d.toString()));
  child.stderr.on('data', d => (stderr += d.toString()));
  child.on('error', err => {
    vscode.window.showErrorMessage(`FLUSEC: analyzer failed to start (${String(err)})`);
    out.appendLine(`[error] ${String(err)}`);
  });
  child.on('close', code => {
    out.appendLine(`[runAnalyzer] exit code=${code}`);
    if (stderr) out.appendLine(`[stderr]\n${stderr}`);
    if (!stdout) { out.appendLine(`[stdout] (empty)`); return; }

    // Parse: Issue[] | {issues: Issue[]} | {findings: Finding[]}
    let parsed: any;
    try { parsed = JSON.parse(stdout); } catch (e) {
      out.appendLine(`[parse error] ${String(e)}\nRaw stdout:\n${stdout}`);
      vscode.window.showErrorMessage('FLUSEC: analyzer output could not be parsed.');
      return;
    }

    const srcPath = analyzerArgs[0] ?? '';
    if (Array.isArray(parsed)) {
      applyDiagnosticsFromIssues(parsed, srcPath);
      if (srcPath && srcPath.endsWith('.dart')) {
        vscode.window.showInformationMessage(`FLUSEC: ${parsed.length} findings in ${path.basename(srcPath)}.`);
      }
    } else {
      const findings = (parsed.findings ?? parsed.issues ?? []) as any[];
      applyDiagnosticsFromFindings(findings);
      if (srcPath && srcPath.endsWith('.dart')) {
        vscode.window.showInformationMessage(`FLUSEC: ${findings.length} findings in ${path.basename(srcPath)}.`);
      }
    }
  });
}

/** Apply diagnostics for the legacy 'findings' shape (file+range). */
function applyDiagnosticsFromFindings(findings: any[]) {
  const byUriStr = new Map<string, vscode.Diagnostic[]>();

  for (const f of findings) {
    const analyzedPath: string = f.file;
    const untitledUri = tempPathToUntitledUri.get(analyzedPath);
    const targetUri = untitledUri ?? vscode.Uri.file(analyzedPath);

    const startLC = f.range?.start;
    const endLC = f.range?.end;
    let range: vscode.Range;

    const hasLineCols =
      startLC?.line !== undefined &&
      startLC?.column !== undefined &&
      endLC?.line !== undefined &&
      endLC?.column !== undefined;

    if (hasLineCols) {
      range = new vscode.Range(
        new vscode.Position(startLC.line - 1, startLC.column - 1),
        new vscode.Position(endLC.line - 1, endLC.column - 1),
      );
    } else {
      const startOffset = f.range?.start?.offset ?? 0;
      const endOffset = f.range?.end?.offset ?? startOffset;
      range = new vscode.Range(
        docPosByOffsetForUri(targetUri, startOffset),
        docPosByOffsetForUri(targetUri, endOffset),
      );
    }

    const diag = new vscode.Diagnostic(range, f.message, vscode.DiagnosticSeverity.Warning);
    diag.code = f.code ?? f.ruleId ?? 'flusec';
    diag.source = 'flusec';

    const key = targetUri.toString();
    const arr = byUriStr.get(key) ?? [];
    arr.push(diag);
    byUriStr.set(key, arr);
  }

  collection.clear();
  currentDiagnostics.clear();

  for (const [uriStr, diags] of byUriStr.entries()) {
    const uri = vscode.Uri.parse(uriStr);
    collection.set(uri, diags);
    currentDiagnostics.set(uri.fsPath, diags);
  }
}

/** Apply diagnostics for Issue[] shape. */
function applyDiagnosticsFromIssues(issues: any[], srcPath: string) {
  const targetUri = tempPathToUntitledUri.get(srcPath) ?? vscode.Uri.file(srcPath);
  const diags: vscode.Diagnostic[] = [];

  for (const i of issues) {
    const line = Number(i.line ?? 1);
    const column = Number(i.column ?? 1);
    const start = new vscode.Position(Math.max(0, line - 1), Math.max(0, column - 1));
    const end = new vscode.Position(Math.max(0, line - 1), Math.max(0, column));
    const range = new vscode.Range(start, end);

    const msg = String(i.message ?? i.ruleId ?? 'FLUSEC issue');
    const diag = new vscode.Diagnostic(range, msg, vscode.DiagnosticSeverity.Warning);
    diag.code = String(i.ruleId ?? 'flusec');
    diag.source = 'flusec';
    diags.push(diag);
  }

  collection.set(targetUri, diags);
  currentDiagnostics.set(targetUri.fsPath, diags);
}

function docPosByOffsetForUri(uri: vscode.Uri, offset: number): vscode.Position {
  const doc = vscode.workspace.textDocuments.find(d => d.uri.toString() === uri.toString());
  if (!doc) return new vscode.Position(0, 0);
  const text = doc.getText();
  let line = 0, ch = 0;
  for (let i = 0; i < Math.min(offset, text.length); i++) {
    if (text[i] === '\n') { line++; ch = 0; } else { ch++; }
  }
  return new vscode.Position(line, ch);
}

/** Smoke test: a single warning for the first 'http://' */
function smokeTestDiagnostics(doc: vscode.TextDocument) {
  if (doc.languageId !== 'dart') return;
  const text = doc.getText();
  const idx = text.indexOf('http://');
  if (idx < 0) {
    collection.set(doc.uri, []);
    currentDiagnostics.set(doc.uri.fsPath, []);
    return;
  }
  const start = doc.positionAt(idx);
  const end = doc.positionAt(idx + 'http://'.length);
  const d = new vscode.Diagnostic(
    new vscode.Range(start, end),
    'Insecure HTTP detected (smoke test). Analyzer will refine this.',
    vscode.DiagnosticSeverity.Warning
  );
  d.code = 'flusec_smoke';
  d.source = 'flusec';
  collection.set(doc.uri, [d]);
  currentDiagnostics.set(doc.uri.fsPath, [d]);
}

/** Debug: log analyzer locations */
function logAnalyzerLocations(context: vscode.ExtensionContext) {
  const candidates = [
    'bin/analyzer.exe',
    'bin/analyzer',
    'bin/analyzer.dart',
    'dart-analyzer/bin/analyzer.exe',
    'dart-analyzer/bin/analyzer',
    'dart-analyzer/bin/analyzer.dart'
  ];
  out.appendLine('---- FLUSEC analyzer location check ----');
  for (const rel of candidates) {
    const abs = context.asAbsolutePath(rel);
    const exists = fs.existsSync(abs);
    out.appendLine(`${abs} exists=${exists}`);
  }
  out.appendLine('----------------------------------------');
}

/** Collect diagnostics snapshot for the dashboard */
function collectCurrentDiagnostics(): Array<{
  file: string;
  message: string;
  code?: string | number;
  severity: 'error' | 'warning' | 'information' | 'hint';
  line: number;
  column: number;
}> {
  const payload: any[] = [];
  for (const [fsPath, diags] of currentDiagnostics.entries()) {
    for (const d of diags) {
      payload.push({
        file: fsPath,
        message: d.message,
        code: d.code,
        severity: severityToString(d.severity),
        line: d.range.start.line + 1,
        column: d.range.start.character + 1
      });
    }
  }
  return payload;
}

function severityToString(s: vscode.DiagnosticSeverity): 'error' | 'warning' | 'information' | 'hint' {
  switch (s) {
    case vscode.DiagnosticSeverity.Error: return 'error';
    case vscode.DiagnosticSeverity.Warning: return 'warning';
    case vscode.DiagnosticSeverity.Information: return 'information';
    case vscode.DiagnosticSeverity.Hint: return 'hint';
    default: return 'warning';
  }
}

/** Build final dashboard HTML: inject CSP + replace hrefs + add messaging & chart logic */
function buildDashboardHtml(
  webview: vscode.Webview,
  rawHtml: string,
  uris: { styleHref: string; chartHref: string }
): string {
  const nonce = getNonce();
  const cspMeta = `
    <meta http-equiv="Content-Security-Policy"
      content="
        default-src 'none';
        img-src ${webview.cspSource} https:;
        style-src ${webview.cspSource} 'unsafe-inline';
        script-src 'nonce-${nonce}';
        font-src ${webview.cspSource} https:;
        connect-src ${webview.cspSource} https:;
      ">
  `;

  // Replace placeholders in the raw HTML
  let html = rawHtml
    .replace(/\{\{styleHref\}\}/g, uris.styleHref)
    .replace(/\{\{chartHref\}\}/g, uris.chartHref)
    .replace(/\{\{nonce\}\}/g, nonce);

  // Insert CSP after <head>
  html = html.replace(/<head>/i, `<head>\n${cspMeta}`);

  // Inject messaging + chart logic
  const messagingScript = `
    <script nonce="${nonce}">
      const vscode = acquireVsCodeApi();
      function send(type, payload) { vscode.postMessage({ type, payload }); }

      let findingsChart; // warnings per rule
      let cdOutChart, cdInChart; // coupling charts
      let lastItems = [];

      window.addEventListener('DOMContentLoaded', () => {
        const btnRescan = document.getElementById('btnRescan');
        const btnRefresh = document.getElementById('btnRefresh');
        const filterInput = document.getElementById('filterInput');

        if (btnRescan) btnRescan.addEventListener('click', () => send('rescanActiveFile'));
        if (btnRefresh) btnRefresh.addEventListener('click', () => send('refreshFindings'));
        if (filterInput) {
          filterInput.addEventListener('input', (e) => {
            const q = (e.target?.value ?? '').toLowerCase();
            filterList(q);
          });
        }

        // Notify extension ready
        send('ready');
      });

      window.addEventListener('message', (event) => {
        const msg = event.data;
        if (!msg) return;

        if (msg.type === 'diagnostics') {
          const items = msg.payload ?? [];
          renderFindings(items);          // list
          renderWarningsChart(items);     // warnings-per-rule
        }

        if (msg.type === 'coupling-data') {
          const p = msg.payload ?? {};
          // Health Index KPI
          const kpi = document.getElementById('kpi-health-index');
          if (kpi) {
            kpi.textContent = (p.healthIndex != null)
              ? String(Math.round(p.healthIndex))
              : '—';
            if (p.healthComponents) {
              const c = p.healthComponents;
              kpi.title = \`Outgoing risk: \${Math.round(c.riskOut)} | Incoming risk: \${Math.round(c.riskIn)} | Redundancy: \${Math.round((c.redundancyRatio ?? 0) * 100)}%\`;
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
          String(it.message).toLowerCase().includes(q)
          || String(it.file).toLowerCase().includes(q)
          || String(it.code ?? '').toLowerCase().includes(q)
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
          .replace(/&/g, '&')
          .replace(/</g, '<')
          .replace(/>/g, '>')
          .replace(/"/g, '"')
          .replace(/'/g, '&#039;');
      }

      // ---- Warnings per Rule (bar) ----
      function renderWarningsChart(items) {
        // Only warnings
        const warnings = (items ?? []).filter(it => String(it.severity).toLowerCase() === 'warning');

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

      // ---- Coupling Charts (Outgoing per module, Incoming per service) ----
      function renderCouplingCharts(payload) {
        if (!payload) return;

        const fg = getComputedStyle(document.documentElement).getPropertyValue('--fg') || '#e0e0e0';
        const modules = payload.modules ?? [];
        const services = payload.services ?? [];

        const outData = modules.map(m => payload.cdOut?.[m] ?? 0);
        const inData  = services.map(s => payload.afferent?.[s] ?? 0);

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

      function getFg() {
        return getComputedStyle(document.documentElement).getPropertyValue('--fg') || '#e0e0e0';
      }
    </script>
  `;

  // Append messaging script before closing </body></html>
  html = html.replace(/<\/body>\s*<\/html>\s*$/i, `${messagingScript}\n</body></html>`);
  return html;
}

function getNonce() {
  const possible = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';
  let text = '';
  for (let i = 0; i < 32; i++) text += possible.charAt(Math.floor(Math.random() * possible.length));
  return text;
}
