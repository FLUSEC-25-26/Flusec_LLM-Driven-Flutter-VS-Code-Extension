// src/web/net/dashboard.ts
//
// Webview dashboard for Insecure Network Communication component.
// Shows: findings list, warnings-per-rule chart, coupling analysis charts, health index.
// Reads from net_findings.json (NET component only).

import * as vscode from "vscode";
import * as fs from "fs";
import * as path from "path";
import { netFindingsPathForFolder } from "../../analyzer/runAnalyzer.js";
import { computeAndPostCoupling } from "../../net/couplingAnalysis.js";
import { getNetChartMessagingScript } from "../../net/netChartScript.js";

// ─── helpers ─────────────────────────────────────────────────────────────────

function getNonce(): string {
  const chars =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  let text = "";
  for (let i = 0; i < 32; i++) {
    text += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return text;
}

// ─── collect NET findings from net_findings.json ────────────────────────────

interface FindingEntry {
  file: string;
  message: string;
  code?: string | number;
  severity: "error" | "warning" | "information" | "hint";
  line: number;
  column: number;
}

function collectNetFindings(folder: vscode.WorkspaceFolder): FindingEntry[] {
  const findingsPath = netFindingsPathForFolder(folder);
  if (!fs.existsSync(findingsPath)) {
    return [];
  }
  try {
    const raw = JSON.parse(fs.readFileSync(findingsPath, "utf8"));
    if (!Array.isArray(raw)) {
      return [];
    }
    // No filter needed — file contains only NET findings
    return raw.map((f: any) => ({
      file: f.file ?? "",
      message: f.message ?? "",
      code: f.code ?? f.ruleId,
      severity: f.severity ?? "warning",
      line: f.line ?? 1, 
      column: f.column ?? 1,
    }));
  } catch {
    return [];
  }
}

// ─── build HTML ──────────────────────────────────────────────────────────────

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

  let html = rawHtml
    .replace(/\{\{styleHref\}\}/g, uris.styleHref)
    .replace(/\{\{chartHref\}\}/g, uris.chartHref)
    .replace(/\{\{nonce\}\}/g, nonce);

  // Inject CSP into <head>
  html = html.replace(/<head>/i, `<head>\n${cspMeta}`);

  // Inject messaging + chart script before </body>
  const messagingScript = getNetChartMessagingScript(nonce);
  html = html.replace(
    /<\/body>\s*<\/html>\s*$/i,
    `${messagingScript}\n</body></html>`
  );

  return html;
}

// ─── open dashboard ──────────────────────────────────────────────────────────

export function openNetDashboard(context: vscode.ExtensionContext) {
  const netWebRoot = vscode.Uri.joinPath(
    context.extensionUri,
    "src",
    "web",
    "net"
  );

  const panel = vscode.window.createWebviewPanel(
    "flusecNetDashboard",
    "FLUSEC – Network Dashboard",
    vscode.ViewColumn.Beside,
    {
      enableScripts: true,
      retainContextWhenHidden: true,
      localResourceRoots: [netWebRoot],
    }
  );

  // Webview-safe URIs
  const htmlPath = vscode.Uri.joinPath(netWebRoot, "dashboard.html");
  const styleHref = panel.webview
    .asWebviewUri(vscode.Uri.joinPath(netWebRoot, "style.css"))
    .toString();
  const chartHref = panel.webview
    .asWebviewUri(vscode.Uri.joinPath(netWebRoot, "chart.min.js"))
    .toString();

  let html = "<html><body>Network Dashboard not found</body></html>";
  if (fs.existsSync(htmlPath.fsPath)) {
    try {
      const raw = fs.readFileSync(htmlPath.fsPath, "utf8");
      html = buildDashboardHtml(panel.webview, raw, { styleHref, chartHref });
    } catch {
      html =
        "<html><body>Failed to load Network Dashboard template</body></html>";
    }
  }
  panel.webview.html = html;

  const folder = vscode.workspace.workspaceFolders?.[0];

  // Helper to push findings to the webview
  const sendFindings = () => {
    const findings = folder ? collectNetFindings(folder) : [];
    panel.webview.postMessage({ type: "diagnostics", payload: findings });
  };

  // Send initial data
  sendFindings();
  computeAndPostCoupling(panel).catch(() => {});

  // Refresh on re-focus
  panel.onDidChangeViewState(() => {
    if (panel.visible) {
      sendFindings();
      computeAndPostCoupling(panel).catch(() => {});
    }
  });

  // Handle webview → extension messages
  panel.webview.onDidReceiveMessage(async (msg) => {
    switch (msg?.type) {
      case "ready": {
        sendFindings();
        await computeAndPostCoupling(panel);
        break;
      }
      case "rescanActiveFile": {
        // Trigger the shared scan command, then refresh
        try { await vscode.commands.executeCommand("flusec.scanFile"); } catch { /* ignore */ }
        sendFindings();
        await computeAndPostCoupling(panel);
        break;
      }
      case "refreshFindings": {
        sendFindings();
        await computeAndPostCoupling(panel);
        break;
      }
      case "openFile": {
        const fsPath: string | undefined = msg?.payload;
        if (fsPath) {
          try {
            const doc = await vscode.workspace.openTextDocument(
              vscode.Uri.file(fsPath)
            );
            await vscode.window.showTextDocument(doc, {
              preview: false,
            });
          } catch (e) {
            vscode.window.showErrorMessage(
              "Failed to open file: " + String(e)
            );
          }
        }
        break;
      }
      default:
        break;
    }
  });
}