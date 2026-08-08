// src/web/net/dasboard.ts
//
// Webview dashboard for Insecure Network Communication component.
// Shows: findings list, warnings-per-rule chart, coupling analysis charts,
// and the existing network dependency health index.
//
// Coupling refresh behavior:
// - Initial dashboard open
// - Dashboard becomes visible again
// - Webview sends "ready"
// - User refreshes/rescans
// - FLUSEC "Scan Entire Project" finishes (via refreshNetDashboard)

import * as vscode from "vscode";
import * as fs from "fs";
import { netFindingsPathForFolder } from "../../analyzer/runAnalyzer.js";
import { computeAndPostCoupling } from "../../net/couplingAnalysis.js";
import { getNetChartMessagingScript } from "../../net/netChartScript.js";

// ─── Current NET dashboard panel ─────────────────────────────────────────────

let activeNetPanel: vscode.WebviewPanel | undefined;

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

function collectNetFindings(
  folder: vscode.WorkspaceFolder
): FindingEntry[] {
  const findingsPath = netFindingsPathForFolder(folder);

  if (!fs.existsSync(findingsPath)) {
    return [];
  }

  try {
    const raw = JSON.parse(
      fs.readFileSync(findingsPath, "utf8")
    );

    if (!Array.isArray(raw)) {
      return [];
    }

    // No filter needed — this file contains only NET findings.
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

// ─── shared dashboard data refresh ──────────────────────────────────────────

async function sendDashboardData(
  panel: vscode.WebviewPanel
): Promise<void> {
  const folder = vscode.workspace.workspaceFolders?.[0];

  const findings = folder
    ? collectNetFindings(folder)
    : [];

  panel.webview.postMessage({
    type: "diagnostics",
    payload: findings,
  });

  try {
    await computeAndPostCoupling(panel);
  } catch (e) {
    console.warn(
      "[NET] Failed to refresh coupling dashboard data:",
      e
    );
  }
}

/**
 * Refresh the currently open NET dashboard, if one exists.
 *
 * This is exported so the "Scan Entire Project" command can update
 * the coupling graph immediately after the project scan finishes.
 *
 * If the dashboard is not open, this function simply does nothing.
 * The next time the dashboard opens, it calculates fresh data normally.
 */
export async function refreshNetDashboard(): Promise<void> {
  const panel = activeNetPanel;

  if (!panel) {
    return;
  }

  await sendDashboardData(panel);
}

// ─── build HTML ──────────────────────────────────────────────────────────────

function buildDashboardHtml(
  webview: vscode.Webview,
  rawHtml: string,
  uris: {
    styleHref: string;
    chartHref: string;
  }
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

  // Inject CSP into <head>.
  html = html.replace(
    /<head>/i,
    `<head>\n${cspMeta}`
  );

  // Inject messaging + chart script before </body>.
  const messagingScript =
    getNetChartMessagingScript(nonce);

  html = html.replace(
    /<\/body>\s*<\/html>\s*$/i,
    `${messagingScript}\n</body></html>`
  );

  return html;
}

// ─── open dashboard ──────────────────────────────────────────────────────────

export function openNetDashboard(
  context: vscode.ExtensionContext
): void {
  // Reuse the existing NET dashboard instead of creating duplicate panels.
  if (activeNetPanel) {
    activeNetPanel.reveal(vscode.ViewColumn.Beside);
    void sendDashboardData(activeNetPanel);
    return;
  }

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

  activeNetPanel = panel;

  panel.onDidDispose(() => {
    if (activeNetPanel === panel) {
      activeNetPanel = undefined;
    }
  });

  // Webview-safe URIs.
  const htmlPath = vscode.Uri.joinPath(
    netWebRoot,
    "dashboard.html"
  );

  const styleHref = panel.webview
    .asWebviewUri(
      vscode.Uri.joinPath(netWebRoot, "style.css")
    )
    .toString();

  const chartHref = panel.webview
    .asWebviewUri(
      vscode.Uri.joinPath(netWebRoot, "chart.min.js")
    )
    .toString();

  let html =
    "<html><body>Network Dashboard not found</body></html>";

  if (fs.existsSync(htmlPath.fsPath)) {
    try {
      const raw = fs.readFileSync(
        htmlPath.fsPath,
        "utf8"
      );

      html = buildDashboardHtml(
        panel.webview,
        raw,
        {
          styleHref,
          chartHref,
        }
      );
    } catch {
      html =
        "<html><body>Failed to load Network Dashboard template</body></html>";
    }
  }

  panel.webview.html = html;

  // Send initial data.
  // The webview will also send "ready", so startup remains reliable even if
  // this first post occurs before its script has fully initialized.
  void sendDashboardData(panel);

  // Refresh whenever the dashboard becomes visible again.
  panel.onDidChangeViewState(() => {
    if (panel.visible) {
      void sendDashboardData(panel);
    }
  });

  // Handle webview → extension messages.
  panel.webview.onDidReceiveMessage(async (msg) => {
    switch (msg?.type) {
      case "ready": {
        await sendDashboardData(panel);
        break;
      }

      case "rescanActiveFile": {
        try {
          await vscode.commands.executeCommand(
            "flusec.scanFile"
          );
        } catch {
          // Ignore command failure here; normal scan command handles errors.
        }

        await sendDashboardData(panel);
        break;
      }

      case "refreshFindings": {
        await sendDashboardData(panel);
        break;
      }

      case "openFile": {
        const fsPath: string | undefined =
          msg?.payload;

        if (fsPath) {
          try {
            const doc =
              await vscode.workspace.openTextDocument(
                vscode.Uri.file(fsPath)
              );

            await vscode.window.showTextDocument(
              doc,
              {
                preview: false,
              }
            );
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
