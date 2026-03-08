// src/web/iiv/dashboard.ts
//
// Webview dashboard for Insufficient Input Validation (IIV) component.
// Shows: findings list, findings-by-rule chart, findings-by-file chart, KPI cards.
// Reads from iiv_findings.json (IIV component only).

import * as vscode from "vscode";
import * as fs from "fs";
import * as path from "path";
import { iivFindingsPathForFolder } from "../../analyzer/runAnalyzer.js";

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

// ─── collect IIV findings from iiv_findings.json ────────────────────────────

interface FindingEntry {
  file: string;
  message: string;
  code?: string | number;
  ruleId?: string;
  severity: "error" | "warning" | "information" | "hint";
  line: number;
  column: number;
  functionName?: string;
}

function collectIivFindings(folder: vscode.WorkspaceFolder): FindingEntry[] {
  const findingsPath = iivFindingsPathForFolder(folder);
  if (!fs.existsSync(findingsPath)) {
    return [];
  }
  try {
    const raw = JSON.parse(fs.readFileSync(findingsPath, "utf8"));
    if (!Array.isArray(raw)) {
      return [];
    }
    return raw.map((f: any) => ({
      file: f.file ?? "",
      message: f.message ?? "",
      code: f.code ?? f.ruleId,
      ruleId: f.ruleId ?? "",
      severity: f.severity ?? "warning",
      line: f.line ?? 1,
      column: f.column ?? 1,
      functionName: f.functionName ?? null,
    }));
  } catch {
    return [];
  }
}

// ─── open dashboard ──────────────────────────────────────────────────────────

export function openIIVDashboard(context: vscode.ExtensionContext) {
  const iivWebRoot = vscode.Uri.joinPath(
    context.extensionUri,
    "src",
    "web",
    "iiv"
  );

  const panel = vscode.window.createWebviewPanel(
    "flusecIivDashboard",
    "FLUSEC – Input Validation Dashboard",
    vscode.ViewColumn.Beside,
    {
      enableScripts: true,
      retainContextWhenHidden: true,
      localResourceRoots: [iivWebRoot],
    }
  );

  // Webview-safe URIs
  const htmlPath = vscode.Uri.joinPath(iivWebRoot, "dashboard.html");
  const styleHref = panel.webview
    .asWebviewUri(vscode.Uri.joinPath(iivWebRoot, "style.css"))
    .toString();

  const nonce = getNonce();

  let html = "<html><body>Input Validation Dashboard not found</body></html>";
  if (fs.existsSync(htmlPath.fsPath)) {
    try {
      let raw = fs.readFileSync(htmlPath.fsPath, "utf8");

      const cspMeta = `
        <meta http-equiv="Content-Security-Policy"
          content="
            default-src 'none';
            img-src ${panel.webview.cspSource} https:;
            style-src ${panel.webview.cspSource} 'unsafe-inline';
            script-src 'nonce-${nonce}';
            font-src ${panel.webview.cspSource} https:;
          ">
      `;

      raw = raw
        .replace(/\{\{styleHref\}\}/g, styleHref)
        .replace(/\{\{nonce\}\}/g, nonce);

      raw = raw.replace(/<head>/i, `<head>\n${cspMeta}`);

      html = raw;
    } catch {
      html =
        "<html><body>Failed to load Input Validation Dashboard template</body></html>";
    }
  }
  panel.webview.html = html;

  const folder = vscode.workspace.workspaceFolders?.[0];

  const sendFindings = () => {
    const findings = folder ? collectIivFindings(folder) : [];
    panel.webview.postMessage({ type: "diagnostics", payload: findings });
  };

  // Send initial data
  sendFindings();

  // Refresh on re-focus
  panel.onDidChangeViewState(() => {
    if (panel.visible) {
      sendFindings();
    }
  });

  // Handle webview → extension messages
  panel.webview.onDidReceiveMessage(async (msg) => {
    switch (msg?.type) {
      case "ready": {
        sendFindings();
        break;
      }
      case "rescanActiveFile": {
        try { await vscode.commands.executeCommand("flusec.scanFile"); } catch { /* ignore */ }
        sendFindings();
        break;
      }
      case "refreshFindings": {
        sendFindings();
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