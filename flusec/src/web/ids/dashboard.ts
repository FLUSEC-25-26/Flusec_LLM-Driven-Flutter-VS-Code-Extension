// src/web/ids/dashboard.ts
//
// IDS Dashboard Controller — manages the webview panel for IDS findings.
// Reads from .flusec/.out/ids_findings.json (written by runAnalyzer.ts).

import * as vscode from "vscode";
import * as path from "path";
import * as fs from "fs";
import { idsFindingsPathForFolder } from "../../analyzer/runAnalyzer.js";

/**
 * Opens the IDS Dashboard in a webview panel.
 */
export function openIDSDashboard(context: vscode.ExtensionContext) {
  const panel = vscode.window.createWebviewPanel(
    "idsDashboard",
    "IDS Vulnerability Dashboard",
    vscode.ViewColumn.Beside,
    {
      enableScripts: true,
      retainContextWhenHidden: true,
      localResourceRoots: [
        vscode.Uri.file(path.join(context.extensionPath, "src", "web", "ids")),
        vscode.Uri.file(path.join(context.extensionPath, "web", "ids")),
      ],
    }
  );

  // Load HTML with injected CSS/JS URIs
  const htmlPath =
    _resolve(context, "web", "ids", "dashboard.html") ??
    _resolve(context, "src", "web", "ids", "dashboard.html");

  const cssPath =
    _resolve(context, "web", "ids", "dashboard.css") ??
    _resolve(context, "src", "web", "ids", "dashboard.css");

  const jsPath =
    _resolve(context, "web", "ids", "dashboard.js") ??
    _resolve(context, "src", "web", "ids", "dashboard.js");

  if (!htmlPath) {
    panel.webview.html =
      "<html><body><h3>IDS Dashboard HTML not found</h3></body></html>";
    return;
  }

  const cssUri = cssPath
    ? panel.webview.asWebviewUri(vscode.Uri.file(cssPath))
    : "";
  const jsUri = jsPath
    ? panel.webview.asWebviewUri(vscode.Uri.file(jsPath))
    : "";
  const cspSource = panel.webview.cspSource;

  let html = fs.readFileSync(htmlPath, "utf8");
  html = html.replace(/\{\{cssUri\}\}/g, cssUri.toString());
  html = html.replace(/\{\{jsUri\}\}/g, jsUri.toString());
  html = html.replace(/\{\{cspSource\}\}/g, cspSource);

  panel.webview.html = html;

  // Workspace + findings path
  const folder = vscode.workspace.workspaceFolders?.[0];
  if (!folder) {
    panel.webview.postMessage({ command: "loadFindings", data: [] });
    return;
  }

  const findingsPath = idsFindingsPathForFolder(folder);

  const sendFindings = () => {
    let findings: any[] = [];
    if (fs.existsSync(findingsPath)) {
      try {
        findings = JSON.parse(fs.readFileSync(findingsPath, "utf8"));
        if (!Array.isArray(findings)) {findings = [];}
      } catch {
        findings = [];
      }
    }
    panel.webview.postMessage({ command: "loadFindings", data: findings });
  };

  sendFindings();

  panel.onDidChangeViewState(() => {
    if (panel.visible) {sendFindings();}
  });

  // Handle messages from webview
  panel.webview.onDidReceiveMessage(
    async (msg) => {
      if (msg?.command === "reveal") {
        try {
          const doc = await vscode.workspace.openTextDocument(
            vscode.Uri.file(msg.file)
          );
          const editor = await vscode.window.showTextDocument(doc, {
            preview: false,
          });
          const pos = new vscode.Position(
            Math.max(0, (msg.line ?? 1) - 1),
            Math.max(0, (msg.column ?? 1) - 1)
          );
          editor.selection = new vscode.Selection(pos, pos);
          editor.revealRange(
            new vscode.Range(pos, pos),
            vscode.TextEditorRevealType.InCenter
          );
        } catch (e) {
          vscode.window.showErrorMessage(
            "Failed to open file from IDS dashboard: " + String(e)
          );
        }
      }

      if (msg?.command === "rescan") {
        try {
          await vscode.commands.executeCommand("flusec.scanFile");
          setTimeout(sendFindings, 500);
        } catch { /* ignore */ }
      }
    },
    undefined,
    context.subscriptions
  );
}

function _resolve(
  ctx: vscode.ExtensionContext,
  ...segments: string[]
): string | null {
  const p = path.join(ctx.extensionUri.fsPath, ...segments);
  return fs.existsSync(p) ? p : null;
}