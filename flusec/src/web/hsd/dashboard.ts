// src/ui/dashboard.ts
//
// Webview dashboard for showing all findings from findings.json.
// - Reads findings.json (same path as analyzer)
// - Shows charts + maintainability hotspots + full table
// - Exports a PDF report (summary + charts data + findings table)

import * as vscode from "vscode";
import * as fs from "fs";
import * as path from "path";
import { findingsPathForFolder } from "../../analyzer/runAnalyzer.js";

/**
 * Open the Flusec Findings dashboard webview.
 */
export function openDashboard(context: vscode.ExtensionContext) {
  const panel = vscode.window.createWebviewPanel(
    "flusecDashboard",
    "Flusec Findings",
    vscode.ViewColumn.Beside,
    {
      enableScripts: true,
      retainContextWhenHidden: true,
    }
  );

  const webview = panel.webview;

  // Root folder for dashboard assets
  const hsdRoot = vscode.Uri.joinPath(
    context.extensionUri,
    "src",
    "web",
    "hsd"
  );

  const styleRoot = vscode.Uri.joinPath(context.extensionUri, "src", "web");

  const htmlPath = vscode.Uri.joinPath(hsdRoot, "dashboard.html");
  const cssPath = vscode.Uri.joinPath(styleRoot, "css", "dashboard.css");
  const jsPath = vscode.Uri.joinPath(styleRoot, "js", "dashboard.js");

  const cssUri = webview.asWebviewUri(cssPath);
  const jsUri = webview.asWebviewUri(jsPath);

  let html = "<html><body>Dashboard not found</body></html>";
  if (fs.existsSync(htmlPath.fsPath)) {
    try {
      const raw = fs.readFileSync(htmlPath.fsPath, "utf8");
      html = raw
        .replace(/{{cssUri}}/g, cssUri.toString())
        .replace(/{{jsUri}}/g, jsUri.toString())
        .replace(/{{cspSource}}/g, webview.cspSource);
    } catch {
      html = "<html><body>Failed to load dashboard template</body></html>";
    }
  }

  panel.webview.html = html;

  // Decide which workspace folder to read findings from.
  const folder = vscode.workspace.workspaceFolders?.[0];
  if (!folder) {
    panel.webview.postMessage({ command: "loadFindings", data: [] });
    return;
  }

  // MUST match the path logic used in the analyzer.
  const findingsPath = findingsPathForFolder(folder);

  /**
   * Read findings.json and send data to the webview.
   */
  const sendFindings = () => {
    let data: any[] = [];
    if (fs.existsSync(findingsPath)) {
      try {
        data = JSON.parse(fs.readFileSync(findingsPath, "utf8"));
        if (!Array.isArray(data)) {
          data = [];
        }
      } catch {
        data = [];
      }
    }
    panel.webview.postMessage({ command: "loadFindings", data });
  };

  // Send once when opened.
  sendFindings();

  // Optional: refresh when the dashboard becomes visible again.
  panel.onDidChangeViewState(() => {
    if (panel.visible) {
      sendFindings();
    }
  });

  // Handle messages from the webview (e.g., "reveal", "refresh", "rescanActiveFile").
  panel.webview.onDidReceiveMessage(async (msg) => {
    const cmd = msg?.command;

    if (cmd === "reveal") {
      const file = String(msg.file || "");
      const line = Math.max(0, (msg.line ?? 1) - 1);
      const col = Math.max(0, (msg.column ?? 1) - 1);

      try {
        const doc = await vscode.workspace.openTextDocument(
          vscode.Uri.file(file)
        );
        const editor = await vscode.window.showTextDocument(doc, {
          preview: false,
        });
        const pos = new vscode.Position(line, col);
        editor.selection = new vscode.Selection(pos, pos);
        editor.revealRange(
          new vscode.Range(pos, pos),
          vscode.TextEditorRevealType.InCenter
        );
      } catch (e) {
        vscode.window.showErrorMessage(
          "Failed to open file from dashboard: " + String(e)
        );
      }
    } else if (cmd === "refresh") {
      // Re-read findings.json and push to webview
      sendFindings();
    } else if (cmd === "rescanActiveFile") {
      // Use existing scan command, then reload findings
      vscode.commands.executeCommand("flusec.scanFile").then(
        () => {
          // After rescan, refresh data
          sendFindings();
        },
        (err) => {
          vscode.window.showErrorMessage(
            "Failed to trigger rescan: " + String(err)
          );
        }
      );
    }
  });
}
