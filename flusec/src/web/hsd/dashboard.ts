// src/ui/dashboard.ts
//
// Webview dashboard for showing all findings from findings.json.
// Reads the same findings path used by the analyzer.
// Allows users to click an entry and navigate to the file/line.

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

  // Load static HTML file for the dashboard UI.
  const htmlPath = path.join(
    context.extensionUri.fsPath,
    "src",
    "web",
    "hsd",
    "dashboard.html"
  );

  panel.webview.html = fs.existsSync(htmlPath)
    ? fs.readFileSync(htmlPath, "utf8")
    : "<html><body>Dashboard not found</body></html>";

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

  // Handle messages from the webview (e.g., "reveal" request).
  panel.webview.onDidReceiveMessage(async (msg) => {
    if (msg?.command === "reveal") {
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
    }
  });
}
