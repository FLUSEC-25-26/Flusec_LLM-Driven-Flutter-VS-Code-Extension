// src/web/hsd/dashboard.ts
import * as vscode from "vscode";
import * as fs from "fs";
import * as path from "path";
import { findingsPathForFolder } from "../../analyzer/runAnalyzer.js";

export function openDashboard(context: vscode.ExtensionContext) {
  const panel = vscode.window.createWebviewPanel(
    "flusecHsdDashboard", // Unique ID
    "🔑 Flusec: Secrets", // Title
    vscode.ViewColumn.Beside,
    { enableScripts: true, retainContextWhenHidden: true }
  );

  const webview = panel.webview;
  
  // Point to existing HSD assets
  const hsdRoot = vscode.Uri.joinPath(context.extensionUri, "src", "web", "hsd");
  const styleRoot = vscode.Uri.joinPath(context.extensionUri, "src", "web");

  const htmlPath = vscode.Uri.joinPath(hsdRoot, "dashboard.html");
  const cssPath = vscode.Uri.joinPath(styleRoot, "css", "dashboard.css");
  const jsPath = vscode.Uri.joinPath(styleRoot, "js", "dashboard.js");

  const cssUri = webview.asWebviewUri(cssPath);
  const jsUri = webview.asWebviewUri(jsPath);

  let html = "<html><body>Dashboard not found</body></html>";
  if (fs.existsSync(htmlPath.fsPath)) {
      const raw = fs.readFileSync(htmlPath.fsPath, "utf8");
      html = raw
        .replace(/{{cssUri}}/g, cssUri.toString())
        .replace(/{{jsUri}}/g, jsUri.toString())
        .replace(/{{cspSource}}/g, webview.cspSource);
  }
  panel.webview.html = html;

  const folder = vscode.workspace.workspaceFolders?.[0];
  const findingsPath = folder ? findingsPathForFolder(folder) : "";

  const sendFindings = () => {
    let data: any[] = [];
    if (fs.existsSync(findingsPath)) {
      try {
        const raw = JSON.parse(fs.readFileSync(findingsPath, "utf8"));
        if (Array.isArray(raw)) {
          // 🔍 FILTER: Exclude IVD -> Only show Secrets (HSD)
          data = raw.filter((f: any) => !f.ruleId || !f.ruleId.includes("IVD"));
        }
      } catch { data = []; }
    }
    panel.webview.postMessage({ command: "loadFindings", data });
  };

  sendFindings();

  panel.onDidChangeViewState(() => { if (panel.visible) sendFindings(); });
  
  // Keep your existing message listeners for refresh/charts
  panel.webview.onDidReceiveMessage(async (msg) => {
    if (msg.command === "refresh") sendFindings();
    // ... rest of your HSD logic ...
  });
}
