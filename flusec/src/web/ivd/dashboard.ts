// src/web/ivd/dashboard.ts
import * as vscode from "vscode";
import * as fs from "fs";
import { findingsPathForFolder } from "../../analyzer/runAnalyzer.js";

let currentPanel: vscode.WebviewPanel | undefined = undefined;

export function openIvdDashboard(context: vscode.ExtensionContext) {
  const column = vscode.window.activeTextEditor ? vscode.window.activeTextEditor.viewColumn : undefined;

  if (currentPanel) {
    currentPanel.reveal(column);
    return;
  }

  // Create the Panel - Focus strictly on Input Validation
  currentPanel = vscode.window.createWebviewPanel(
    "flusecIvdDashboard",
    "🛡️ Input Validation",
    column || vscode.ViewColumn.One,
    { enableScripts: true, retainContextWhenHidden: true }
  );

  const webview = currentPanel.webview;

  // --- Load HTML ---
  const ivdRoot = vscode.Uri.joinPath(context.extensionUri, "src", "web", "ivd");
  const styleRoot = vscode.Uri.joinPath(context.extensionUri, "src", "web");
  
  const htmlPath = vscode.Uri.joinPath(ivdRoot, "dashboard.html");
  const cssPath = vscode.Uri.joinPath(styleRoot, "css", "dashboard.css");
  const cssUri = webview.asWebviewUri(cssPath);

  let htmlContent = "<html><body>Error: Could not find dashboard.html</body></html>";
  
  // ESLint Fix: Added braces to the if condition
  if (fs.existsSync(htmlPath.fsPath)) {
    htmlContent = fs.readFileSync(htmlPath.fsPath, "utf8")
      .replace(/{{cssUri}}/g, cssUri.toString())
      .replace(/{{cspSource}}/g, webview.cspSource);
  }
  
  currentPanel.webview.html = htmlContent;

  // --- Load Data ---
  const folder = vscode.workspace.workspaceFolders?.[0];
  const findingsPath = folder ? findingsPathForFolder(folder) : "";

  const sendFindings = () => {
    let data: any[] = [];
    if (fs.existsSync(findingsPath)) {
      try {
        const raw = JSON.parse(fs.readFileSync(findingsPath, "utf8"));
        // 🔍 FILTER: Exclusively handle IVD findings
        data = raw.filter((f: any) => f.ruleId && f.ruleId.includes("IVD"));
      } catch (e) {
        console.error("Error reading findings.json", e);
      }
    }
    
    // ESLint Fix: Added braces for currentPanel check
    if (currentPanel) {
      currentPanel.webview.postMessage({ command: "loadFindings", data });
    }
  };

  sendFindings();

  currentPanel.onDidChangeViewState(e => {
    // ESLint Fix: Added braces for visible check
    if (e.webviewPanel.visible) {
      sendFindings();
    }
  });

  currentPanel.onDidDispose(() => {
    currentPanel = undefined;
  }, null, context.subscriptions);
}