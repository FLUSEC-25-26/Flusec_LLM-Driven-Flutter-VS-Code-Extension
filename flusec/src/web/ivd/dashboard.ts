import * as vscode from "vscode";
import * as fs from "fs";
import * as path from "path";
import { findingsPathForFolder } from "../../analyzer/runAnalyzer.js";

export function openIvdDashboard(context: vscode.ExtensionContext) {
  const panel = vscode.window.createWebviewPanel(
    "flusecIvdDashboard",
    "Flusec: Input Validation",
    vscode.ViewColumn.Beside,
    { enableScripts: true, retainContextWhenHidden: true }
  );

  const webview = panel.webview;
  // Point to IVD html folder
  const ivdRoot = vscode.Uri.joinPath(context.extensionUri, "src", "web", "ivd");
  const styleRoot = vscode.Uri.joinPath(context.extensionUri, "src", "web");

  const htmlPath = vscode.Uri.joinPath(ivdRoot, "dashboard.html");
  // Reuse existing CSS/JS because the layout is the same!
  const cssPath = vscode.Uri.joinPath(styleRoot, "css", "dashboard.css");
  const jsPath = vscode.Uri.joinPath(styleRoot, "js", "dashboard.js");

  const cssUri = webview.asWebviewUri(cssPath);
  const jsUri = webview.asWebviewUri(jsPath);

  // ... (Rest of the code is identical to hsd/dashboard.ts) ...
  // Just ensure you read the HTML file correctly.
  
  let html = "";
  if (fs.existsSync(htmlPath.fsPath)) {
      const raw = fs.readFileSync(htmlPath.fsPath, "utf8");
      html = raw
        .replace(/{{cssUri}}/g, cssUri.toString())
        .replace(/{{jsUri}}/g, jsUri.toString())
        .replace(/{{cspSource}}/g, webview.cspSource);
  }
  panel.webview.html = html;

  // ... (Logic to read findings.json is exactly the same) ...
  // NOTE: IVD and HSD share the same findings.json. 
  // The JS inside the HTML will filter them.
  
  const folder = vscode.workspace.workspaceFolders?.[0];
  const findingsPath = folder ? findingsPathForFolder(folder) : "";
  
  const sendFindings = () => {
    let data: any[] = [];
    if (fs.existsSync(findingsPath)) {
        try {
            data = JSON.parse(fs.readFileSync(findingsPath, "utf8"));
            if (!Array.isArray(data)) {data = [];}
        } catch { data = []; }
    }
    // Fix: Send 'data' instead of 'allFindings'
    panel.webview.postMessage({ command: "loadFindings", data: data });
};

  sendFindings();
  // ... rest of event listeners ...
}