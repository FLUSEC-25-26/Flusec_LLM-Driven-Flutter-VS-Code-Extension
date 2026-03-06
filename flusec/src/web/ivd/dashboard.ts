import * as vscode from "vscode";
import * as fs from "fs";
import { findingsPathForFolder } from "../../analyzer/runAnalyzer.js";

let currentPanel: vscode.WebviewPanel | undefined;

export function openIvdDashboard(context: vscode.ExtensionContext) {

  const column =
    vscode.window.activeTextEditor?.viewColumn ?? vscode.ViewColumn.One;

  if (currentPanel) {
    currentPanel.reveal(column);
    return;
  }

  currentPanel = vscode.window.createWebviewPanel(
    "flusecIvdDashboard",
    "🛡️ Input Validation Dashboard",
    column,
    {
      enableScripts: true,
      retainContextWhenHidden: true
    }
  );

  const webview = currentPanel.webview;

  // Paths
  const ivdRoot = vscode.Uri.joinPath(context.extensionUri, "src", "web", "ivd");
  const webRoot = vscode.Uri.joinPath(context.extensionUri, "src", "web");

  const htmlPath = vscode.Uri.joinPath(ivdRoot, "dashboard.html");
  const cssPath = vscode.Uri.joinPath(webRoot, "css", "dashboard.css");

  const cssUri = webview.asWebviewUri(cssPath);

  let htmlContent = `<html><body>Dashboard not found</body></html>`;

  if (fs.existsSync(htmlPath.fsPath)) {
    htmlContent = fs
      .readFileSync(htmlPath.fsPath, "utf8")
      .replace(/{{cssUri}}/g, cssUri.toString())
      .replace(/{{cspSource}}/g, webview.cspSource);
  }

  webview.html = htmlContent;

  const folder = vscode.workspace.workspaceFolders?.[0];

  if (!folder) {
    vscode.window.showErrorMessage("Flusec: No workspace folder open.");
    return;
  }

  const findingsPath = findingsPathForFolder(folder);

  function sendFindings() {

    let data: any[] = [];

    try {

      if (fs.existsSync(findingsPath)) {

        const raw = JSON.parse(
          fs.readFileSync(findingsPath, "utf8")
        );

        data = Array.isArray(raw) ? raw : [];

      }

    } catch (err) {

      console.error("Error reading findings.json", err);

    }

    if (currentPanel) {

      currentPanel.webview.postMessage({
        command: "loadFindings",
        data: data
      });

    }

  }

  // Wait for webview to say "ready"
  webview.onDidReceiveMessage((message) => {

    if (message.command === "ready") {
      sendFindings();
    }

  });

  // Refresh when dashboard becomes visible
  currentPanel.onDidChangeViewState(e => {

    if (e.webviewPanel.visible) {
      sendFindings();
    }

  });

  // Watch findings.json for changes
  if (fs.existsSync(findingsPath)) {

    fs.watch(findingsPath, () => {
      sendFindings();
    });

  }

  currentPanel.onDidDispose(() => {
    currentPanel = undefined;
  }, null, context.subscriptions);
}