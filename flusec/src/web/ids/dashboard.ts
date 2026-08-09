// src/web/ids/dashboard.ts
//
// VS Code host for the FLUSEC Insecure Data Storage dashboard.
// Uses securitySeverity as the canonical security impact field.

import * as vscode from "vscode";
import * as fs from "fs";
import { idsFindingsPathForFolder } from "../../analyzer/runAnalyzer.js";
import {
  buildDashboardHtml,
  createFindingsWatcher,
  readDashboardFindings,
  revealDashboardFinding,
} from "../shared/dashboardHost.js";

let activeIdsPanel: vscode.WebviewPanel | undefined;

export function openIDSDashboard(context: vscode.ExtensionContext): void {
  if (activeIdsPanel) {
    activeIdsPanel.reveal(vscode.ViewColumn.Beside);
    sendFindings(activeIdsPanel);
    return;
  }

  const webRoot = vscode.Uri.joinPath(context.extensionUri, "src", "web");
  const panel = vscode.window.createWebviewPanel(
    "flusecIdsDashboard",
    "FLUSEC · Insecure Data Storage",
    vscode.ViewColumn.Beside,
    {
      enableScripts: true,
      retainContextWhenHidden: true,
      localResourceRoots: [webRoot],
    }
  );

  activeIdsPanel = panel;
  panel.webview.html = buildDashboardHtml(context, panel.webview, "ids");

  let watcher: fs.FSWatcher | undefined;

  const attachWatcher = () => {
    watcher?.close();
    watcher = undefined;

    const folder = vscode.workspace.workspaceFolders?.[0];
    if (!folder) {return;}

    const findingsPath = idsFindingsPathForFolder(folder);
    watcher = createFindingsWatcher(findingsPath, () => {
      if (panel.visible) {sendFindings(panel);}
    });
  };

  panel.onDidDispose(() => {
    watcher?.close();
    watcher = undefined;
    if (activeIdsPanel === panel) {activeIdsPanel = undefined;}
  });

  panel.onDidChangeViewState(() => {
    if (!panel.visible) {return;}
    attachWatcher();
    sendFindings(panel);
  });

  panel.webview.onDidReceiveMessage(async (message) => {
    switch (message?.command) {
      case "ready":
      case "refresh":
        attachWatcher();
        sendFindings(panel);
        break;
      case "reveal":
        await revealDashboardFinding(
          message.file,
          message.line,
          message.column
        );
        break;
      default:
        break;
    }
  });

  attachWatcher();
  sendFindings(panel);
}

function sendFindings(panel: vscode.WebviewPanel): void {
  const folder = vscode.workspace.workspaceFolders?.[0];
  const payload = readDashboardFindings(
    folder ? idsFindingsPathForFolder(folder) : undefined
  );

  void panel.webview.postMessage({
    type: "flusec:findings",
    payload,
  });
}
