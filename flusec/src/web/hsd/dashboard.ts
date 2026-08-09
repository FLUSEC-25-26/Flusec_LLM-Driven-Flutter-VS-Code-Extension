// src/web/hsd/dashboard.ts
//
// VS Code host for the FLUSEC Hardcoded Secrets dashboard.
// The webview renders the normalized HSD finding contract produced by Phase 5.

import * as vscode from "vscode";
import * as fs from "fs";
import { hsdFindingsPathForFolder } from "../../analyzer/runAnalyzer.js";
import {
  buildDashboardHtml,
  createFindingsWatcher,
  readDashboardFindings,
  revealDashboardFinding,
} from "../shared/dashboardHost.js";

let activeHsdPanel: vscode.WebviewPanel | undefined;

export function openDashboard(context: vscode.ExtensionContext): void {
  if (activeHsdPanel) {
    activeHsdPanel.reveal(vscode.ViewColumn.Beside);
    sendFindings(activeHsdPanel);
    return;
  }

  const webRoot = vscode.Uri.joinPath(context.extensionUri, "src", "web");
  const panel = vscode.window.createWebviewPanel(
    "flusecHsdDashboard",
    "FLUSEC · Hardcoded Secrets",
    vscode.ViewColumn.Beside,
    {
      enableScripts: true,
      retainContextWhenHidden: true,
      localResourceRoots: [webRoot],
    }
  );

  activeHsdPanel = panel;
  panel.webview.html = buildDashboardHtml(context, panel.webview, "hsd");

  let watcher: fs.FSWatcher | undefined;

  const attachWatcher = () => {
    watcher?.close();
    watcher = undefined;

    const folder = vscode.workspace.workspaceFolders?.[0];
    if (!folder) {return;}

    const findingsPath = hsdFindingsPathForFolder(folder);
    watcher = createFindingsWatcher(findingsPath, () => {
      if (panel.visible) {sendFindings(panel);}
    });
  };

  panel.onDidDispose(() => {
    watcher?.close();
    watcher = undefined;
    if (activeHsdPanel === panel) {activeHsdPanel = undefined;}
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
    folder ? hsdFindingsPathForFolder(folder) : undefined
  );

  void panel.webview.postMessage({
    type: "flusec:findings",
    payload,
  });
}
