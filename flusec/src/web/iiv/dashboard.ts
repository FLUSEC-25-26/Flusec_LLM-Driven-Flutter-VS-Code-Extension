// src/web/iiv/dashboard.ts
//
// VS Code host for the FLUSEC Insufficient Input Validation dashboard.
// Sends the complete normalized IIV finding model to the shared dashboard UI.

import * as vscode from "vscode";
import * as fs from "fs";
import { iivFindingsPathForFolder } from "../../analyzer/runAnalyzer.js";
import {
  buildDashboardHtml,
  createFindingsWatcher,
  readDashboardFindings,
  revealDashboardFinding,
} from "../shared/dashboardHost.js";

let activeIivPanel: vscode.WebviewPanel | undefined;

export function openIIVDashboard(context: vscode.ExtensionContext): void {
  if (activeIivPanel) {
    activeIivPanel.reveal(vscode.ViewColumn.Beside);
    sendFindings(activeIivPanel);
    return;
  }

  const webRoot = vscode.Uri.joinPath(context.extensionUri, "src", "web");
  const panel = vscode.window.createWebviewPanel(
    "flusecIivDashboard",
    "FLUSEC · Input Validation",
    vscode.ViewColumn.Beside,
    {
      enableScripts: true,
      retainContextWhenHidden: true,
      localResourceRoots: [webRoot],
    }
  );

  activeIivPanel = panel;
  panel.webview.html = buildDashboardHtml(context, panel.webview, "iiv");

  let watcher: fs.FSWatcher | undefined;

  const attachWatcher = () => {
    watcher?.close();
    watcher = undefined;

    const folder = vscode.workspace.workspaceFolders?.[0];
    if (!folder) {return;}

    const findingsPath = iivFindingsPathForFolder(folder);
    watcher = createFindingsWatcher(findingsPath, () => {
      if (panel.visible) {sendFindings(panel);}
    });
  };

  panel.onDidDispose(() => {
    watcher?.close();
    watcher = undefined;
    if (activeIivPanel === panel) {activeIivPanel = undefined;}
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
    folder ? iivFindingsPathForFolder(folder) : undefined
  );

  void panel.webview.postMessage({
    type: "flusec:findings",
    payload,
  });
}
