// src/web/net/dasboard.ts
//
// VS Code host for the FLUSEC Network Security dashboard.
// Security findings use the shared normalized dashboard UI, while coupling is
// shown in a separate Architecture Context tab and never affects severity.

import * as vscode from "vscode";
import * as fs from "fs";
import { netFindingsPathForFolder } from "../../analyzer/runAnalyzer.js";
import { computeAndPostCoupling } from "../../net/couplingAnalysis.js";
import {
  buildDashboardHtml,
  createFindingsWatcher,
  readDashboardFindings,
  revealDashboardFinding,
} from "../shared/dashboardHost.js";

let activeNetPanel: vscode.WebviewPanel | undefined;

export async function refreshNetDashboard(): Promise<void> {
  if (!activeNetPanel) {return;}
  await sendDashboardData(activeNetPanel);
}

export function openNetDashboard(context: vscode.ExtensionContext): void {
  if (activeNetPanel) {
    activeNetPanel.reveal(vscode.ViewColumn.Beside);
    void sendDashboardData(activeNetPanel);
    return;
  }

  const webRoot = vscode.Uri.joinPath(context.extensionUri, "src", "web");
  const panel = vscode.window.createWebviewPanel(
    "flusecNetDashboard",
    "FLUSEC · Network Security",
    vscode.ViewColumn.Beside,
    {
      enableScripts: true,
      retainContextWhenHidden: true,
      localResourceRoots: [webRoot],
    }
  );

  activeNetPanel = panel;
  panel.webview.html = buildDashboardHtml(context, panel.webview, "net");

  let watcher: fs.FSWatcher | undefined;

  const attachWatcher = () => {
    watcher?.close();
    watcher = undefined;

    const folder = vscode.workspace.workspaceFolders?.[0];
    if (!folder) {return;}

    const findingsPath = netFindingsPathForFolder(folder);
    watcher = createFindingsWatcher(findingsPath, () => {
      if (panel.visible) {void sendDashboardData(panel);}
    });
  };

  panel.onDidDispose(() => {
    watcher?.close();
    watcher = undefined;
    if (activeNetPanel === panel) {activeNetPanel = undefined;}
  });

  panel.onDidChangeViewState(() => {
    if (!panel.visible) {return;}
    attachWatcher();
    void sendDashboardData(panel);
  });

  panel.webview.onDidReceiveMessage(async (message) => {
    switch (message?.command) {
      case "ready":
      case "refresh":
        attachWatcher();
        await sendDashboardData(panel);
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
  void sendDashboardData(panel);
}

async function sendDashboardData(panel: vscode.WebviewPanel): Promise<void> {
  const folder = vscode.workspace.workspaceFolders?.[0];
  const payload = readDashboardFindings(
    folder ? netFindingsPathForFolder(folder) : undefined
  );

  await panel.webview.postMessage({
    type: "flusec:findings",
    payload,
  });

  try {
    await computeAndPostCoupling(panel);
  } catch (error) {
    console.warn("[NET] Failed to refresh coupling context:", error);
  }
}
