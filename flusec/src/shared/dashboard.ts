// src/shared/dashboard.ts
//
// Dashboard webview controller.
// - Loads findings JSON file
// - Sends it to dashboard.html
// - Handles "reveal" messages (jump to file/line)
// - Handles "export" if needed (dashboard.html already does export itself)
//
// ✅ Shared because one dashboard can show any component findings.
// Later you can add dropdown filter: HSD / Network / Storage / Validation.

import * as vscode from "vscode";
import * as fs from "fs";
import * as path from "path";

export function openDashboard(
  context: vscode.ExtensionContext,
  findingsFilePath: string
) {
  const panel = vscode.window.createWebviewPanel(
    "flusecDashboard",
    "Flusec Findings",
    vscode.ViewColumn.Beside,
    { enableScripts: true, retainContextWhenHidden: true }
  );

  const htmlPath = path.join(context.extensionUri.fsPath, "web", "dashboard.html");
  panel.webview.html = fs.existsSync(htmlPath)
    ? fs.readFileSync(htmlPath, "utf8")
    : "<html><body>Dashboard not found</body></html>";

  // Send findings to the webview
  const load = () => {
    try {
      const raw = fs.existsSync(findingsFilePath)
        ? JSON.parse(fs.readFileSync(findingsFilePath, "utf8"))
        : [];
      panel.webview.postMessage({ command: "loadFindings", data: raw });
    } catch {
      panel.webview.postMessage({ command: "loadFindings", data: [] });
    }
  };

  load();

  // React to dashboard interactions
  panel.webview.onDidReceiveMessage(async (msg) => {
    if (!msg || typeof msg.command !== "string") {return;}

    if (msg.command === "reveal") {
      const file = String(msg.file || "");
      const line = Math.max(1, Number(msg.line || 1));
      const column = Math.max(1, Number(msg.column || 1));

      try {
        const uri = vscode.Uri.file(file);
        const doc = await vscode.workspace.openTextDocument(uri);
        const editor = await vscode.window.showTextDocument(doc, { preview: false });

        const pos = new vscode.Position(line - 1, column - 1);
        editor.selection = new vscode.Selection(pos, pos);
        editor.revealRange(new vscode.Range(pos, pos), vscode.TextEditorRevealType.InCenter);
      } catch (e) {
        vscode.window.showErrorMessage("Failed to reveal file: " + String(e));
      }
    }

    if (msg.command === "refresh") {
      load();
    }
  });
}
