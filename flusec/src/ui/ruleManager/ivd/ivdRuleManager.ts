import * as vscode from "vscode";
import * as fs from "fs";
import * as path from "path";

/**
 * Opens the IVD Rule Manager UI.
 * Reads/Writes dart-analyzer/data/input_validation_rules.json
 */
export function openIvdRuleManager(context: vscode.ExtensionContext) {
  const panel = vscode.window.createWebviewPanel(
    "ivdRuleManager",
    "IVD Rule Manager",
    vscode.ViewColumn.One,
    { enableScripts: true, retainContextWhenHidden: true }
  );

  const extensionRoot = context.extensionUri.fsPath;
  // 🎯 Target File: input_validation_rules.json
  const rulesPath = path.join(extensionRoot, "dart-analyzer", "data", "input_validation_rules.json");
  const htmlFile = path.join(extensionRoot, "src", "ui", "ruleManager", "ivd", "ivdRuleManager.html");

  // Load HTML
  if (fs.existsSync(htmlFile)) {
      panel.webview.html = fs.readFileSync(htmlFile, "utf8");
  } else {
      panel.webview.html = `<h1>Error: HTML file not found at ${htmlFile}</h1>`;
  }

  function readRules(): any[] {
    try {
      if (!fs.existsSync(rulesPath)) return [];
      const txt = fs.readFileSync(rulesPath, "utf8");
      const json = JSON.parse(txt);
      return Array.isArray(json) ? json : [];
    } catch {
      return [];
    }
  }

  // Initial Load
  const data = readRules();
  panel.webview.postMessage({ command: "loadRules", rules: data });

  // Handle Messages
  panel.webview.onDidReceiveMessage(async (msg) => {
    if (msg.command === "saveRules") {
      try {
        // Ensure directory exists
        const dir = path.dirname(rulesPath);
        if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });

        // Write file
        fs.writeFileSync(rulesPath, JSON.stringify(msg.rules, null, 2), "utf8");

        const action = msg.action === "delete" ? "deleted" : "saved";
        vscode.window.showInformationMessage(`✅ IVD Rules ${action} successfully!`);
        
        // Reload to confirm
        const newData = readRules();
        panel.webview.postMessage({ command: "loadRules", rules: newData });

      } catch (e) {
        vscode.window.showErrorMessage("Failed to save IVD rules: " + e);
      }
    }
  });
}