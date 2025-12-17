import * as vscode from "vscode";
import * as fs from "fs";
import * as path from "path";

/**
 * Opens the Rule Manager UI as a VS Code Webview.
 * Loads and saves dart-analyzer/data/rules.json.
 */
export function openRuleManager(context: vscode.ExtensionContext) {
  const panel = vscode.window.createWebviewPanel(
    "ruleManager",
    "Flusec Rule Manager",
    vscode.ViewColumn.One,
    { enableScripts: true, retainContextWhenHidden: true }
  );

  const extensionRoot = context.extensionUri.fsPath;
  const rulesPath = path.join(extensionRoot, "dart-analyzer", "data", "hardcoded_secrets_rules.json");
  const htmlFile = path.join(extensionRoot, "src", "ui", "ruleManager.html");
  panel.webview.html = fs.readFileSync(htmlFile, "utf8");

  function readRules(): any[] {
    try {
      const txt = fs.readFileSync(rulesPath, "utf8");
      const json = JSON.parse(txt);
      return Array.isArray(json) ? json : [];
    } catch {
      return [];
    }
  }

  function writeRules(rules: any[]) {
    fs.mkdirSync(path.dirname(rulesPath), { recursive: true });
    const tmp = rulesPath + ".tmp";
    fs.writeFileSync(tmp, JSON.stringify(rules, null, 2), "utf8");
    fs.renameSync(tmp, rulesPath);
  }

  function loadRulesIntoWebview() {
    const data = readRules();
    panel.webview.postMessage({ command: "loadRules", rules: data });
  }

  // Initial load
  loadRulesIntoWebview();

  panel.webview.onDidReceiveMessage(async (msg) => {
   if (msg.command === "saveRules") {
  try {
    fs.writeFileSync(rulesPath, JSON.stringify(msg.rules, null, 2), "utf8");

    const action = typeof msg.action === "string" ? msg.action : "save";
    const deletedId =
      typeof msg.deletedId === "string" && msg.deletedId.trim().length > 0
        ? msg.deletedId.trim()
        : "";

    console.log("[RuleManager] saveRules action =", action, "deletedId =", deletedId);

    const toast =
      action === "delete"
        ? `🗑️ Rule deleted successfully${deletedId ? `: ${deletedId}` : ""}.`
        : "✅ Rules saved successfully!";

    vscode.window.showInformationMessage(toast);

    const data = JSON.parse(fs.readFileSync(rulesPath, "utf8"));
    panel.webview.postMessage({ command: "loadRules", rules: data });
  } catch (e) {
    vscode.window.showErrorMessage("Failed to save rules: " + e);
  }
}



    else if (msg.command === "confirmDelete") {
      const { id, index } = msg as { id?: string; index?: number };
      const choice = await vscode.window.showWarningMessage(
        `Delete rule${id ? ` "${id}"` : ""}?`,
        { modal: true },
        "Delete",
        "Cancel"
      );
      if (choice !== "Delete"){ return;}

      try {
        const rules = readRules();

        // Try to locate by ID first (preferred)
        let delIndex = -1;
        if (id){ delIndex = rules.findIndex((r) => r && r.id === id);}

        // Fallback to provided index if ID missing or not found
        if ((delIndex < 0 || delIndex >= rules.length) && typeof index === "number") {
          if (index >= 0 && index < rules.length){ delIndex = index;}
        }

        if (delIndex >= 0 && delIndex < rules.length) {
          const removed = rules.splice(delIndex, 1);
          writeRules(rules);
          vscode.window.showInformationMessage(
            `🗑️ Deleted rule${removed[0]?.id ? ` "${removed[0].id}"` : ""}.`
          );
          loadRulesIntoWebview();
        } else {
          vscode.window.showErrorMessage(
            `Could not find rule to delete (id: ${id ?? "n/a"}, index: ${index ?? "n/a"}).`
          );
        }
      } catch (e: any) {
        vscode.window.showErrorMessage("Failed to delete rule: " + (e?.message || e));
      }
    }

    else if (msg.command === "refresh") {
      loadRulesIntoWebview();
    }

    else if (msg.command === "debugPath") {
      vscode.window.showInformationMessage(`Rules path: ${rulesPath}`);
    }
  });
}
