import * as vscode from "vscode";
import * as fs from "fs";
import * as path from "path";
import { hsdStoragePaths, writeHsdWorkspaceData } from "../../../rules/hsdRulePack.js";

/**
 * Opens the Rule Manager UI as a VS Code Webview.
 * NOW:
 * - reads/writes USER rules to globalStorage (per developer machine)
 * - after any change, regenerates workspace effective rule files
 * Keeps ALL your old webview message commands:
 * - saveRules (with action/deletedId)
 * - confirmDelete (modal confirm)
 * - refresh
 * - debugPath
 */
export function openRuleManager(context: vscode.ExtensionContext) {
  const panel = vscode.window.createWebviewPanel(
    "ruleManager",
    "Flusec Rule Manager",
    vscode.ViewColumn.One,
    { enableScripts: true, retainContextWhenHidden: true }
  );

  const extensionRoot = context.extensionUri.fsPath;

  // Packaged HTML is under web/ (because package.json files includes web/)
  // Dev HTML is under src/
  const htmlFileWeb = path.join(
    extensionRoot,
    "web",
    "ruleManager",
    "hardcoded_secrets",
    "ruleManager.html"
  );

  const htmlFileSrc = path.join(
    extensionRoot,
    "src",
    "ui",
    "ruleManager",
    "hardcoded_secrets",
    "ruleManager.html"
  );

  const htmlPath = fs.existsSync(htmlFileWeb) ? htmlFileWeb : htmlFileSrc;

  panel.webview.html = fs.existsSync(htmlPath)
    ? fs.readFileSync(htmlPath, "utf8")
    : `<html><body><h3>Missing rule manager HTML:</h3><pre>${htmlPath}</pre></body></html>`;

  // USER rules stored locally (globalStorage)
  const sp = hsdStoragePaths(context);
  const userRulesPath = sp.userRules;

  function ensureRulesFileExists() {
    try {
      if (!fs.existsSync(userRulesPath)) {
        fs.mkdirSync(path.dirname(userRulesPath), { recursive: true });
        fs.writeFileSync(userRulesPath, "[]\n", "utf8");
      }
    } catch {
      // ignore
    }
  }

  function readRules(): any[] {
    try {
      ensureRulesFileExists();
      const txt = fs.readFileSync(userRulesPath, "utf8");
      const json = JSON.parse(txt);
      return Array.isArray(json) ? json : [];
    } catch {
      return [];
    }
  }

  function writeRules(rules: any[]) {
    ensureRulesFileExists();
    fs.mkdirSync(path.dirname(userRulesPath), { recursive: true });
    const tmp = userRulesPath + ".tmp";
    fs.writeFileSync(tmp, JSON.stringify(rules, null, 2), "utf8");
    fs.renameSync(tmp, userRulesPath);
  }

  function loadRulesIntoWebview() {
    panel.webview.postMessage({ command: "loadRules", rules: readRules() });
  }

  function rebuildEffectiveRulesForAllWorkspaces() {
    for (const f of vscode.workspace.workspaceFolders ?? []) {
      writeHsdWorkspaceData(context, f.uri.fsPath);
    }
  }

  // Initial load
  loadRulesIntoWebview();

  panel.webview.onDidReceiveMessage(async (msg) => {
    // -------------------------
    // SAVE (keeps old behavior)
    // -------------------------
    if (msg.command === "saveRules") {
      try {
        const rules = Array.isArray(msg.rules) ? msg.rules : [];
        writeRules(rules);

        // NEW: update workspace effective merged rules so analyzer uses latest
        rebuildEffectiveRulesForAllWorkspaces();

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

        // reload and push back
        loadRulesIntoWebview();
      } catch (e: any) {
        vscode.window.showErrorMessage("Failed to save rules: " + (e?.message || e));
      }
      return;
    }

    // -------------------------
    // CONFIRM DELETE (keeps old)
    // -------------------------
    if (msg.command === "confirmDelete") {
      const { id, index } = msg as { id?: string; index?: number };

      const choice = await vscode.window.showWarningMessage(
        `Delete rule${id ? ` "${id}"` : ""}?`,
        { modal: true },
        "Delete",
        "Cancel"
      );

      if (choice !== "Delete") {return;}

      try {
        const rules = readRules();

        // Try by ID first
        let delIndex = -1;
        if (id) {delIndex = rules.findIndex((r) => r && r.id === id);}

        // Fallback to index if needed
        if ((delIndex < 0 || delIndex >= rules.length) && typeof index === "number") {
          if (index >= 0 && index < rules.length) {delIndex = index;}
        }

        if (delIndex >= 0 && delIndex < rules.length) {
          const removed = rules.splice(delIndex, 1);
          writeRules(rules);

          // NEW: update workspace effective merged rules
          rebuildEffectiveRulesForAllWorkspaces();

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
      return;
    }

    // -------------------------
    // REFRESH (keeps old)
    // -------------------------
    if (msg.command === "refresh") {
      loadRulesIntoWebview();
      return;
    }

    // -------------------------
    // DEBUG PATH (keeps old)
    // -------------------------
    if (msg.command === "debugPath") {
      vscode.window.showInformationMessage(`User rules path: ${userRulesPath}`);
      return;
    }
  });
}
