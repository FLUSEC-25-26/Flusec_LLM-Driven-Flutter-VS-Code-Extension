// src/components/hsd/ruleManager.ts
//
// HSD-only Rule Manager.
// It opens a webview (ruleManager.html) and edits ONE file:
//   <extensionRoot>/dart-analyzer/data/hardcoded_secrets_rules.json
//
// ✅ Only your HSD component needs this.
// Other components will implement their own manager later, with their own rules files.

import * as vscode from "vscode";
import * as fs from "fs";
import * as path from "path";
import {
  componentRuleManagerHtmlPath,
  rulesJsonPathForComponent,
} from "../../shared/paths";
import { HSD_RULES_FILE } from "./settings";

export function openHsdRuleManager(context: vscode.ExtensionContext) {
  const panel = vscode.window.createWebviewPanel(
    "hsdRuleManager",
    "HSD Rule Manager (Hardcoded Secrets)",
    vscode.ViewColumn.One,
    { enableScripts: true, retainContextWhenHidden: true }
  );

  // ✅ Rules JSON path for HSD
  const rulesPath = rulesJsonPathForComponent(context, HSD_RULES_FILE);

  // ✅ HTML path (HSD-only UI)
  const htmlFile = componentRuleManagerHtmlPath(
    context,
    path.join("src", "components", "hsd", "ui", "ruleManager.html")
  );

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
    if (!msg || typeof msg.command !== "string") return;

    // Save all rules (or delete action)
    if (msg.command === "saveRules") {
      try {
        writeRules(msg.rules);

        const action = typeof msg.action === "string" ? msg.action : "save";
        const deletedId =
          typeof msg.deletedId === "string" && msg.deletedId.trim().length > 0
            ? msg.deletedId.trim()
            : "";

        const toast =
          action === "delete"
            ? `🗑️ Rule deleted successfully${deletedId ? `: ${deletedId}` : ""}.`
            : "✅ Rules saved successfully!";

        vscode.window.showInformationMessage(toast);

        loadRulesIntoWebview();
      } catch (e) {
        vscode.window.showErrorMessage("Failed to save rules: " + e);
      }
      return;
    }

    // Optional confirm delete flow (you currently use direct deleteInWebview)
    if (msg.command === "confirmDelete") {
      const { id, index } = msg as { id?: string; index?: number };
      const choice = await vscode.window.showWarningMessage(
        `Delete rule${id ? ` "${id}"` : ""}?`,
        { modal: true },
        "Delete",
        "Cancel"
      );
      if (choice !== "Delete") return;

      try {
        const rules = readRules();

        let delIndex = -1;
        if (id) delIndex = rules.findIndex((r) => r && r.id === id);

        if ((delIndex < 0 || delIndex >= rules.length) && typeof index === "number") {
          if (index >= 0 && index < rules.length) delIndex = index;
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
      return;
    }

    if (msg.command === "refresh") {
      loadRulesIntoWebview();
      return;
    }

    if (msg.command === "debugPath") {
      vscode.window.showInformationMessage(`Rules path: ${rulesPath}`);
      return;
    }
  });
}
