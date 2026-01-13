import * as vscode from "vscode";
import * as fs from "fs";
import * as path from "path";
import { hsdStoragePaths, writeHsdWorkspaceData } from "../../../rules/hsdRulePack.js";

export function openRuleManager(context: vscode.ExtensionContext) {
  const panel = vscode.window.createWebviewPanel(
    "ruleManager",
    "Flusec Rule Manager",
    vscode.ViewColumn.One,
    { enableScripts: true, retainContextWhenHidden: true }
  );

  const extensionRoot = context.extensionUri.fsPath;

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

  // Workspace-first rules path (.flusec/user_rules.json)
  const active = vscode.window.activeTextEditor?.document;
  const wf =
    (active ? vscode.workspace.getWorkspaceFolder(active.uri) : undefined) ??
    vscode.workspace.workspaceFolders?.[0];

  const userRulesPath = wf
    ? path.join(wf.uri.fsPath, ".flusec", "user_rules.json")
    : hsdStoragePaths(context).userRules; // fallback if no workspace

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

  loadRulesIntoWebview();

  panel.webview.onDidReceiveMessage(async (msg) => {
    if (msg.command === "saveRules") {
      try {
        const rules = Array.isArray(msg.rules) ? msg.rules : [];
        writeRules(rules);

        rebuildEffectiveRulesForAllWorkspaces();

        const action = typeof msg.action === "string" ? msg.action : "save";
        const deletedId =
          typeof msg.deletedId === "string" && msg.deletedId.trim().length > 0
            ? msg.deletedId.trim()
            : "";

        console.log("[RuleManager] saveRules action =", action, "deletedId =", deletedId);

        const toast =
          action === "delete"
            ? `Rule deleted successfully${deletedId ? `: ${deletedId}` : ""}.`
            : "Rules saved successfully.";

        vscode.window.showInformationMessage(toast);

        loadRulesIntoWebview();
      } catch (e: any) {
        vscode.window.showErrorMessage("Failed to save rules: " + (e?.message || e));
      }
      return;
    }

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

        let delIndex = -1;
        if (id) {delIndex = rules.findIndex((r) => r && r.id === id);}

        if ((delIndex < 0 || delIndex >= rules.length) && typeof index === "number") {
          if (index >= 0 && index < rules.length) {delIndex = index;}
        }

        if (delIndex >= 0 && delIndex < rules.length) {
          const removed = rules.splice(delIndex, 1);
          writeRules(rules);

          rebuildEffectiveRulesForAllWorkspaces();

          vscode.window.showInformationMessage(
            `Deleted rule${removed[0]?.id ? ` "${removed[0].id}"` : ""}.`
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
      vscode.window.showInformationMessage(`User rules path: ${userRulesPath}`);
      return;
    }
  });
}
