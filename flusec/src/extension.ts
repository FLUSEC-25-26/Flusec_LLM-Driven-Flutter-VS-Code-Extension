import * as vscode from "vscode";
import * as fs from "fs";
import * as path from "path";
import { runAnalyzer, findingsPathForFolder } from "./analyzer/runAnalyzer.js";
import { diagCollection } from "./analyzer/findingsStore.js";
import { registerHoverProvider } from "./diagnostics/hoverllm.js";
import { openRuleManager } from "./ui/ruleManager/hardcoded_secrets/ruleManager.js";
import { openDashboard } from "./web/hsd/dashboard.js";
import { registerFlusecNavigationView } from "./ui/flusecNavigation.js";
import { syncHsdRulePack, writeHsdWorkspaceData } from "./rules/hsdRulePack.js";
import { uploadFindingsCommand } from "./cloud/uploadFindings.js";


let lastDartDoc: vscode.TextDocument | undefined;

// We only want to clear findings.json once per VS Code session.
let clearedFindingsThisSession = false;

// Delete findings.json for all workspace folders ONCE per session
function clearFindingsForAllWorkspaceFoldersOnce() {
  if (clearedFindingsThisSession) {return;}

  const folders = vscode.workspace.workspaceFolders ?? [];
  if (!folders.length) {return;}

  try {
    for (const folder of folders) {
      const findingsPath = findingsPathForFolder(folder);

      if (fs.existsSync(findingsPath)) {
        fs.unlinkSync(findingsPath);
        console.log("FLUSEC: deleted", findingsPath);
      }

      // NEW: findings now live under <workspace>/.flusec/.out/findings.json
      // So analyzerDir = <workspace>/.flusec
      const outDir = path.dirname(findingsPath);       // .../.flusec/.out
      const analyzerDir = path.dirname(outDir);        // .../.flusec

      if (fs.existsSync(outDir) && fs.readdirSync(outDir).length === 0) {
        fs.rmdirSync(outDir);
        console.log("FLUSEC: deleted empty dir", outDir);
      }

      if (fs.existsSync(analyzerDir) && fs.readdirSync(analyzerDir).length === 0) {
        fs.rmdirSync(analyzerDir);
        console.log("FLUSEC: deleted empty dir", analyzerDir);
      }
    }
  } catch (e) {
    console.warn("FLUSEC: Cleanup warning:", e);
  }

  clearedFindingsThisSession = true;
}

export async function activate(context: vscode.ExtensionContext) {
  // Ensure diagnostics collection is disposed when extension is deactivated.
  context.subscriptions.push(diagCollection);

  // keep your old cleanup behavior
  clearFindingsForAllWorkspaceFoldersOnce();

  // Mandatory remote sync (safe offline) + then write workspace effective files
  try {
    await syncHsdRulePack(context);
  } catch (e) {
    console.error("[FLUSEC] syncHsdRulePack (startup) failed:", e);
  }

  for (const f of vscode.workspace.workspaceFolders ?? []) {
    writeHsdWorkspaceData(context, f.uri.fsPath);
  }

  // Periodic mandatory update (6 hours)
  const timer = setInterval(async () => {
    try {
      await syncHsdRulePack(context);
      for (const f of vscode.workspace.workspaceFolders ?? []) {
        writeHsdWorkspaceData(context, f.uri.fsPath);
      }
    } catch (e) {
      console.error("[FLUSEC] periodic rulepack sync failed:", e);
    }
  }, 6 * 60 * 60 * 1000);

  context.subscriptions.push({ dispose: () => clearInterval(timer) });

  // If folders added later
  context.subscriptions.push(
    vscode.workspace.onDidChangeWorkspaceFolders(() => {
      clearFindingsForAllWorkspaceFoldersOnce();
      for (const f of vscode.workspace.workspaceFolders ?? []) {
        writeHsdWorkspaceData(context, f.uri.fsPath);
      }
    })
  );

  // Track last Dart doc
  context.subscriptions.push(
    vscode.workspace.onDidOpenTextDocument((doc) => {
      if (doc.languageId === "dart") {lastDartDoc = doc;}
    })
  );

  // Force update rulepacks
  context.subscriptions.push(
    vscode.commands.registerCommand("flusec.updateRulePacks", async () => {
      try {
        await syncHsdRulePack(context, { force: true });
        for (const f of vscode.workspace.workspaceFolders ?? []) {
          writeHsdWorkspaceData(context, f.uri.fsPath);
        }
        vscode.window.showInformationMessage("FLUSEC: Rule packs updated.");
      } catch (e) {
        console.error("[FLUSEC] updateRulePacks failed:", e);
        vscode.window.showErrorMessage("FLUSEC: Rule pack update failed. Check console.");
      }
    })
  );

  // Manual scan
  context.subscriptions.push(
    vscode.commands.registerCommand("flusec.scanFile", async () => {
      const active = vscode.window.activeTextEditor;
      let target: vscode.TextDocument | undefined;

      if (active && active.document.languageId === "dart") {target = active.document;}
      else if (lastDartDoc) {target = lastDartDoc;}
      else {
        const dartDocs = vscode.workspace.textDocuments.filter((d) => d.languageId === "dart");
        if (dartDocs.length > 0) {target = dartDocs[0];}
      }

      if (!target) {
        vscode.window.showInformationMessage(
          "FLUSEC: No Dart file available to scan. Open a Dart file first."
        );
        return;
      }

      try {
        await runAnalyzer(target, context);
        vscode.window.setStatusBarMessage(`FLUSEC: Scan completed for ${target.fileName}`, 3000);
      } catch (e) {
        vscode.window.showErrorMessage("FLUSEC: Scan failed: " + String(e));
      }
    })
  );

  // Rule manager
  context.subscriptions.push(
    vscode.commands.registerCommand("flusec.manageRules", () => openRuleManager(context))
  );

  // Dashboard
  context.subscriptions.push(
    vscode.commands.registerCommand("flusec.openFindings", () => openDashboard(context))
  );

  context.subscriptions.push(
    vscode.commands.registerCommand("flusec.uploadFindings", async () => {
      try {
        await uploadFindingsCommand(context);
      } catch (e) {
        vscode.window.showErrorMessage("FLUSEC: Upload failed: " + String(e));
      }
    })
  );


  // Auto scan on SAVE
  context.subscriptions.push(
    vscode.workspace.onDidSaveTextDocument(async (doc) => {
      if (doc.languageId === "dart") {
        lastDartDoc = doc;
        await runAnalyzer(doc, context);
      }
    })
  );

  // Auto scan while TYPING (debounced)
  let typingTimeout: NodeJS.Timeout | undefined;
  context.subscriptions.push(
    vscode.workspace.onDidChangeTextDocument((event) => {
      const doc = event.document;
      if (doc.languageId !== "dart") {return;}

      lastDartDoc = doc;

      clearTimeout(typingTimeout);
      typingTimeout = setTimeout(() => {
        runAnalyzer(doc, context);
      }, 1500);
    })
  );

  // Hover provider (LLM feedback)
  registerHoverProvider(context);

  // Navigation view
  registerFlusecNavigationView(context);
}

export function deactivate() {
  diagCollection.clear();
  diagCollection.dispose();
}
