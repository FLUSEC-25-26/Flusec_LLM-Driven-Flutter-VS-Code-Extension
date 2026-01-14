// // src/extension.ts
// //
// // Main entry point for the VS Code extension.
// // Wires up:
// // - activation / deactivation
// // - commands
// // - auto-scan triggers
// // - hover provider
// // - one-time cleanup of old findings.json

import * as vscode from "vscode";
import * as fs from "fs";
import * as path from "path";
import { runAnalyzer, findingsPathForFolder } from "./analyzer/runAnalyzer.js";
import { diagCollection } from "./analyzer/findingsStore.js";
import { registerHoverProvider } from "./diagnostics/hoverllm.js";
import { openRuleManager } from "./ui/ruleManager/hardcoded_secrets/ruleManager.js";
import { registerFlusecNavigationView } from "./ui/flusecNavigation.js";
import { openDashboard } from "./web/hsd/dashboard.js";

import { openIvdDashboard } from "./web/ivd/dashboard.js";
import { openIvdRuleManager } from "./ui/ruleManager/ivd/ivdRuleManager.js"; 

let lastDartDoc: vscode.TextDocument | undefined;
let clearedFindingsThisSession = false;

function clearFindingsForAllWorkspaceFoldersOnce() {
  if (clearedFindingsThisSession) return;
  const folders = vscode.workspace.workspaceFolders ?? [];
  if (!folders.length) return;

  try {
    for (const folder of folders) {
      const findingsPath = findingsPathForFolder(folder);
      if (fs.existsSync(findingsPath)) fs.unlinkSync(findingsPath);
      
      const outDir = path.dirname(findingsPath);
      if (fs.existsSync(outDir) && fs.readdirSync(outDir).length === 0) fs.rmdirSync(outDir);
      
      const analyzerDir = path.dirname(outDir);
      if (fs.existsSync(analyzerDir) && fs.readdirSync(analyzerDir).length === 0) fs.rmdirSync(analyzerDir);
    }
  } catch (e) { console.warn("FLUSEC: Cleanup warning:", e); }
  clearedFindingsThisSession = true;
}

export function activate(context: vscode.ExtensionContext) {
  context.subscriptions.push(diagCollection);
  clearFindingsForAllWorkspaceFoldersOnce();

  context.subscriptions.push(vscode.workspace.onDidChangeWorkspaceFolders(() => {
      clearFindingsForAllWorkspaceFoldersOnce();
  }));

  context.subscriptions.push(vscode.workspace.onDidOpenTextDocument((doc) => {
      if (doc.languageId === "dart") lastDartDoc = doc;
  }));

  // --- NAVIGATION ---
  registerFlusecNavigationView(context);

  context.subscriptions.push(
    vscode.commands.registerCommand("flusec.openFindings", () => openDashboard(context))
  );

  // 2. IVD Dashboard
  context.subscriptions.push(
    vscode.commands.registerCommand("flusec.openIvdFindings", () => openIvdDashboard(context))
  );

  context.subscriptions.push(
    vscode.commands.registerCommand("flusec.manageRules", () => openRuleManager(context))
  );

  // 4. IVD Rule Manager
  context.subscriptions.push(
    vscode.commands.registerCommand("flusec.manageIvdRules", () => openIvdRuleManager(context))
  );

  // 5. Scan File
  context.subscriptions.push(
    vscode.commands.registerCommand("flusec.scanFile", async () => {
      const active = vscode.window.activeTextEditor;
      let target = active && active.document.languageId === "dart" ? active.document : lastDartDoc;

      if (!target) {
        const dartDocs = vscode.workspace.textDocuments.filter(d => d.languageId === "dart");
        if (dartDocs.length > 0) target = dartDocs[0];
      }

      if (!target) {
        vscode.window.showInformationMessage("FLUSEC: No Dart file available to scan.");
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

  // --- LISTENERS ---
  context.subscriptions.push(
    vscode.workspace.onDidSaveTextDocument(async (doc) => {
      if (doc.languageId === "dart") {
        lastDartDoc = doc;
        await runAnalyzer(doc, context);
      }
    })
  );

  let typingTimeout: NodeJS.Timeout | undefined;
  context.subscriptions.push(
    vscode.workspace.onDidChangeTextDocument((event) => {
      const doc = event.document;
      if (doc.languageId !== "dart") return;
      lastDartDoc = doc;
      clearTimeout(typingTimeout);
      typingTimeout = setTimeout(() => { runAnalyzer(doc, context); }, 1500);
    })
  );

  registerHoverProvider(context);
}

export function deactivate() {
  diagCollection.clear();
  diagCollection.dispose();
}