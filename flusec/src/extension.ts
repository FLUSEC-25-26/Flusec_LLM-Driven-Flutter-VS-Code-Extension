// src/extension.ts
//
// Main entry point for the VS Code extension.
// Wires up:
// - activation / deactivation
// - commands
// - auto-scan triggers
// - hover provider
// - one-time cleanup of old findings.json

import * as vscode from "vscode";
import * as fs from "fs";
import * as path from "path";
import { runAnalyzer, findingsPathForFolder } from "./analyzer/runAnalyzer.js";
import { diagCollection } from "./analyzer/findingsStore.js";
import { registerHoverProvider } from "./diagnostics/hoverllm.js";
import { openRuleManager } from "./ui/ruleManager/hardcoded_secrets/ruleManager.js";
import { openDashboard } from "./web/hsd/dashboard.js";
import { registerFlusecNavigationView } from "./ui/flusecNavigation.js";

let lastDartDoc: vscode.TextDocument | undefined;

// We only want to clear findings.json once per VS Code session.
let clearedFindingsThisSession = false;

//  Delete findings.json for all workspace folders ONCE per session
function clearFindingsForAllWorkspaceFoldersOnce() {
  if (clearedFindingsThisSession) {
    return;
  }

  const folders = vscode.workspace.workspaceFolders ?? [];
  if (!folders.length) {
    return;
  }

  try {
    for (const folder of folders) {
      const findingsPath = findingsPathForFolder(folder);

      // 1️⃣ delete findings.json
      if (fs.existsSync(findingsPath)) {
        fs.unlinkSync(findingsPath);
        console.log("FLUSEC: deleted", findingsPath);
      }

      // 2️⃣ compute directories
      const outDir = path.dirname(findingsPath);
      const analyzerDir = path.dirname(outDir);

      // 3️⃣ delete .out if empty
      if (fs.existsSync(outDir) && fs.readdirSync(outDir).length === 0) {
        fs.rmdirSync(outDir);
        console.log("FLUSEC: deleted empty dir", outDir);
      }

      // 4️⃣ delete dart-analyzer if empty
      if (
        fs.existsSync(analyzerDir) &&
        fs.readdirSync(analyzerDir).length === 0
      ) {
        fs.rmdirSync(analyzerDir);
        console.log("FLUSEC: deleted empty dir", analyzerDir);
      }
    }
  } catch (e) {
    console.warn("FLUSEC: Cleanup warning:", e);
  }

  clearedFindingsThisSession = true;
}


export function activate(context: vscode.ExtensionContext) {
  // Ensure diagnostics collection is disposed when extension is deactivated.
  context.subscriptions.push(diagCollection);

  // Try to clear immediately if a workspace is already open when extension activates.
  clearFindingsForAllWorkspaceFoldersOnce();

  // Also clear once when folders are added later (Dev Host starts empty, then you open folder).
  context.subscriptions.push(
    vscode.workspace.onDidChangeWorkspaceFolders(() => {
      clearFindingsForAllWorkspaceFoldersOnce();
    })
  );

  // Track last Dart document when opened.
  context.subscriptions.push(
    vscode.workspace.onDidOpenTextDocument((doc) => {
      if (doc.languageId === "dart") {
        lastDartDoc = doc;
      }
    })
  );

  // -----------------------------
  // Manual scan command
  // -----------------------------
  context.subscriptions.push(
    vscode.commands.registerCommand("flusec.scanFile", async () => {
      const active = vscode.window.activeTextEditor;
      let target: vscode.TextDocument | undefined;

      if (active && active.document.languageId === "dart") {
        target = active.document;
      } else if (lastDartDoc) {
        target = lastDartDoc;
      } else {
        const dartDocs = vscode.workspace.textDocuments.filter(
          (d) => d.languageId === "dart"
        );
        if (dartDocs.length > 0) {
          target = dartDocs[0];
        }
      }

      if (!target) {
        vscode.window.showInformationMessage(
          "FLUSEC: No Dart file available to scan. Open a Dart file first."
        );
        return;
      }

      try {
        await runAnalyzer(target, context);
        vscode.window.setStatusBarMessage(
          `FLUSEC: Scan completed for ${target.fileName}`,
          3000
        );
      } catch (e) {
        vscode.window.showErrorMessage(
          "FLUSEC: Scan failed: " + String(e)
        );
      }
    })
  );

  // -----------------------------
  // Rule manager (dynamic rules UI)
  // -----------------------------
  context.subscriptions.push(
    vscode.commands.registerCommand("flusec.manageRules", () =>
      openRuleManager(context)
    )
  );

  // -----------------------------
  // Findings dashboard
  // -----------------------------
  context.subscriptions.push(
    vscode.commands.registerCommand("flusec.openFindings", () =>
      openDashboard(context)
    )
  );

  // -----------------------------
  // Auto scan on SAVE
  // -----------------------------
  context.subscriptions.push(
    vscode.workspace.onDidSaveTextDocument(async (doc) => {
      if (doc.languageId === "dart") {
        lastDartDoc = doc;
        await runAnalyzer(doc, context);
      }
    })
  );

  // -----------------------------
  // Auto scan while TYPING (debounced)
  // -----------------------------
  let typingTimeout: NodeJS.Timeout | undefined;

  context.subscriptions.push(
    vscode.workspace.onDidChangeTextDocument((event) => {
      const doc = event.document;
      if (doc.languageId !== "dart") {
        return;
      }

      lastDartDoc = doc;

      clearTimeout(typingTimeout);
      typingTimeout = setTimeout(() => {
        runAnalyzer(doc, context);
      }, 1500);
    })
  );

  // -----------------------------
  // Hover provider (LLM feedback)
  // -----------------------------
  registerHoverProvider(context);

  registerFlusecNavigationView(context);
}

export function deactivate() {
  diagCollection.clear();
  diagCollection.dispose();
}
