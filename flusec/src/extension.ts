// src/extension.ts

import * as vscode from "vscode";
import * as fs from "fs";
import * as path from "path";
import { runAnalyzer, findingsPathForFolder } from "./analyzer/runAnalyzer.js";
import { diagCollection } from "./analyzer/findingsStore.js";
import { registerHoverProvider } from "./diagnostics/hoverllm.js";
import { openIvdRuleManager } from "./ui/ruleManager/ivd/ivdRuleManager.js"; // Updated to IVD
import { openIvdDashboard } from "./web/ivd/dashboard.js"; // Updated to IVD
import { registerFlusecNavigationView } from "./ui/flusecNavigation.js";

let lastDartDoc: vscode.TextDocument | undefined;
let clearedFindingsThisSession = false;

/**
 * Cleans up old findings.json files once per VS Code session.
 */
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

      if (fs.existsSync(findingsPath)) {
        fs.unlinkSync(findingsPath);
      }

      const outDir = path.dirname(findingsPath);
      const analyzerDir = path.dirname(outDir);

      if (fs.existsSync(outDir) && fs.readdirSync(outDir).length === 0) {
        fs.rmdirSync(outDir);
      }

      if (fs.existsSync(analyzerDir) && fs.readdirSync(analyzerDir).length === 0) {
        fs.rmdirSync(analyzerDir);
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

  // Initial cleanup
  clearFindingsForAllWorkspaceFoldersOnce();

  // If folders are added later, perform cleanup
  context.subscriptions.push(
    vscode.workspace.onDidChangeWorkspaceFolders(() => {
      clearFindingsForAllWorkspaceFoldersOnce();
    })
  );

  // Track last opened Dart document
  context.subscriptions.push(
    vscode.workspace.onDidOpenTextDocument((doc) => {
      if (doc.languageId === "dart") {
        lastDartDoc = doc;
      }
    })
  );

  // --- COMMANDS ---

  // Manual scan command
  context.subscriptions.push(
    vscode.commands.registerCommand("flusec.scanFile", async () => {
      const active = vscode.window.activeTextEditor;
      let target: vscode.TextDocument | undefined;

      if (active && active.document.languageId === "dart") {
        target = active.document;
      } else if (lastDartDoc) {
        target = lastDartDoc;
      } else {
        const dartDocs = vscode.workspace.textDocuments.filter((d) => d.languageId === "dart");
        if (dartDocs.length > 0) {
          target = dartDocs[0];
        }
      }

      if (!target) {
        vscode.window.showInformationMessage("FLUSEC: Open a Dart file first to scan.");
        return;
      }

      try {
        await runAnalyzer(target, context);
        vscode.window.setStatusBarMessage(`FLUSEC: IVD Scan completed for ${target.fileName}`, 3000);
      } catch (e) {
        vscode.window.showErrorMessage("FLUSEC: Scan failed: " + String(e));
      }
    })
  );

  // IVD Rule manager (Renamed from manageRules/hsd)
  context.subscriptions.push(
    vscode.commands.registerCommand("flusec.manageIvdRules", () => openIvdRuleManager(context))
  );

  // IVD Dashboard (Renamed from openFindings/hsd)
  context.subscriptions.push(
    vscode.commands.registerCommand("flusec.openIvdFindings", () => openIvdDashboard(context))
  );

  // --- AUTOMATION ---

  // Auto scan on SAVE
  context.subscriptions.push(
    vscode.workspace.onDidSaveTextDocument(async (doc) => {
      if (doc.languageId === "dart") {
        lastDartDoc = doc;
        await runAnalyzer(doc, context);
      }
    })
  );

  // Auto scan while TYPING (debounced 1.5s)
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

  // --- UI REGISTRATION ---

  // Hover provider (LLM feedback)
  registerHoverProvider(context);

  // Navigation view (Side bar)
  registerFlusecNavigationView(context);
}

export function deactivate() {
  // Clear the diagnostics to prevent memory leaks
  diagCollection.clear();
  diagCollection.dispose();
  
  // Optional: Add logging to verify clean shutdown
  console.log("FLUSEC: Extension deactivated successfully.");
}