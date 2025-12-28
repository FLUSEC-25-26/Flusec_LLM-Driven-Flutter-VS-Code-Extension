// src/extension.ts
//
// Main entry point for the VS Code extension.
// Now this file only wires up:
// - activation / deactivation
// - commands
// - auto-scan triggers
// - hover provider
//
// All heavy logic (analyzer, diagnostics, LLM, dashboard)
// is moved into dedicated modules for easier maintenance.

import * as vscode from "vscode";
import { runAnalyzer } from "./analyzer/runAnalyzer.js";
import { diagCollection } from "./analyzer/findingsStore.js";
import { registerHoverProvider } from "./diagnostics/hoverllm.js";
import { openRuleManager } from "./ui/ruleManager/hardcoded_secrets/ruleManager.js";
import { openDashboard } from "./web/hsd/dashboard.js";
import { registerFlusecNavigationView } from "./ui/flusecNavigation.js";


export function activate(context: vscode.ExtensionContext) {
  // Ensure diagnostics collection is disposed when extension is deactivated.
  context.subscriptions.push(diagCollection);

  // -----------------------------
  // Manual scan command
  // -----------------------------
  context.subscriptions.push(
    vscode.commands.registerCommand("flusec.scanFile", async () => {
      const editor = vscode.window.activeTextEditor;
      if (editor) {
        await runAnalyzer(editor.document, context);
      } else {
        vscode.window.showInformationMessage("No active Dart file to scan.");
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

      // Clear previous pending scan
      clearTimeout(typingTimeout);

      // Schedule scan 1.5s after last change
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
  // Clear diagnostics when extension is deactivated.
  diagCollection.clear();
  diagCollection.dispose();
}
