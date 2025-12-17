// src/components/hsd/index.ts
//
// This is where the HSD component "plugs into" the extension.
//
// It registers:
// ✅ Manual scan command
// ✅ Manage rules command (HSD rule manager UI)
// ✅ Open findings command (dashboard)
// ✅ Auto-scan on save
// ✅ Auto-scan on typing (debounced)
//
// Later, other components will have their own index.ts,
// and you’ll register them from src/extension.ts.

import * as vscode from "vscode";
import * as fs from "fs";

import { findWorkspaceFolderForDoc } from "../../shared/workspace";
import { applyDiagnostics } from "../../shared/diagnostics";
import { ensureDirForFile } from "../../shared/fsUtil";
import { Finding } from "../../shared/types";

import { findingsPathForComponent } from "../../shared/paths";
import { runAnalyzerExe } from "../../shared/analyzerRunner";
import { clearCacheForDocument } from "../../hover/llmQueue";
import { openDashboard } from "../../shared/dashboard";

import { openHsdRuleManager } from "./ruleManager";
import {
  CMD_MANAGE_RULES,
  CMD_OPEN_FINDINGS,
  CMD_SCAN_FILE,
  HSD_COMPONENT_ID,
} from "./settings";

// Writes/merges findings per-document into a component findings.json.
// This is the file your dashboard reads.
// Example:
// <workspace>/dart-analyzer/.out/hsd/findings.json
function upsertFindingsForDoc(
  findingsFilePath: string,
  doc: vscode.TextDocument,
  componentId: string,
  newFindings: Finding[]
) {
  ensureDirForFile(findingsFilePath);

  let all: Finding[] = [];
  if (fs.existsSync(findingsFilePath)) {
    try {
      const parsed = JSON.parse(fs.readFileSync(findingsFilePath, "utf8"));
      all = Array.isArray(parsed) ? parsed : [];
    } catch {
      all = [];
    }
  }

  // Remove old entries for this file (so the file doesn't duplicate rows)
  const filePath = doc.fileName;
  all = all.filter((x) => x?.file !== filePath);

  // Store new ones with component tagging
  for (const f of newFindings) {
    all.push({
      ...f,
      file: filePath,
      component: componentId,
    });
  }

  fs.writeFileSync(findingsFilePath, JSON.stringify(all, null, 2), "utf8");
}

async function runHsdAnalyzerForDoc(doc: vscode.TextDocument, context: vscode.ExtensionContext) {
  const folder = findWorkspaceFolderForDoc(doc);
  if (!folder) {
    vscode.window.showErrorMessage("No workspace folder found for this document.");
    return;
  }

  const findingsFile = findingsPathForComponent(folder, HSD_COMPONENT_ID);

  // 1) Run analyzer.exe
  let findings: Finding[] = [];
  try {
    findings = await runAnalyzerExe(context, folder, doc.fileName);
  } catch (e) {
    console.error("Analyzer execution error:", e);
    return;
  }

  // 2) Clear LLM cache for this document so hover uses fresh messages
  clearCacheForDocument(doc.uri);

  // 3) Apply diagnostics immediately (squiggles + problems panel)
  applyDiagnostics(
    findings.map((f) => ({
      ...f,
      file: doc.fileName, // enforce correct file
      component: HSD_COMPONENT_ID,
    }))
  );

  // 4) Persist findings for dashboard/history (component-separated)
  upsertFindingsForDoc(findingsFile, doc, HSD_COMPONENT_ID, findings);
}

export function registerHsdComponent(context: vscode.ExtensionContext) {
  // Manual scan
  context.subscriptions.push(
    vscode.commands.registerCommand(CMD_SCAN_FILE, async () => {
      const editor = vscode.window.activeTextEditor;
      if (editor && editor.document.languageId === "dart") {
        await runHsdAnalyzerForDoc(editor.document, context);
      }
    })
  );

  // HSD rule manager
  context.subscriptions.push(
    vscode.commands.registerCommand(CMD_MANAGE_RULES, async () => {
      openHsdRuleManager(context);
    })
  );

  // Findings dashboard (opens the HSD findings)
  context.subscriptions.push(
    vscode.commands.registerCommand(CMD_OPEN_FINDINGS, async () => {
      const editor = vscode.window.activeTextEditor;
      if (!editor) {
        vscode.window.showErrorMessage("Open a Dart file first to locate workspace.");
        return;
      }
      const folder = findWorkspaceFolderForDoc(editor.document);
      if (!folder) {
        vscode.window.showErrorMessage("No workspace folder found.");
        return;
      }
      const findingsFile = findingsPathForComponent(folder, HSD_COMPONENT_ID);
      openDashboard(context, findingsFile);
    })
  );

  // AUTO scan on SAVE
  context.subscriptions.push(
    vscode.workspace.onDidSaveTextDocument(async (doc) => {
      if (doc.languageId === "dart") {
        await runHsdAnalyzerForDoc(doc, context);
      }
    })
  );

  // AUTO scan while TYPING (debounced)
  let typingTimeout: NodeJS.Timeout | undefined;
  context.subscriptions.push(
    vscode.workspace.onDidChangeTextDocument((event) => {
      const doc = event.document;
      if (doc.languageId !== "dart") return;

      clearTimeout(typingTimeout);
      typingTimeout = setTimeout(() => {
        runHsdAnalyzerForDoc(doc, context);
      }, 1500);
    })
  );

  // ✅ When other components implement theirs:
  // - they can either reuse the same commands but add a picker UI,
  //   OR use separate commands:
  //   flusec.network.scanFile, flusec.storage.scanFile, etc.
}
