// src/analyzer/runAnalyzer.ts

import * as vscode from "vscode";
import { exec } from "child_process";
import * as path from "path";
import * as fs from "fs";

import {
  diagCollection,
  severityToVS,
  upsertFindingsForDoc,
} from "./findingsStore.js";
import {
  resetLLMState,
  clearFeedbackForDocument,
} from "../diagnostics/hoverllm.js";

export function findWorkspaceFolderForDoc(
  doc: vscode.TextDocument
): vscode.WorkspaceFolder | undefined {
  return (
    vscode.workspace.getWorkspaceFolder(doc.uri) ??
    vscode.workspace.workspaceFolders?.[0]
  );
}

export function findingsPathForFolder(
  folder: vscode.WorkspaceFolder
): string {
  return path.join(folder.uri.fsPath, "dart-analyzer", ".out", "findings.json");
}

export async function runAnalyzer(
  doc: vscode.TextDocument,
  _context: vscode.ExtensionContext
): Promise<void> {
  resetLLMState();
  clearFeedbackForDocument(doc.uri);

  const folder = findWorkspaceFolderForDoc(doc);
  if (!folder) return;

  const findingsFile = findingsPathForFolder(folder);

  // ---------------------------------------------------------
  // ⚡️ FIX: Point to analyzer.dart (Source Code), NOT .exe
  // ---------------------------------------------------------
  const analyzerScript = path.join(
    __dirname,
    "..",
    "dart-analyzer",
    "bin",
    "analyzer.dart"
  );

  if (!fs.existsSync(analyzerScript)) {
    vscode.window.showErrorMessage(`Analyzer script not found: ${analyzerScript}`);
    return;
  }

  // Run 'dart run' command
  // Ensure "dart" is in your system PATH (open cmd and type 'dart --version' to check)
  const command = `dart run "${analyzerScript}" "${doc.fileName}"`;

  const stdout = await new Promise<string>((resolve, reject) => {
    exec(command, (err, stdout, stderr) => {
      if (err) {
        console.error("Analyzer Error:", stderr);
        // If the analyzer finds issues, it might exit with code 0 or 1, 
        // but if 'dart' isn't found, it throws an error.
        if (stderr.includes("'dart' is not recognized")) {
             vscode.window.showErrorMessage("Dart SDK not found. Is Flutter/Dart installed and in PATH?");
        }
        return resolve("[]"); // Fail gracefully with empty findings
      }
      resolve(stdout);
    });
  });

  let findings: any[] = [];
  try {
    findings = JSON.parse(stdout);
    if (!Array.isArray(findings)) findings = [];
  } catch (e) {
    console.error("Failed to parse JSON:", e);
    // Silent fail so we don't annoy the user
    return;
  }

  // Update VS Code Diagnostics (Squiggles)
  const diags: vscode.Diagnostic[] = [];
  for (const f of findings) {
    const lineIdx = Math.max(0, (f.line ?? 1) - 1);
    const range = new vscode.Range(lineIdx, 0, lineIdx, 999);

    const diag = new vscode.Diagnostic(
      range,
      f.message || "Security Issue",
      severityToVS(f.severity || "warning")
    );
    diag.source = "flusec";
    diag.code = f.ruleId;
    diags.push(diag);
  }

  diagCollection.set(doc.uri, diags);
  upsertFindingsForDoc(findingsFile, doc, findings);
}