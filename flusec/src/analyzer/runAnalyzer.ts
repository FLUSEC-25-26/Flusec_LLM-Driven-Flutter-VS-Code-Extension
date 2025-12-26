// src/analyzer/runAnalyzer.ts
//
// Responsible for:
// - locating workspace / findings path
// - executing the Dart analyzer.exe
// - parsing JSON findings from stdout
// - creating diagnostics for the current document
// - updating findings.json via findingsStore
// - resetting LLM hover state for this document

import * as vscode from "vscode";
import { execFile } from "child_process";
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

/**
 * Return workspace folder for a document.
 * If none is directly associated, fallback to the first workspace folder.
 */
export function findWorkspaceFolderForDoc(
  doc: vscode.TextDocument
): vscode.WorkspaceFolder | undefined {
  return (
    vscode.workspace.getWorkspaceFolder(doc.uri) ??
    vscode.workspace.workspaceFolders?.[0]
  );
}

/**
 * Compute findings.json path for a given workspace folder.
 * Matches your earlier behavior: <root>/dart-analyzer/.out/findings.json
 */
export function findingsPathForFolder(
  folder: vscode.WorkspaceFolder
): string {
  return path.join(folder.uri.fsPath, "dart-analyzer", ".out", "findings.json");
}

/**
 * Run the external Dart analyzer.exe against a document.
 * This function is called by extension.ts on:
 * - manual scan
 * - save
 * - debounced typing
 */
export async function runAnalyzer(
  doc: vscode.TextDocument,
  _context: vscode.ExtensionContext
) {
  // Clear LLM queue / state and feedback cache for this document.
  resetLLMState();
  clearFeedbackForDocument(doc.uri);

  const folder = findWorkspaceFolderForDoc(doc);
  if (!folder) {
    vscode.window.showErrorMessage(
      "No workspace folder found for this document."
    );
    return;
  }

  const findingsFile = findingsPathForFolder(folder);

  // analyzer.exe is under <extension>/dart-analyzer/bin/analyzer.exe
  const analyzerPath = path.join(
    __dirname,
    "..",
    "dart-analyzer",
    "bin",
    "analyzer.exe"
  );

  if (!fs.existsSync(analyzerPath)) {
    vscode.window.showErrorMessage(
      `Analyzer not found at path: ${analyzerPath}`
    );
    return;
  }

  // Execute analyzer.exe with the current file path.
  execFile(
    analyzerPath,
    [doc.fileName],
    { shell: true },
    (err, stdout, stderr) => {
      if (err) {
        console.error("Analyzer execution error:", err);
        return;
      }
      if (stderr) {
        console.error("Analyzer stderr:", stderr);
      }

      let findings: any[] = [];
      try {
        findings = JSON.parse(stdout);
      } catch (e) {
        console.error("Failed to parse analyzer output:", e);
        return;
      }

      // Build diagnostics for this document (in-memory view).
      const diags: vscode.Diagnostic[] = [];

      for (const f of findings) {
        const lineIdx = Math.max(0, f.line - 1);
        const text = doc.lineAt(lineIdx).text;
        const range = new vscode.Range(lineIdx, 0, lineIdx, text.length);

        const cx =
          typeof f.complexity === "number"
            ? ` (Complexity: ${f.complexity})`
            : "";
        const message = `${f.message}${cx}`;

        const diag = new vscode.Diagnostic(
          range,
          message,
          severityToVS(f.severity || "warning")
        );

        diag.source = "flusec";
        diag.code = f.ruleId;

        diags.push(diag);

        // NOTE: you previously had commented-out LLM prefetch here.
        // If you want to pre-queue LLM requests, you can re-add it via
        // exported helpers from hoverLLM.ts.
      }

      // Set diagnostics for THIS document.
      diagCollection.set(doc.uri, diags);

      // Merge into findings.json + refresh global diagnostics.
      upsertFindingsForDoc(findingsFile, doc, findings);
    }
  );
}
