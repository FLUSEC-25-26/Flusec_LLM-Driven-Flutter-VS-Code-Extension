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
 *
 * IMPORTANT:
 * We now return a Promise that resolves ONLY AFTER:
 * - analyzer.exe has finished
 * - findings.json has been updated via upsertFindingsForDoc
 *
 * This guarantees the dashboard can safely refresh immediately after
 * awaiting runAnalyzer / flusec.scanFile.
 */
export async function runAnalyzer(
  doc: vscode.TextDocument,
  _context: vscode.ExtensionContext
): Promise<void> {
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

  // Core fix: wrap execFile in a Promise and await it.
  const stdout = await new Promise<string>((resolve, reject) => {
    execFile(
      analyzerPath,
      [doc.fileName],
      { shell: true },
      (err, stdout, stderr) => {
        if (err) {
          console.error("Analyzer execution error:", err);
          vscode.window.showErrorMessage(
            "FLUSEC analyzer failed. See console for details."
          );
          return reject(err);
        }
        if (stderr) {
          // Not always fatal, but useful to log.
          console.error("Analyzer stderr:", stderr);
        }
        resolve(stdout);
      }
    );
  });

  let findings: any[] = [];
  try {
    findings = JSON.parse(stdout);
    if (!Array.isArray(findings)) {
      findings = [];
    }
  } catch (e) {
    console.error("Failed to parse analyzer output as JSON:", e);
    vscode.window.showErrorMessage(
      "FLUSEC: Failed to parse analyzer output. See console for details."
    );
    return;
  }

  // Build diagnostics for this document (in-memory view).
  const diags: vscode.Diagnostic[] = [];
  for (const f of findings) {
    const lineIdx = Math.max(0, (f.line ?? 1) - 1);

    let range: vscode.Range;
    try {
      const textLine = doc.lineAt(lineIdx);
      range = new vscode.Range(lineIdx, 0, lineIdx, textLine.text.length);
    } catch {
      // If line index is out of range, fall back to a safe zero-length range.
      range = new vscode.Range(lineIdx, 0, lineIdx, 0);
    }

    // 🔹 Build numeric metric suffix: Cx, Depth, Size
    const metricParts: string[] = [];
    if (typeof f.complexity === "number") {
      metricParts.push(`Cx=${f.complexity}`);
    }
    if (typeof f.nestingDepth === "number") {
      metricParts.push(`Depth=${f.nestingDepth}`);
    }
    if (typeof f.functionLoc === "number") {
      metricParts.push(`Size=${f.functionLoc} LOC`);
    }
    const metricSuffix =
      metricParts.length > 0 ? ` [${metricParts.join(", ")}]` : "";

    // f.message is already enriched in Dart:
    // e.g. "Hardcoded API key in function loginUser
    //       (Function complexity: high, nesting: medium, size: medium)"
    const message = `${f.message ?? ""}${metricSuffix}`;

    const diag = new vscode.Diagnostic(
      range,
      message,
      severityToVS(f.severity || "warning")
    );
    diag.source = "flusec";
    diag.code = f.ruleId;
    diags.push(diag);
  }

  // Update diagnostics and findings.json (synchronous write inside upsert)
  diagCollection.set(doc.uri, diags);
  upsertFindingsForDoc(findingsFile, doc, findings);
}
