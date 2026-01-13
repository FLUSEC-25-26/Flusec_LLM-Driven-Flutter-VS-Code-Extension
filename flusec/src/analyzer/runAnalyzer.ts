// src/analyzer/runAnalyzer.ts
//
// Responsible for:
// - locating workspace / findings path
// - executing the Dart analyzer.exe
// - parsing JSON findings from stdout
// - creating diagnostics for the current document
// - updating findings.json via findingsStore
// - resetting LLM hover state for this document
// - (NEW) sync rulepack + write effective workspace rule files

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

// NEW: rule pack sync + workspace effective rule generation
import {
  syncHsdRulePack,
  writeHsdWorkspaceData,
} from "../rules/hsdRulePack.js";

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
 * Called by extension.ts on:
 * - manual scan
 * - save
 * - debounced typing
 *
 * IMPORTANT:
 * Resolves ONLY AFTER:
 * - analyzer.exe finished
 * - diagnostics updated
 * - findings.json updated
 */
export async function runAnalyzer(
  doc: vscode.TextDocument,
  context: vscode.ExtensionContext
): Promise<void> {
  // Clear LLM queue/state and feedback cache for this document.
  resetLLMState();
  clearFeedbackForDocument(doc.uri);

  const folder = findWorkspaceFolderForDoc(doc);
  if (!folder) {
    vscode.window.showErrorMessage(
      "No workspace folder found for this document."
    );
    return;
  }

  // NEW: sync rulepack + write effective workspace rule files
  // Safe if offline: it just keeps cached/globalStorage values
  await syncHsdRulePack(context).catch((e) => {
  console.error("[FLUSEC] syncHsdRulePack (scan) failed:", e);
  });
  writeHsdWorkspaceData(context, folder.uri.fsPath);

  const findingsFile = findingsPathForFolder(folder);

  // analyzer.exe is under <extension>/dart-analyzer/bin/analyzer.exe
  // (Keep your old __dirname approach)
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

  // IMPORTANT NEW: set cwd = <workspace>/dart-analyzer
  // so your Dart resolver loads: <cwd>/data/hardcoded_secrets_rules.json
  const analyzerCwd = path.join(folder.uri.fsPath, "dart-analyzer");

  // Ensure output folder exists (because upsertFindingsForDoc writes findings.json)
  fs.mkdirSync(path.dirname(findingsFile), { recursive: true });

  // Wrap execFile in a Promise and await it.
  const stdout = await new Promise<string>((resolve, reject) => {
    execFile(
      analyzerPath,
      [doc.fileName],
      { shell: true, cwd: analyzerCwd, maxBuffer: 10 * 1024 * 1024 },
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
    if (!Array.isArray(findings)) {findings = [];}
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
      range = new vscode.Range(lineIdx, 0, lineIdx, 0);
    }

    // numeric metric suffix: Cx, Depth, Size
    const metricParts: string[] = [];
    if (typeof f.complexity === "number") {metricParts.push(`Cx=${f.complexity}`);}
    if (typeof f.nestingDepth === "number") {metricParts.push(`Depth=${f.nestingDepth}`);}
    if (typeof f.functionLoc === "number") {metricParts.push(`Size=${f.functionLoc} LOC`);}

    const metricSuffix = metricParts.length ? ` [${metricParts.join(", ")}]` : "";
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

  // Update diagnostics and findings.json
  diagCollection.set(doc.uri, diags);
  upsertFindingsForDoc(findingsFile, doc, findings);
}
