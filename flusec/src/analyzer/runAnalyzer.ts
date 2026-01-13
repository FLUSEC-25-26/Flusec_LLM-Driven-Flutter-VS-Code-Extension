import * as vscode from "vscode";
import { execFile } from "child_process";
import * as path from "path";
import * as fs from "fs";

import { diagCollection, severityToVS, upsertFindingsForDoc } from "./findingsStore.js";

import { resetLLMState, clearFeedbackForDocument } from "../diagnostics/hoverllm.js";

// Workspace effective rule generation (no network here)
import { writeHsdWorkspaceData } from "../rules/hsdRulePack.js";

export function findWorkspaceFolderForDoc(
  doc: vscode.TextDocument
): vscode.WorkspaceFolder | undefined {
  return (
    vscode.workspace.getWorkspaceFolder(doc.uri) ??
    vscode.workspace.workspaceFolders?.[0]
  );
}

// NEW: .flusec location
export function findingsPathForFolder(folder: vscode.WorkspaceFolder): string {
  return path.join(folder.uri.fsPath, ".flusec", ".out", "findings.json");
}

export async function runAnalyzer(
  doc: vscode.TextDocument,
  context: vscode.ExtensionContext
): Promise<void> {
  resetLLMState();
  clearFeedbackForDocument(doc.uri);

  const folder = findWorkspaceFolderForDoc(doc);
  if (!folder) {
    vscode.window.showErrorMessage("No workspace folder found for this document.");
    return;
  }

  // Ensure workspace effective rule files exist
  writeHsdWorkspaceData(context, folder.uri.fsPath);

  const findingsFile = findingsPathForFolder(folder);

  const analyzerPath = path.join(__dirname, "..", "dart-analyzer", "bin", "analyzer.exe");
  if (!fs.existsSync(analyzerPath)) {
    vscode.window.showErrorMessage(`Analyzer not found at path: ${analyzerPath}`);
    return;
  }

  // NEW: set cwd = <workspace>/.flusec so resolver reads <cwd>/data/*.json
  const analyzerCwd = path.join(folder.uri.fsPath, ".flusec");

  // Ensure output folder exists
  fs.mkdirSync(path.dirname(findingsFile), { recursive: true });

  const stdout = await new Promise<string>((resolve, reject) => {
    execFile(
      analyzerPath,
      [doc.fileName],
      { shell: true, cwd: analyzerCwd, maxBuffer: 10 * 1024 * 1024 },
      (err, stdout, stderr) => {
        if (err) {
          console.error("Analyzer execution error:", err);
          vscode.window.showErrorMessage("FLUSEC analyzer failed. See console for details.");
          return reject(err);
        }
        if (stderr) {
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

    const metricParts: string[] = [];
    if (typeof f.complexity === "number") {metricParts.push(`Cx=${f.complexity}`);}
    if (typeof f.nestingDepth === "number") {metricParts.push(`Depth=${f.nestingDepth}`);}
    if (typeof f.functionLoc === "number") {metricParts.push(`Size=${f.functionLoc} LOC`);}

    const metricSuffix = metricParts.length ? ` [${metricParts.join(", ")}]` : "";
    const message = `${f.message ?? ""}${metricSuffix}`;

    const diag = new vscode.Diagnostic(range, message, severityToVS(f.severity || "warning"));
    diag.source = "flusec";
    diag.code = f.ruleId;
    diags.push(diag);
  }

  diagCollection.set(doc.uri, diags);
  upsertFindingsForDoc(findingsFile, doc, findings);
}
