// src/analyzer/findingsStore.ts
//
// Central place for:
// - VS Code diagnostic collection
// - mapping severity strings to VS severity
// - storing / merging findings.json
// - refreshing diagnostics from findings.json

import * as vscode from "vscode";
import * as fs from "fs";
import * as path from "path";



/** * Ensure the directory for a given file path exists.
 */
function ensureDirForFile(filePath: string) {
  const dir = path.dirname(filePath);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
}

// Shared diagnostics collection for the whole extension.
export const diagCollection = vscode.languages.createDiagnosticCollection("flusec");

export function severityToVS(sev: string): vscode.DiagnosticSeverity {
  // Map custom severity string ("error" / "warning" / anything else)
  // to VS Code's DiagnosticSeverity enum.
  return sev?.toLowerCase() === "error"
    ? vscode.DiagnosticSeverity.Error
    : vscode.DiagnosticSeverity.Warning;
}

/**
 * Read findings.json from the given path and update all diagnostics.
 */
export function refreshDiagnosticsFromFindings(fp: string) {
  if (!fs.existsSync(fp)) {
    // If no findings file, clear all diagnostics.
    diagCollection.clear();
    return;
  }

  let raw: any[] = [];
  try {
    raw = JSON.parse(fs.readFileSync(fp, "utf8"));
  } catch (e) {
    console.error("Failed to parse findings.json:", e);
    return;
  }

    const map = new Map<string, vscode.Diagnostic[]>();
  for (const f of raw) {
    const file = String(f.file || "");
    if (!file) { continue; }

    const line = Math.max(0, (f.line ?? 1) - 1);
    const col = Math.max(0, (f.column ?? 1) - 1);
    const endCol = col + Math.max(1, (f.snippet?.length ?? 80));

    // 🔹 numeric metrics again
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

    const diag = new vscode.Diagnostic(
      new vscode.Range(line, col, line, endCol),
      `[${f.ruleId}] ${f.message || ""}${metricSuffix}`,
      severityToVS(f.severity || "warning")
    );

    diag.source = "flusec";
    diag.code = f.ruleId;

    const list = map.get(file) ?? [];
    list.push(diag);
    map.set(file, list);
  }


  // Clear all and re-set per file.
  diagCollection.clear();
  for (const [fsPath, diags] of map) {
    diagCollection.set(vscode.Uri.file(fsPath), diags);
  }
}

/**
 * Merge new findings for a single document into findings.json,
 * then refresh diagnostics.
 */
export function upsertFindingsForDoc(
  findingsFilePath: string,
  doc: vscode.TextDocument,
  newFindings: Array<{
    ruleId: string;
    severity: string;
    message: string;
    line: number;
    column: number;
    functionName?: string;
    complexity?: number;
    nestingDepth?: number;   // 🔹 NEW
    functionLoc?: number;    // 🔹 NEW
  }>
){
  ensureDirForFile(findingsFilePath);
  let all: any[] = [];
  if (fs.existsSync(findingsFilePath)) {
    try {
      all = JSON.parse(fs.readFileSync(findingsFilePath, "utf8"));
      if (!Array.isArray(all)) { all = []; }
    } catch {
      all = [];
    }
  }

  const filePath = doc.fileName;
  // remove old findings for this file
  all = all.filter((x) => x?.file !== filePath);

  for (const f of newFindings) {
    const lineIdx = Math.max(0, f.line - 1);
    const lineText = doc.lineAt(lineIdx).text;
    all.push({
      file: filePath,
      line: f.line,
      column: f.column,
      endColumn: lineText.length,
      ruleId: f.ruleId,
      message: f.message,
      severity: f.severity || "warning",
      functionName: (f as any).functionName,
      complexity: (f as any).complexity,
      // 🔹 store numeric metrics in findings.json
      nestingDepth: (f as any).nestingDepth,
      functionLoc: (f as any).functionLoc,
    });
  }

  fs.writeFileSync(findingsFilePath, JSON.stringify(all, null, 2), "utf8");
  refreshDiagnosticsFromFindings(findingsFilePath);
}

