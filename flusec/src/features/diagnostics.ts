// src/features/diagnostics.ts
import * as vscode from "vscode";
import * as fs from "fs";

const collection = vscode.languages.createDiagnosticCollection("flusec");

export function refreshDiagnostics(findingsPath: string) {
  if (!fs.existsSync(findingsPath)) {
    collection.clear();
    return;
  }
  let raw: any[] = [];
  try {
    raw = JSON.parse(fs.readFileSync(findingsPath, "utf8"));
  } catch {
    // ignore parse errors
  }

  const map = new Map<string, vscode.Diagnostic[]>();

  for (const f of raw) {
    const file = String(f.file || "");
    const line = Math.max(0, (f.line ?? 1) - 1);
    const col = Math.max(0, (f.column ?? 1) - 1);

    const range = new vscode.Range(line, col, line, col + 1);
    const sev = (f.severity === "error")
      ? vscode.DiagnosticSeverity.Error
      : vscode.DiagnosticSeverity.Warning;

    const msg = `[${f.ruleId}] ${f.message || ""}`;
    const d = new vscode.Diagnostic(range, msg, sev);
    d.source = "flusec";
    d.code = f.ruleId;

    const list = map.get(file) ?? [];
    list.push(d);
    map.set(file, list);
  }

  collection.clear();
  for (const [fsPath, diags] of map) {
    collection.set(vscode.Uri.file(fsPath), diags);
  }
}

export function disposeDiagnostics() {
  collection.clear();
  collection.dispose();
}
