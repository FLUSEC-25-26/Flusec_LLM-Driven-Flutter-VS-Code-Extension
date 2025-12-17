// src/shared/diagnostics.ts
//
// Diagnostics = red/yellow squiggly lines in editor + Problems panel.
//
// Your extension sets diagnostics using the findings.json data.
// Any hover provider can later read those diagnostics and show LLM feedback.
//
// ✅ Why keep this shared?
// - All components produce the same "Finding" shape.
// - So they all get diagnostics “for free”.

import * as vscode from "vscode";
import { Finding } from "./types";

const diagCollection = vscode.languages.createDiagnosticCollection("flusec");

function severityToVS(sev: string): vscode.DiagnosticSeverity {
  return sev?.toLowerCase() === "error"
    ? vscode.DiagnosticSeverity.Error
    : vscode.DiagnosticSeverity.Warning;
}

export function applyDiagnostics(findings: Finding[]) {
  const map = new Map<string, vscode.Diagnostic[]>();

  for (const f of findings) {
    const file = String(f.file || "");
    if (!file) continue;

    const line = Math.max(0, (f.line ?? 1) - 1);
    const col = Math.max(0, (f.column ?? 1) - 1);

    // We highlight from column to a short range.
    // If you later store endColumn/snippet, you can expand.
    const endCol = col + 1;

    const cx = typeof f.complexity === "number" ? ` (Cx: ${f.complexity})` : "";
    const msg = `[${f.ruleId}] ${f.message || ""}${cx}`;

    const d = new vscode.Diagnostic(
      new vscode.Range(line, col, line, endCol),
      msg,
      severityToVS(f.severity || "warning")
    );

    d.source = "flusec";
    d.code = f.ruleId;

    const list = map.get(file) ?? [];
    list.push(d);
    map.set(file, list);
  }

  diagCollection.clear();
  for (const [fsPath, diags] of map) {
    diagCollection.set(vscode.Uri.file(fsPath), diags);
  }
}

export function clearDiagnostics() {
  diagCollection.clear();
}

export function disposeDiagnostics() {
  diagCollection.clear();
  diagCollection.dispose();
}
