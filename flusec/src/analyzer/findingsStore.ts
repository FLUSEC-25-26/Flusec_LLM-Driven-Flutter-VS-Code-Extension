// src/analyzer/findingsStore.ts
//
// Central storage and diagnostic helpers for FLUSEC findings.

import * as vscode from "vscode";
import * as fs from "fs";
import * as path from "path";
import type { AnalyzerFinding } from "./findingTypes";

function ensureDirForFile(filePath: string): void {
  const dir = path.dirname(filePath);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }
}

export const diagCollection =
  vscode.languages.createDiagnosticCollection("flusec");

export function severityToVS(severity: string): vscode.DiagnosticSeverity {
  switch (severity?.toLowerCase()) {
    case "error":
      return vscode.DiagnosticSeverity.Error;
    case "information":
    case "info":
      return vscode.DiagnosticSeverity.Information;
    case "hint":
      return vscode.DiagnosticSeverity.Hint;
    case "warning":
    default:
      return vscode.DiagnosticSeverity.Warning;
  }
}

function findingContextSuffix(finding: AnalyzerFinding): string {
  const parts: string[] = [];

  if (finding.securitySeverity) {
    parts.push(`Security=${String(finding.securitySeverity).toUpperCase()}`);
  }
  if (finding.confidence) {
    parts.push(`Confidence=${String(finding.confidence).toUpperCase()}`);
  }
  if (typeof finding.complexity === "number") {
    parts.push(`Cx=${finding.complexity}`);
  }
  if (typeof finding.nestingDepth === "number") {
    parts.push(`Depth=${finding.nestingDepth}`);
  }
  if (typeof finding.functionLoc === "number") {
    parts.push(`Size=${finding.functionLoc} LOC`);
  }
  if (typeof finding.maintainabilityScore === "number") {
    parts.push(`MCS=${finding.maintainabilityScore}/100`);
  }

  return parts.length > 0 ? ` [${parts.join(", ")}]` : "";
}

export function refreshDiagnosticsFromFindings(filePath: string): void {
  if (!fs.existsSync(filePath)) {
    diagCollection.clear();
    return;
  }

  let raw: AnalyzerFinding[] = [];
  try {
    const parsed = JSON.parse(fs.readFileSync(filePath, "utf8"));
    raw = Array.isArray(parsed) ? parsed : [];
  } catch (error) {
    console.error("Failed to parse findings JSON:", error);
    return;
  }

  const map = new Map<string, vscode.Diagnostic[]>();

  for (const finding of raw) {
    const sourceFile = String(finding.file || "");
    if (!sourceFile) {continue;}

    const line = Math.max(0, (finding.line ?? 1) - 1);
    const column = Math.max(0, (finding.column ?? 1) - 1);
    const endColumn = column + 80;

    const diagnostic = new vscode.Diagnostic(
      new vscode.Range(line, column, line, endColumn),
      `[${finding.ruleId}] ${finding.message}${findingContextSuffix(finding)}`,
      severityToVS(finding.severity || "warning")
    );

    diagnostic.source = "flusec";
    diagnostic.code = finding.ruleId;

    const list = map.get(sourceFile) ?? [];
    list.push(diagnostic);
    map.set(sourceFile, list);
  }

  diagCollection.clear();
  for (const [sourceFile, diagnostics] of map) {
    diagCollection.set(vscode.Uri.file(sourceFile), diagnostics);
  }
}

function storedFinding(
  finding: AnalyzerFinding,
  sourceFile: string,
  endColumn?: number
): Record<string, unknown> {
  return {
    file: finding.file ?? sourceFile,
    line: finding.line ?? 1,
    column: finding.column ?? 1,
    endColumn: endColumn ?? null,
    ruleId: finding.ruleId ?? "",
    message: finding.message ?? "",
    severity: finding.severity ?? "warning",
    securitySeverity: finding.securitySeverity ?? null,
    confidence: finding.confidence ?? null,
    category: finding.category ?? null,
    remediation: finding.remediation ?? null,
    cwe: finding.cwe ?? null,
    evidence: finding.evidence ?? null,
    functionName: finding.functionName ?? null,
    complexity: finding.complexity ?? null,
    nestingDepth: finding.nestingDepth ?? null,
    functionLoc: finding.functionLoc ?? null,
    maintainabilityScore: finding.maintainabilityScore ?? null,
    maintainabilityLevel: finding.maintainabilityLevel ?? null,
    secretType: finding.secretType ?? null,
    taintFlow: finding.taintFlow ?? null,
    component: finding.component ?? "hsd",
    riskLevel: finding.riskLevel ?? null,
    dataType: finding.dataType ?? null,
    storageContext: finding.storageContext ?? null,
  };
}

function readExistingFindings(findingsFilePath: string): any[] {
  if (!fs.existsSync(findingsFilePath)) {return [];}

  try {
    const parsed = JSON.parse(fs.readFileSync(findingsFilePath, "utf8"));
    return Array.isArray(parsed) ? parsed : [];
  } catch {
    return [];
  }
}

export function upsertFindingsForDoc(
  findingsFilePath: string,
  document: vscode.TextDocument,
  newFindings: AnalyzerFinding[]
): void {
  ensureDirForFile(findingsFilePath);

  const sourceFile = document.fileName;
  const retained = readExistingFindings(findingsFilePath).filter(
    (finding) => finding?.file !== sourceFile
  );

  for (const finding of newFindings) {
    const lineIndex = Math.max(0, finding.line - 1);
    let endColumn = 1;
    try {
      endColumn = document.lineAt(lineIndex).text.length;
    } catch {
      endColumn = Math.max(1, finding.column ?? 1);
    }

    retained.push(storedFinding(finding, sourceFile, endColumn));
  }

  fs.writeFileSync(
    findingsFilePath,
    JSON.stringify(retained, null, 2),
    "utf8"
  );
}

export function upsertFindingsForFile(
  findingsFilePath: string,
  sourceFilePath: string,
  newFindings: AnalyzerFinding[]
): void {
  ensureDirForFile(findingsFilePath);

  const retained = readExistingFindings(findingsFilePath).filter(
    (finding) => finding?.file !== sourceFilePath
  );

  for (const finding of newFindings) {
    retained.push(storedFinding(finding, sourceFilePath));
  }

  fs.writeFileSync(
    findingsFilePath,
    JSON.stringify(retained, null, 2),
    "utf8"
  );
}
