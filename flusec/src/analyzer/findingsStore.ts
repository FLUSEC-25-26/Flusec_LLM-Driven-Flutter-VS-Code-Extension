// src/analyzer/findingsStore.ts
//
// Central storage, normalization, fingerprint fallback, and diagnostic helpers
// for FLUSEC findings.

import * as vscode from "vscode";
import * as fs from "fs";
import * as path from "path";
import { createHash } from "crypto";
import type {
  AnalyzerFinding,
  FlusecComponent,
} from "./findingTypes.js";

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
    const endColumn = Math.max(column + 1, finding.endColumn ?? column + 80);

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

function normalizedComponent(value: unknown): FlusecComponent {
  const raw = String(value ?? "hsd").trim().toLowerCase();
  if (raw === "net" || raw === "ids" || raw === "iiv") {return raw;}
  return "hsd";
}

function normalizedPathForIdentity(filePath: string): string {
  const normalized = path.resolve(filePath).replace(/\\/g, "/");
  return process.platform === "win32" ? normalized.toLowerCase() : normalized;
}

function fallbackFingerprint(
  finding: AnalyzerFinding,
  sourceFile: string,
  component: FlusecComponent
): string {
  const identity = [
    component,
    finding.ruleId ?? "",
    normalizedPathForIdentity(finding.file ?? sourceFile),
    finding.functionName ?? "",
    finding.line ?? 1,
    finding.column ?? 1,
  ].join("|");

  return createHash("sha256").update(identity, "utf8").digest("hex");
}

function putIfPresent(
  target: Record<string, unknown>,
  key: string,
  value: unknown
): void {
  if (value !== null && value !== undefined) {
    target[key] = value;
  }
}

/**
 * Convert analyzer output into the one local storage contract used by both
 * single-file and project scans.
 *
 * Current FLUSEC security diagnostics are normalized to VS Code Warning.
 * Security impact remains independent in securitySeverity.
 */
export function normalizeFindingForStorage(
  finding: AnalyzerFinding,
  sourceFile: string,
  endColumn?: number
): Record<string, unknown> {
  const component = normalizedComponent(finding.component);
  const file = finding.file ?? sourceFile;
  const stored: Record<string, unknown> = {
    file,
    line: finding.line ?? 1,
    column: finding.column ?? 1,
    ruleId: finding.ruleId ?? "",
    message: finding.message ?? "",
    severity: "warning",
    component,
    fingerprint:
      finding.fingerprint ?? fallbackFingerprint(finding, sourceFile, component),
  };

  if (typeof endColumn === "number") {
    stored.endColumn = endColumn;
  }

  putIfPresent(stored, "securitySeverity", finding.securitySeverity);
  putIfPresent(stored, "confidence", finding.confidence);
  putIfPresent(stored, "category", finding.category);
  putIfPresent(stored, "remediation", finding.remediation);
  putIfPresent(stored, "cwe", finding.cwe);
  putIfPresent(stored, "evidence", finding.evidence);

  putIfPresent(stored, "functionName", finding.functionName);
  putIfPresent(stored, "complexity", finding.complexity);
  putIfPresent(stored, "nestingDepth", finding.nestingDepth);
  putIfPresent(stored, "functionLoc", finding.functionLoc);
  putIfPresent(stored, "maintainabilityScore", finding.maintainabilityScore);
  putIfPresent(stored, "maintainabilityLevel", finding.maintainabilityLevel);

  if (component === "hsd") {
    putIfPresent(stored, "secretType", finding.secretType);
    putIfPresent(stored, "taintFlow", finding.taintFlow);
  }

  if (component === "ids") {
    putIfPresent(stored, "dataType", finding.dataType);
    putIfPresent(stored, "storageContext", finding.storageContext);
  }

  return stored;
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

function sameFile(left: unknown, right: string): boolean {
  if (typeof left !== "string" || !left.trim()) {return false;}
  return normalizedPathForIdentity(left) === normalizedPathForIdentity(right);
}

export function upsertFindingsForDoc(
  findingsFilePath: string,
  document: vscode.TextDocument,
  newFindings: AnalyzerFinding[]
): void {
  ensureDirForFile(findingsFilePath);

  const sourceFile = document.fileName;
  const retained = readExistingFindings(findingsFilePath)
    .filter((finding) => !sameFile(finding?.file, sourceFile))
    .map((finding) =>
      normalizeFindingForStorage(
        finding as AnalyzerFinding,
        String(finding?.file ?? "")
      )
    );

  for (const finding of newFindings) {
    const lineIndex = Math.max(0, finding.line - 1);
    let endColumn = 1;
    try {
      endColumn = document.lineAt(lineIndex).text.length;
    } catch {
      endColumn = Math.max(1, finding.column ?? 1);
    }

    retained.push(
      normalizeFindingForStorage(finding, sourceFile, endColumn)
    );
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

  const retained = readExistingFindings(findingsFilePath)
    .filter((finding) => !sameFile(finding?.file, sourceFilePath))
    .map((finding) =>
      normalizeFindingForStorage(
        finding as AnalyzerFinding,
        String(finding?.file ?? "")
      )
    );

  for (const finding of newFindings) {
    retained.push(normalizeFindingForStorage(finding, sourceFilePath));
  }

  fs.writeFileSync(
    findingsFilePath,
    JSON.stringify(retained, null, 2),
    "utf8"
  );
}

/** Replace a component findings file after a full project scan. */
export function replaceFindingsFile(
  findingsFilePath: string,
  findings: AnalyzerFinding[]
): void {
  ensureDirForFile(findingsFilePath);

  const normalized = findings.map((finding) =>
    normalizeFindingForStorage(finding, finding.file ?? "")
  );

  fs.writeFileSync(
    findingsFilePath,
    JSON.stringify(normalized, null, 2),
    "utf8"
  );
}
