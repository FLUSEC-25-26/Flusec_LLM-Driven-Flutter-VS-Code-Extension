// src/analyzer/runAnalyzer.ts
//
// Responsible for:
// - locating workspace / findings path
// - executing the Dart analyzer.exe
// - parsing JSON findings from stdout
// - creating diagnostics for the current document
// - updating hsd_findings.json, net_findings.json, ids_findings.json & iiv_findings.json via findingsStore
// - resetting LLM hover state for this document
// - sync rulepack + write effective workspace rule files (HSD + NET + IDS + IIV)
// - PROJECT SCAN: scan all .dart files in lib/ in a single analyzer process

import * as vscode from "vscode";
import { spawn } from "child_process";
import * as path from "path";
import * as fs from "fs";

import {
  diagCollection,
  severityToVS,
  upsertFindingsForDoc,
  upsertFindingsForFile,
} from "./findingsStore.js";

import {
  resetLLMState,
  clearFeedbackForDocument,
} from "../diagnostics/hoverllm.js";

import { syncPoliciesForWorkspace } from "../policies/policySync.js";

/**
 * Return workspace folder for a document.
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
 * Compute the .out directory for a given workspace folder.
 */
export function findingsOutDir(folder: vscode.WorkspaceFolder): string {
  return path.join(folder.uri.fsPath, ".flusec", ".out");
}

/**
 * HSD component findings path.
 */
export function hsdFindingsPathForFolder(
  folder: vscode.WorkspaceFolder
): string {
  return path.join(findingsOutDir(folder), "hsd_findings.json");
}

/**
 * NET component findings path.
 */
export function netFindingsPathForFolder(
  folder: vscode.WorkspaceFolder
): string {
  return path.join(findingsOutDir(folder), "net_findings.json");
}

/**
 * IDS component findings path.
 */
export function idsFindingsPathForFolder(
  folder: vscode.WorkspaceFolder
): string {
  return path.join(findingsOutDir(folder), "ids_findings.json");
}

/**
 * IIV component findings path.
 */
export function iivFindingsPathForFolder(
  folder: vscode.WorkspaceFolder
): string {
  return path.join(findingsOutDir(folder), "iiv_findings.json");
}

/**
 * Resolve the path to the analyzer executable.
 */
function resolveAnalyzerPath(): string {
  return path.join(__dirname, "..", "dart-analyzer", "bin", "analyzer.exe");
}

/**
 * Sync all rulepacks and write workspace data for a given folder.
 */
async function syncAndWriteAllRules(
  context: vscode.ExtensionContext,
  folderFsPath: string
): Promise<void> {
  await syncPoliciesForWorkspace(context, folderFsPath, {
    allowCachedFallback: true,
    silent: false,
  });
}

/**
 * Run the external Dart analyzer.exe against a document.
 */
export async function runAnalyzer(
  doc: vscode.TextDocument,
  context: vscode.ExtensionContext
): Promise<void> {
  resetLLMState();
  clearFeedbackForDocument(doc.uri);

  const folder = findWorkspaceFolderForDoc(doc);
  if (!folder) {
    vscode.window.showErrorMessage(
      "No workspace folder found for this document."
    );
    return;
  }

  await syncAndWriteAllRules(context, folder.uri.fsPath);

  const analyzerPath = resolveAnalyzerPath();

  if (!fs.existsSync(analyzerPath)) {
    vscode.window.showErrorMessage(
      `Analyzer not found at path: ${analyzerPath}`
    );
    return;
  }

  const analyzerCwd = path.join(folder.uri.fsPath, ".flusec");
  const outDir = findingsOutDir(folder);
  fs.mkdirSync(outDir, { recursive: true });

  const stdout = await new Promise<string>((resolve, reject) => {
    const proc = spawn(analyzerPath, [doc.fileName], {
      cwd: analyzerCwd,
      stdio: ["ignore", "pipe", "pipe"],
    });

    let out = "";
    let err = "";
    proc.stdout.on("data", (d: Buffer) => { out += d.toString(); });
    proc.stderr.on("data", (d: Buffer) => { err += d.toString(); });

    proc.on("error", (e) => {
      console.error("Analyzer spawn error:", e);
      vscode.window.showErrorMessage(
        "FLUSEC analyzer failed. See console for details."
      );
      reject(e);
    });

    proc.on("close", (code) => {
      if (err) {
        console.error("Analyzer stderr:", err);
      }
      if (code !== 0) {
        vscode.window.showErrorMessage(
          "FLUSEC analyzer failed. See console for details."
        );
        reject(new Error(`Analyzer exited with code ${code}`));
      } else {
        resolve(out);
      }
    });
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

  // Build diagnostics for this document
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
    if (f.securitySeverity) {
      metricParts.push(`Security=${String(f.securitySeverity).toUpperCase()}`);
    }
    if (f.confidence) {
      metricParts.push(`Confidence=${String(f.confidence).toUpperCase()}`);
    }
    if (typeof f.complexity === "number") {
      metricParts.push(`Cx=${f.complexity}`);
    }
    if (typeof f.nestingDepth === "number") {
      metricParts.push(`Depth=${f.nestingDepth}`);
    }
    if (typeof f.functionLoc === "number") {
      metricParts.push(`Size=${f.functionLoc} LOC`);
    }
    if (typeof f.maintainabilityScore === "number") {
      metricParts.push(`MCS=${f.maintainabilityScore}/100`);
    }

    const metricSuffix = metricParts.length
      ? ` [${metricParts.join(", ")}]`
      : "";
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

  diagCollection.set(doc.uri, diags);

  // Split findings by component and write to separate files
  const hsdFindings = findings.filter((f: any) => (f.component ?? "hsd") === "hsd");
  const netFindings = findings.filter((f: any) => f.component === "net");
  const idsFindings = findings.filter((f: any) => f.component === "ids");
  const iivFindings = findings.filter((f: any) => f.component === "iiv");

  const hsdPath = hsdFindingsPathForFolder(folder);
  const netPath = netFindingsPathForFolder(folder);
  const idsPath = idsFindingsPathForFolder(folder);
  const iivPath = iivFindingsPathForFolder(folder);

  upsertFindingsForDoc(hsdPath, doc, hsdFindings);
  upsertFindingsForDoc(netPath, doc, netFindings);
  upsertFindingsForDoc(idsPath, doc, idsFindings);
  upsertFindingsForDoc(iivPath, doc, iivFindings);
}


// ==========================================================================
// PROJECT SCAN
// ==========================================================================

export interface ProjectScanResult {
  totalFiles: number;
  filesWithIssues: number;
  totalIssues: number;
  hsdCount: number;
  netCount: number;
  idsCount: number;
  iivCount: number;
}

export async function runProjectAnalyzer(
  context: vscode.ExtensionContext,
  folder: vscode.WorkspaceFolder,
  scanDir?: string
): Promise<ProjectScanResult> {
  resetLLMState();

  await syncAndWriteAllRules(context, folder.uri.fsPath);

  const analyzerPath = resolveAnalyzerPath();

  if (!fs.existsSync(analyzerPath)) {
    throw new Error(`Analyzer not found at path: ${analyzerPath}`);
  }

  const targetDir = scanDir ?? path.join(folder.uri.fsPath, "lib");

  if (!fs.existsSync(targetDir)) {
    throw new Error(`Scan directory not found: ${targetDir}`);
  }

  const analyzerCwd = path.join(folder.uri.fsPath, ".flusec");
  const outDir = findingsOutDir(folder);
  fs.mkdirSync(outDir, { recursive: true });

  const stdout = await new Promise<string>((resolve, reject) => {
    const proc = spawn(analyzerPath, ["--project", targetDir], {
      cwd: analyzerCwd,
      stdio: ["ignore", "pipe", "pipe"],
    });

    let out = "";
    let err = "";
    proc.stdout.on("data", (d: Buffer) => { out += d.toString(); });
    proc.stderr.on("data", (d: Buffer) => { err += d.toString(); });

    proc.on("error", (e) => {
      console.error("Analyzer spawn error (project scan):", e);
      reject(e);
    });

    proc.on("close", (code) => {
      if (err) {
        console.error("Analyzer stderr (project scan):", err);
      }
      if (code !== 0) {
        reject(new Error(`Analyzer exited with code ${code}`));
      } else {
        resolve(out);
      }
    });
  });

  let findings: any[] = [];
  try {
    findings = JSON.parse(stdout);
    if (!Array.isArray(findings)) {
      findings = [];
    }
  } catch (e) {
    console.error("Failed to parse project scan output:", e);
    throw new Error("Failed to parse analyzer output as JSON");
  }

  // Group findings by file for diagnostics
  const findingsByFile = new Map<string, any[]>();
  for (const f of findings) {
    const filePath = f.file ?? "";
    if (!filePath) { continue; }
    const existing = findingsByFile.get(filePath) ?? [];
    existing.push(f);
    findingsByFile.set(filePath, existing);
  }

  // Set diagnostics for each file
  for (const [filePath, fileFindings] of findingsByFile) {
    const uri = vscode.Uri.file(filePath);
    const diags: vscode.Diagnostic[] = [];

    for (const f of fileFindings) {
      const lineIdx = Math.max(0, (f.line ?? 1) - 1);
      const range = new vscode.Range(lineIdx, 0, lineIdx, 200);

      const metricParts: string[] = [];
      if (f.securitySeverity) {
        metricParts.push(`Security=${String(f.securitySeverity).toUpperCase()}`);
      }
      if (f.confidence) {
        metricParts.push(`Confidence=${String(f.confidence).toUpperCase()}`);
      }
      if (typeof f.complexity === "number") {
        metricParts.push(`Cx=${f.complexity}`);
      }
      if (typeof f.nestingDepth === "number") {
        metricParts.push(`Depth=${f.nestingDepth}`);
      }
      if (typeof f.functionLoc === "number") {
        metricParts.push(`Size=${f.functionLoc} LOC`);
      }
      if (typeof f.maintainabilityScore === "number") {
        metricParts.push(`MCS=${f.maintainabilityScore}/100`);
      }

      const metricSuffix = metricParts.length
        ? ` [${metricParts.join(", ")}]`
        : "";
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

    diagCollection.set(uri, diags);
  }

  // Split findings by component
  const hsdFindings = findings.filter((f: any) => (f.component ?? "hsd") === "hsd");
  const netFindings = findings.filter((f: any) => f.component === "net");
  const idsFindings = findings.filter((f: any) => f.component === "ids");
  const iivFindings = findings.filter((f: any) => f.component === "iiv");

  const hsdPath = hsdFindingsPathForFolder(folder);
  const netPath = netFindingsPathForFolder(folder);
  const idsPath = idsFindingsPathForFolder(folder);
  const iivPath = iivFindingsPathForFolder(folder);

  writeFindingsFile(hsdPath, hsdFindings);
  writeFindingsFile(netPath, netFindings);
  writeFindingsFile(idsPath, idsFindings);
  writeFindingsFile(iivPath, iivFindings);

  const filesWithIssues = findingsByFile.size;

  return {
    totalFiles: countDartFiles(targetDir),
    filesWithIssues,
    totalIssues: findings.length,
    hsdCount: hsdFindings.length,
    netCount: netFindings.length,
    idsCount: idsFindings.length,
    iivCount: iivFindings.length,
  };
}

function writeFindingsFile(filePath: string, findings: any[]): void {
  const dir = path.dirname(filePath);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }

  const enriched = findings.map((f: any) => ({
    file: f.file ?? "",
    line: f.line ?? 1,
    column: f.column ?? 1,
    ruleId: f.ruleId ?? "",
    message: f.message ?? "",
    severity: f.severity ?? "warning",
    securitySeverity: f.securitySeverity ?? null,
    confidence: f.confidence ?? null,
    category: f.category ?? null,
    remediation: f.remediation ?? null,
    cwe: f.cwe ?? null,
    evidence: f.evidence ?? null,
    functionName: f.functionName ?? null,
    complexity: f.complexity ?? null,
    nestingDepth: f.nestingDepth ?? null,
    functionLoc: f.functionLoc ?? null,
    maintainabilityScore: f.maintainabilityScore ?? null,
    maintainabilityLevel: f.maintainabilityLevel ?? null,
    secretType: f.secretType ?? null,
    taintFlow: f.taintFlow ?? null,
    component: f.component ?? "hsd",
    riskLevel: f.riskLevel ?? null,
    dataType: f.dataType ?? null,
    storageContext: f.storageContext ?? null,
  }));

  fs.writeFileSync(filePath, JSON.stringify(enriched, null, 2), "utf8");
}

function countDartFiles(dirPath: string): number {
  let count = 0;
  try {
    const entries = fs.readdirSync(dirPath, { withFileTypes: true });
    for (const entry of entries) {
      const fullPath = path.join(dirPath, entry.name);
      if (entry.isDirectory()) {
        if (
          entry.name === ".dart_tool" ||
          entry.name === "build" ||
          entry.name === ".flusec" ||
          entry.name === "generated"
        ) {
          continue;
        }
        count += countDartFiles(fullPath);
      } else if (entry.name.endsWith(".dart")) {
        count++;
      }
    }
  } catch {
    // ignore
  }
  return count;
}