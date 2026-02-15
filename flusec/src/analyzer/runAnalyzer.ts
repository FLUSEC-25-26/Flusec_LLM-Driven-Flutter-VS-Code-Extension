// src/analyzer/runAnalyzer.ts
//
// Responsible for:
// - locating workspace / findings path
// - executing the Dart analyzer.exe
// - parsing JSON findings from stdout
// - creating diagnostics for the current document
// - updating hsd_findings.json & net_findings.json via findingsStore
// - resetting LLM hover state for this document
// - sync rulepack + write effective workspace rule files (HSD + NET)

import * as vscode from "vscode";
import { spawn } from "child_process";
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

// HSD rulepack sync + workspace effective rule generation
import {
  syncHsdRulePack,
  writeHsdWorkspaceData,
} from "../rules/hsdRulePack.js";

// NET rulepack sync + workspace effective rule generation
import {
  syncNetRulePack,
  writeNetWorkspaceData,
} from "../rules/netRulePack.js";

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
 * Compute the .out directory for a given workspace folder.
 * <root>/.flusec/.out/
 */
export function findingsOutDir(folder: vscode.WorkspaceFolder): string {
  return path.join(folder.uri.fsPath, ".flusec", ".out");
}

/**
 * HSD component findings path.
 * <root>/.flusec/.out/hsd_findings.json
 */
export function hsdFindingsPathForFolder(
  folder: vscode.WorkspaceFolder
): string {
  return path.join(findingsOutDir(folder), "hsd_findings.json");
}

/**
 * NET component findings path.
 * <root>/.flusec/.out/net_findings.json
 */
export function netFindingsPathForFolder(
  folder: vscode.WorkspaceFolder
): string {
  return path.join(findingsOutDir(folder), "net_findings.json");
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
 * - hsd_findings.json & net_findings.json updated
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

  // Sync rulepacks + write effective workspace rule files for ALL components
  // Safe if offline: it just keeps cached/globalStorage values
  await syncHsdRulePack(context).catch((e) => {
    console.error("[FLUSEC] syncHsdRulePack (scan) failed:", e);
  });
  writeHsdWorkspaceData(context, folder.uri.fsPath);

  // NET rulepack sync
  await syncNetRulePack(context).catch((e) => {
    console.error("[FLUSEC] syncNetRulePack (scan) failed:", e);
  });
  writeNetWorkspaceData(context, folder.uri.fsPath);

  // Future: syncIdsRulePack, writeIdsWorkspaceData, etc.

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

  // Set cwd = <workspace>/.flusec
  // so the Dart resolver loads: <cwd>/data/<component>_rules.json
  const analyzerCwd = path.join(folder.uri.fsPath, ".flusec");

  // Ensure output folder exists
  const outDir = findingsOutDir(folder);
  fs.mkdirSync(outDir, { recursive: true });

  // Spawn the analyzer directly (no shell needed — more reliable on Windows)
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
    if (typeof f.complexity === "number") {
      metricParts.push(`Cx=${f.complexity}`);
    }
    if (typeof f.nestingDepth === "number") {
      metricParts.push(`Depth=${f.nestingDepth}`);
    }
    if (typeof f.functionLoc === "number") {
      metricParts.push(`Size=${f.functionLoc} LOC`);
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

  // Update diagnostics
  diagCollection.set(doc.uri, diags);

  // Split findings by component and write to separate files
  const hsdFindings = findings.filter((f: any) => f.component === "hsd");
  const netFindings = findings.filter((f: any) => f.component === "net");

  const hsdPath = hsdFindingsPathForFolder(folder);
  const netPath = netFindingsPathForFolder(folder);

  upsertFindingsForDoc(hsdPath, doc, hsdFindings);
  upsertFindingsForDoc(netPath, doc, netFindings);
}