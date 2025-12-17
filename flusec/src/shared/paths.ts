// src/shared/paths.ts
//
// Central place for paths so you don't hardcode them across files.
//
// ✅ Key idea:
// - analyzer.exe lives inside the extension install folder
// - findings.json should live inside the USER WORKSPACE folder
// - analyzer should run with cwd = workspace/dart-analyzer so .out goes there
//
// This fixes your earlier bug:
// analyzer cwd was VS Code install folder,
// so it wrote ".out/findings.json" into VS Code program files.

import * as path from "path";
import * as vscode from "vscode";

export function analyzerExePath(context: vscode.ExtensionContext): string {
  // analyzer.exe packaged inside extension root
  return path.join(context.extensionUri.fsPath, "dart-analyzer", "bin", "analyzer.exe");
}

export function analyzerCwdForWorkspace(folder: vscode.WorkspaceFolder): string {
  // Run analyzer from workspace/dart-analyzer
  // so relative ".out" writes go into workspace/dart-analyzer/.out
  return path.join(folder.uri.fsPath, "dart-analyzer");
}

export function findingsPathForComponent(
  folder: vscode.WorkspaceFolder,
  componentId: string
): string {
  // Component-separated findings:
  // <workspace>/dart-analyzer/.out/<componentId>/findings.json
  return path.join(folder.uri.fsPath, "dart-analyzer", ".out", componentId, "findings.json");
}

export function rulesJsonPathForComponent(
  context: vscode.ExtensionContext,
  componentRulesFileName: string
): string {
  // Component rules JSON is stored in extension-installed analyzer data folder
  // Example for HSD:
  // <extensionRoot>/dart-analyzer/data/hardcoded_secrets_rules.json
  return path.join(context.extensionUri.fsPath, "dart-analyzer", "data", componentRulesFileName);
}

export function componentRuleManagerHtmlPath(
  context: vscode.ExtensionContext,
  relHtmlPathFromExtensionRoot: string
): string {
  // Example:
  // relHtmlPathFromExtensionRoot = "src/components/hsd/ui/ruleManager.html"
  return path.join(context.extensionUri.fsPath, relHtmlPathFromExtensionRoot);
}
