// src/shared/analyzerRunner.ts
//
// Runs analyzer.exe and parses stdout JSON.
//
// ✅ Expected behavior (your current behavior):
// - analyzer.exe receives one dart file path
// - stdout = JSON array (minimal payload)
// - stderr = debug logs (we print them to Extension Output/Console)
//
// Important:
// - We set cwd to workspace/dart-analyzer
//   so analyzer relative paths (.out, data, etc.) behave correctly.

import { execFile } from "child_process";
import * as vscode from "vscode";
import * as fs from "fs";
import { Finding } from "./types";
import { analyzerCwdForWorkspace, analyzerExePath } from "./paths";

export async function runAnalyzerExe(
  context: vscode.ExtensionContext,
  folder: vscode.WorkspaceFolder,
  dartFilePath: string
): Promise<Finding[]> {
  const exe = analyzerExePath(context);
  const cwd = analyzerCwdForWorkspace(folder);

  if (!fs.existsSync(exe)) {
    throw new Error(`Analyzer not found at: ${exe}`);
  }

  return await new Promise<Finding[]>((resolve, reject) => {
    execFile(
      exe,
      [dartFilePath],
      {
        
        cwd, // ✅ critical fix for ".out" writing location
      },
      (err, stdout, stderr) => {
        if (stderr) {
          // Analyzer logs (including your "Reloaded rules..." etc.)
          console.error("[Analyzer stderr]", stderr);
        }
        if (err) {
          reject(err);
          return;
        }

        try {
          const parsed = JSON.parse(stdout);
          if (!Array.isArray(parsed)) {
            resolve([]);
            return;
          }
          resolve(parsed as Finding[]);
        } catch (e) {
          reject(new Error("Failed to parse analyzer stdout JSON: " + String(e)));
        }
      }
    );
  });
}
