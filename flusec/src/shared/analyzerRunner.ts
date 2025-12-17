import { execFile } from "child_process";
import * as fs from "fs";
import * as path from "path";
import * as vscode from "vscode";
import { analyzerCwdForWorkspace, analyzerExePath } from "./paths";
import { Finding } from "./types";

function winNormalize(p: string) {
  // Normalize and ensure absolute Windows path format
  return path.resolve(p);
}

export async function runAnalyzerExe(
  context: vscode.ExtensionContext,
  folder: vscode.WorkspaceFolder,
  dartFilePath: string
): Promise<Finding[]> {
  const exe = winNormalize(analyzerExePath(context));
  const cwd = winNormalize(analyzerCwdForWorkspace(folder));
  const dart = winNormalize(dartFilePath);

  console.log("DEBUG analyzer exe =", exe);
  console.log("DEBUG exe exists =", fs.existsSync(exe));
  console.log("DEBUG cwd =", cwd);
  console.log("DEBUG dart file =", dart);

  // Extra sanity checks
  if (!fs.existsSync(exe)) throw new Error(`Analyzer not found: ${exe}`);
  if (!fs.existsSync(dart)) throw new Error(`Dart file not found: ${dart}`);

  return await new Promise<Finding[]>((resolve, reject) => {
    execFile(
      exe,
      [dart],
      {
        cwd,
        windowsHide: true,
        // CRITICAL: do NOT use shell here
      },
      (err, stdout, stderr) => {
        if (stderr) console.error("[Analyzer stderr]", stderr);

        if (err) {
          // IMPORTANT: show full error detail in console
          console.error("spawn error object =", err);
          return reject(err);
        }

        try {
          const parsed = JSON.parse(stdout);
          resolve(Array.isArray(parsed) ? parsed : []);
        } catch (e) {
          reject(new Error("Failed to parse analyzer stdout JSON: " + String(e)));
        }
      }
    );
  });
}
