// src/extension.ts
//
// FLUSEC VS Code Extension — main entry point.
// Supports: HSD + NET + IDS + IIV
// Features: Single file scan + Full project scan + Team sync + Policy sync
//
// Important runtime design:
// - The extension must NOT require the web backend to be running just to activate.
// - Policy sync is best-effort on startup.
// - If backend sync fails, activation continues and the user can manually run "Sync Policies".

import * as vscode from "vscode";
import * as fs from "fs";
import * as path from "path";
import {
  runAnalyzer,
  runProjectAnalyzer,
  findingsOutDir,
  hsdFindingsPathForFolder,
  netFindingsPathForFolder,
  idsFindingsPathForFolder,
  iivFindingsPathForFolder,
} from "./analyzer/runAnalyzer.js";
import { diagCollection } from "./analyzer/findingsStore.js";
import { registerHoverProvider } from "./diagnostics/hoverllm.js";
import { openDashboard } from "./web/hsd/dashboard.js";
import { openNetDashboard } from "./web/net/dasboard.js";
import { openIDSDashboard } from "./web/ids/dashboard.js";
import { openIIVDashboard } from "./web/iiv/dashboard.js";
import { registerFlusecNavigationView } from "./ui/flusecNavigation.js";
import { uploadFindings } from "./cloud/uploadFindings.js";
import { loginToTeam, logoutFromTeam } from "./cloud/auth.js";
import { syncPoliciesForAllWorkspaces } from "./policies/policySync.js";

let lastDartDoc: vscode.TextDocument | undefined;

// We only want to clear findings once per VS Code session.
let clearedFindingsThisSession = false;

// Delete local findings files for all workspace folders ONCE per session
function clearFindingsForAllWorkspaceFoldersOnce() {
  if (clearedFindingsThisSession) {
    return;
  }

  const folders = vscode.workspace.workspaceFolders ?? [];
  if (!folders.length) {
    return;
  }

  try {
    for (const folder of folders) {
      for (const fp of [
        hsdFindingsPathForFolder(folder),
        netFindingsPathForFolder(folder),
        idsFindingsPathForFolder(folder),
        iivFindingsPathForFolder(folder),
      ]) {
        if (fs.existsSync(fp)) {
          fs.unlinkSync(fp);
          console.log("FLUSEC: deleted", fp);
        }
      }

      const outDir = findingsOutDir(folder);
      const analyzerDir = path.dirname(outDir);

      if (fs.existsSync(outDir) && fs.readdirSync(outDir).length === 0) {
        fs.rmdirSync(outDir);
        console.log("FLUSEC: deleted empty dir", outDir);
      }

      if (
        fs.existsSync(analyzerDir) &&
        fs.readdirSync(analyzerDir).length === 0
      ) {
        fs.rmdirSync(analyzerDir);
        console.log("FLUSEC: deleted empty dir", analyzerDir);
      }
    }
  } catch (e) {
    console.warn("FLUSEC: Cleanup warning:", e);
  }

  clearedFindingsThisSession = true;
}

// Best-effort policy preparation.
// This should never be allowed to break extension activation.
async function writeAllWorkspaceData(context: vscode.ExtensionContext) {
  await syncPoliciesForAllWorkspaces(context, {
    allowCachedFallback: true,
    silent: false,
  });
}

async function tryPreparePolicies(
  context: vscode.ExtensionContext,
  source: "startup" | "periodic" | "workspace-change" | "post-login"
): Promise<boolean> {
  try {
    await writeAllWorkspaceData(context);

    if (source === "post-login") {
      vscode.window.showInformationMessage(
        "FLUSEC: Policies synced successfully after login."
      );
    }

    return true;
  } catch (e) {
    const msg = `FLUSEC: Policy sync skipped (${source}). ${String(e)}`;

    // Do not spam users during activation/background operations.
    // Just log and continue.
    if (source === "startup" || source === "periodic" || source === "workspace-change") {
      console.warn(msg);
      return false;
    }

    // post-login can show a warning because the user just completed login
    vscode.window.showWarningMessage(msg);
    return false;
  }
}

function captureInitialActiveDartEditor() {
  const active = vscode.window.activeTextEditor;
  if (active?.document.languageId === "dart") {
    lastDartDoc = active.document;
  }
}

async function safeRunSingleFileScan(
  doc: vscode.TextDocument,
  context: vscode.ExtensionContext,
  opts?: { showSuccessMessage?: boolean }
): Promise<void> {
  try {
    await runAnalyzer(doc, context);

    if (opts?.showSuccessMessage) {
      vscode.window.setStatusBarMessage(
        `FLUSEC: Scan completed for ${doc.fileName}`,
        3000
      );
    }
  } catch (e) {
    vscode.window.showErrorMessage("FLUSEC: Scan failed: " + String(e));
    console.error("[FLUSEC] Single-file scan error:", e);
  }
}

export async function activate(context: vscode.ExtensionContext) {
  // Ensure diagnostics collection is disposed when extension is deactivated.
  context.subscriptions.push(diagCollection);

  // Keep old cleanup behavior
  clearFindingsForAllWorkspaceFoldersOnce();

  // Track currently active editor if already open
  captureInitialActiveDartEditor();

  // ─── Commands ─────────────────────────────────────────────────────────────

  // Manual policy sync
  context.subscriptions.push(
    vscode.commands.registerCommand("flusec.updateRulePacks", async () => {
      try {
        await syncPoliciesForAllWorkspaces(context, {
          allowCachedFallback: true,
          silent: false,
        });
        vscode.window.showInformationMessage(
          "FLUSEC: Policies synced successfully."
        );
      } catch (e) {
        vscode.window.showErrorMessage(
          "FLUSEC: Failed to sync policies. " + String(e)
        );
      }
    })
  );

  // Manual scan (single file)
  context.subscriptions.push(
    vscode.commands.registerCommand("flusec.scanFile", async () => {
      const active = vscode.window.activeTextEditor;
      let target: vscode.TextDocument | undefined;

      if (active && active.document.languageId === "dart") {
        target = active.document;
      } else if (lastDartDoc) {
        target = lastDartDoc;
      } else {
        const dartDocs = vscode.workspace.textDocuments.filter(
          (d) => d.languageId === "dart"
        );
        if (dartDocs.length > 0) {
          target = dartDocs[0];
        }
      }

      if (!target) {
        vscode.window.showInformationMessage(
          "FLUSEC: No Dart file available to scan. Open a Dart file first."
        );
        return;
      }

      await safeRunSingleFileScan(target, context, {
        showSuccessMessage: true,
      });
    })
  );

  // Full project scan
  context.subscriptions.push(
    vscode.commands.registerCommand("flusec.scanProject", async () => {
      const folder = vscode.workspace.workspaceFolders?.[0];
      if (!folder) {
        vscode.window.showInformationMessage(
          "FLUSEC: No workspace folder open."
        );
        return;
      }

      // Prefer lib/ for Flutter projects, fall back to workspace root
      let scanDir = path.join(folder.uri.fsPath, "lib");
      if (!fs.existsSync(scanDir)) {
        scanDir = folder.uri.fsPath;
      }

      await vscode.window.withProgress(
        {
          location: vscode.ProgressLocation.Notification,
          title: "FLUSEC: Scanning entire project...",
          cancellable: false,
        },
        async (progress) => {
          progress.report({ message: "Initializing project scan..." });

          try {
            const result = await runProjectAnalyzer(context, folder, scanDir);

            const msg = [
              "Project scan complete.",
              `Files: ${result.totalFiles} scanned, ${result.filesWithIssues} with issues.`,
              `Issues: ${result.totalIssues} total`,
              `(HSD: ${result.hsdCount}, NET: ${result.netCount}, IDS: ${result.idsCount}, IIV: ${result.iivCount})`,
            ].join(" ");

            vscode.window.showInformationMessage(`FLUSEC: ${msg}`);
          } catch (e) {
            vscode.window.showErrorMessage(
              "FLUSEC: Project scan failed: " + String(e)
            );
            console.error("[FLUSEC] Project scan error:", e);
          }
        }
      );
    })
  );

  // Dashboards
  context.subscriptions.push(
    vscode.commands.registerCommand("flusec.openFindings", () =>
      openDashboard(context)
    )
  );

  context.subscriptions.push(
    vscode.commands.registerCommand("flusec.openNetDashboard", () =>
      openNetDashboard(context)
    )
  );

  context.subscriptions.push(
    vscode.commands.registerCommand("flusec.openIDSDashboard", () =>
      openIDSDashboard(context)
    )
  );

  context.subscriptions.push(
    vscode.commands.registerCommand("flusec.openIIVDashboard", () =>
      openIIVDashboard(context)
    )
  );

  // Upload findings
  context.subscriptions.push(
    vscode.commands.registerCommand("flusec.uploadFindings", async () => {
      try {
        await uploadFindings(context);
      } catch (e) {
        vscode.window.showErrorMessage(
          "FLUSEC: Upload failed: " + String(e)
        );
      }
    })
  );

  // Login to team
  context.subscriptions.push(
    vscode.commands.registerCommand("flusec.loginToTeam", async () => {
      try {
        await loginToTeam(context);

        // Best-effort policy sync after successful login
        await tryPreparePolicies(context, "post-login");
      } catch (e) {
        vscode.window.showErrorMessage(
          "FLUSEC: Login failed: " + String(e)
        );
      }
    })
  );

  // Logout from team
  context.subscriptions.push(
    vscode.commands.registerCommand("flusec.logoutFromTeam", async () => {
      await logoutFromTeam(context);
    })
  );

  // ─── Event handlers ────────────────────────────────────────────────────────

  // If folders added later — try best-effort policy preparation
  context.subscriptions.push(
    vscode.workspace.onDidChangeWorkspaceFolders(async () => {
      clearFindingsForAllWorkspaceFoldersOnce();
      await tryPreparePolicies(context, "workspace-change");
    })
  );

  // Track last Dart doc
  context.subscriptions.push(
    vscode.workspace.onDidOpenTextDocument((doc) => {
      if (doc.languageId === "dart") {
        lastDartDoc = doc;
      }
    })
  );

  // Auto scan on SAVE
  context.subscriptions.push(
    vscode.workspace.onDidSaveTextDocument(async (doc) => {
      if (doc.languageId === "dart") {
        lastDartDoc = doc;
        await safeRunSingleFileScan(doc, context);
      }
    })
  );

  // Auto scan while TYPING (debounced)
  let typingTimeout: NodeJS.Timeout | undefined;
  context.subscriptions.push(
    vscode.workspace.onDidChangeTextDocument((event) => {
      const doc = event.document;
      if (doc.languageId !== "dart") {
        return;
      }

      lastDartDoc = doc;

      clearTimeout(typingTimeout);
      typingTimeout = setTimeout(() => {
        void runAnalyzer(doc, context).catch((e) => {
          console.error("[FLUSEC] Auto-scan failed:", e);
        });
      }, 1500);
    })
  );

  // ─── Providers / UI ────────────────────────────────────────────────────────

  registerHoverProvider(context);
  registerFlusecNavigationView(context);

  // ─── Background behavior ───────────────────────────────────────────────────

  // Best-effort initial policy preparation.
  // Important: do NOT fail activation if backend is unavailable.
  await tryPreparePolicies(context, "startup");

  // Periodic best-effort refresh (6 hours)
  const timer = setInterval(() => {
    void tryPreparePolicies(context, "periodic");
  }, 6 * 60 * 60 * 1000);

  context.subscriptions.push({
    dispose: () => clearInterval(timer),
  });
}

export function deactivate() {
  diagCollection.clear();
  diagCollection.dispose();
}