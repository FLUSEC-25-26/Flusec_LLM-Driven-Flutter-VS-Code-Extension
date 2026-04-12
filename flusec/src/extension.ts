// src/extension.ts
//
// FLUSEC VS Code Extension — main entry point.
// Now supports: HSD + NET + IDS + IIV (Insufficient Input Validation)
// Features: Single file scan + Full project scan

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
import { openRuleManager } from "./ui/ruleManager/hardcoded_secrets/ruleManager.js";
import { openDashboard } from "./web/hsd/dashboard.js";

// NET dashboard
import { openNetDashboard } from "./web/net/dasboard.js";

// IDS dashboard
import { openIDSDashboard } from "./web/ids/dashboard.js";

// IIV dashboard
import { openIIVDashboard } from "./web/iiv/dashboard.js";

import { registerFlusecNavigationView } from "./ui/flusecNavigation.js";
import { uploadFindings } from './cloud/uploadFindings.js';
import { loginToTeam, logoutFromTeam } from './cloud/auth.js';

// HSD rulepack
import { syncHsdRulePack, writeHsdWorkspaceData } from "./rules/hsdRulePack.js";

// NET rulepack
import { syncNetRulePack, writeNetWorkspaceData } from "./rules/netRulePack.js";

// IDS rulepack
import { syncIdsRulePack, writeIdsWorkspaceData } from "./rules/idsRulePack.js";

// IIV rulepack
import { syncIivRulePack, writeIivWorkspaceData } from "./rules/iivRulePack.js";


let lastDartDoc: vscode.TextDocument | undefined;

// We only want to clear findings once per VS Code session.
let clearedFindingsThisSession = false;

// Delete hsd_findings.json, net_findings.json, ids_findings.json & iiv_findings.json
// for all workspace folders ONCE per session
function clearFindingsForAllWorkspaceFoldersOnce() {
  if (clearedFindingsThisSession) { return; }

  const folders = vscode.workspace.workspaceFolders ?? [];
  if (!folders.length) { return; }

  try {
    for (const folder of folders) {
      // Delete all component findings files
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

      // Clean up empty directories
      const outDir = findingsOutDir(folder);
      const analyzerDir = path.dirname(outDir);

      if (fs.existsSync(outDir) && fs.readdirSync(outDir).length === 0) {
        fs.rmdirSync(outDir);
        console.log("FLUSEC: deleted empty dir", outDir);
      }

      if (fs.existsSync(analyzerDir) && fs.readdirSync(analyzerDir).length === 0) {
        fs.rmdirSync(analyzerDir);
        console.log("FLUSEC: deleted empty dir", analyzerDir);
      }
    }
  } catch (e) {
    console.warn("FLUSEC: Cleanup warning:", e);
  }

  clearedFindingsThisSession = true;
}

// ─── Helper: write ALL component workspace data ──────────────────────────────

function writeAllWorkspaceData(context: vscode.ExtensionContext) {
  for (const f of vscode.workspace.workspaceFolders ?? []) {
    writeHsdWorkspaceData(context, f.uri.fsPath);
    writeNetWorkspaceData(context, f.uri.fsPath);
    writeIdsWorkspaceData(context, f.uri.fsPath);
    writeIivWorkspaceData(context, f.uri.fsPath);
  }
}

// ─── Helper: sync ALL component rulepacks ────────────────────────────────────

async function syncAllRulePacks(
  context: vscode.ExtensionContext,
  opts?: { force?: boolean }
) {
  // Sync each component independently — one failing shouldn't block others
  try {
    await syncHsdRulePack(context, opts);
  } catch (e) {
    console.error("[FLUSEC] syncHsdRulePack failed:", e);
  }

  try {
    await syncNetRulePack(context, opts);
  } catch (e) {
    console.error("[FLUSEC] syncNetRulePack failed:", e);
  }

  try {
    await syncIdsRulePack(context);
  } catch (e) {
    console.error("[FLUSEC] syncIdsRulePack failed:", e);
  }

  try {
    await syncIivRulePack(context, opts);
  } catch (e) {
    console.error("[FLUSEC] syncIivRulePack failed:", e);
  }
}

// ─── Activate ────────────────────────────────────────────────────────────────

export async function activate(context: vscode.ExtensionContext) {
  // Ensure diagnostics collection is disposed when extension is deactivated.
  context.subscriptions.push(diagCollection);

  // Keep your old cleanup behavior
  clearFindingsForAllWorkspaceFoldersOnce();

  // Mandatory remote sync for ALL components (safe offline)
  await syncAllRulePacks(context);

  // Write workspace effective files for ALL components
  writeAllWorkspaceData(context);

  // Periodic mandatory update (6 hours) for ALL components
  const timer = setInterval(async () => {
    try {
      await syncAllRulePacks(context);
      writeAllWorkspaceData(context);
    } catch (e) {
      console.error("[FLUSEC] periodic rulepack sync failed:", e);
    }
  }, 6 * 60 * 60 * 1000);

  context.subscriptions.push({ dispose: () => clearInterval(timer) });

  // If folders added later — write ALL component data
  context.subscriptions.push(
    vscode.workspace.onDidChangeWorkspaceFolders(() => {
      clearFindingsForAllWorkspaceFoldersOnce();
      writeAllWorkspaceData(context);
    })
  );

  // Track last Dart doc
  context.subscriptions.push(
    vscode.workspace.onDidOpenTextDocument((doc) => {
      if (doc.languageId === "dart") { lastDartDoc = doc; }
    })
  );

  // Force update rulepacks (ALL components)
  context.subscriptions.push(
    vscode.commands.registerCommand("flusec.updateRulePacks", async () => {
      try {
        await syncAllRulePacks(context, { force: true });
        writeAllWorkspaceData(context);
        vscode.window.showInformationMessage("FLUSEC: Rule packs updated for all components.");
      } catch (e) {
        console.error("[FLUSEC] updateRulePacks failed:", e);
        vscode.window.showErrorMessage("FLUSEC: Rule pack update failed. Check console.");
      }
    })
  );

  // Manual scan (single file)
  context.subscriptions.push(
    vscode.commands.registerCommand("flusec.scanFile", async () => {
      const active = vscode.window.activeTextEditor;
      let target: vscode.TextDocument | undefined;

      if (active && active.document.languageId === "dart") { target = active.document; }
      else if (lastDartDoc) { target = lastDartDoc; }
      else {
        const dartDocs = vscode.workspace.textDocuments.filter((d) => d.languageId === "dart");
        if (dartDocs.length > 0) { target = dartDocs[0]; }
      }

      if (!target) {
        vscode.window.showInformationMessage(
          "FLUSEC: No Dart file available to scan. Open a Dart file first."
        );
        return;
      }

      try {
        await runAnalyzer(target, context);
        vscode.window.setStatusBarMessage(`FLUSEC: Scan completed for ${target.fileName}`, 3000);
      } catch (e) {
        vscode.window.showErrorMessage("FLUSEC: Scan failed: " + String(e));
      }
    })
  );

  // ─── Full project scan (all components: HSD + NET + IDS + IIV) ───────
  context.subscriptions.push(
    vscode.commands.registerCommand("flusec.scanProject", async () => {
      const folder = vscode.workspace.workspaceFolders?.[0];
      if (!folder) {
        vscode.window.showInformationMessage("FLUSEC: No workspace folder open.");
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

            // Show summary
            const msg = [
              `Project scan complete.`,
              `Files: ${result.totalFiles} scanned, ${result.filesWithIssues} with issues.`,
              `Issues: ${result.totalIssues} total`,
              `(HSD: ${result.hsdCount}, NET: ${result.netCount}, IDS: ${result.idsCount}, IIV: ${result.iivCount})`,
            ].join(" ");

            vscode.window.showInformationMessage(`FLUSEC: ${msg}`);
          } catch (e) {
            vscode.window.showErrorMessage("FLUSEC: Project scan failed: " + String(e));
            console.error("[FLUSEC] Project scan error:", e);
          }
        }
      );
    })
  );

  // Rule manager (HSD)
  context.subscriptions.push(
    vscode.commands.registerCommand("flusec.manageRules", () => openRuleManager(context))
  );

  // Dashboard (HSD)
  context.subscriptions.push(
    vscode.commands.registerCommand("flusec.openFindings", () => openDashboard(context))
  );

  // Dashboard (NET)
  context.subscriptions.push(
    vscode.commands.registerCommand("flusec.openNetDashboard", () => openNetDashboard(context))
  );

  // Dashboard (IDS)
  context.subscriptions.push(
    vscode.commands.registerCommand("flusec.openIDSDashboard", () => openIDSDashboard(context))
  );

  // Dashboard (IIV)
  context.subscriptions.push(
    vscode.commands.registerCommand("flusec.openIIVDashboard", () => openIIVDashboard(context))
  );

  // Upload findings
  context.subscriptions.push(
    vscode.commands.registerCommand('flusec.uploadFindings', async () => {
      try {
        await uploadFindings(context);
      } catch (e) {
        vscode.window.showErrorMessage('FLUSEC: Upload failed: ' + String(e));
      }
    })
  );

  // Login to FluSec Web Platform
  context.subscriptions.push(
    vscode.commands.registerCommand('flusec.loginToTeam', async () => {
      try {
        await loginToTeam(context);
      } catch (e) {
        vscode.window.showErrorMessage('FLUSEC: Login failed: ' + String(e));
      }
    })
  );

  // Logout from FluSec Web Platform
  context.subscriptions.push(
    vscode.commands.registerCommand('flusec.logoutFromTeam', async () => {
      await logoutFromTeam(context);
    })
  );

  // Auto scan on SAVE
  context.subscriptions.push(
    vscode.workspace.onDidSaveTextDocument(async (doc) => {
      if (doc.languageId === "dart") {
        lastDartDoc = doc;
        await runAnalyzer(doc, context);
      }
    })
  );

  // Auto scan while TYPING (debounced)
  let typingTimeout: NodeJS.Timeout | undefined;
  context.subscriptions.push(
    vscode.workspace.onDidChangeTextDocument((event) => {
      const doc = event.document;
      if (doc.languageId !== "dart") { return; }

      lastDartDoc = doc;

      clearTimeout(typingTimeout);
      typingTimeout = setTimeout(() => {
        runAnalyzer(doc, context);
      }, 1500);
    })
  );

  // Hover provider (LLM feedback — routes to HSD/NET/IDS/IIV based on ruleId)
  registerHoverProvider(context);

  // Navigation view
  registerFlusecNavigationView(context);
}

export function deactivate() {
  diagCollection.clear();
  diagCollection.dispose();
}