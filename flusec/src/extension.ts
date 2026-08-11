// src/extension.ts
//
// FLUSEC VS Code Extension — main entry point.
// Supports HSD + NET + IDS + IIV with local static analysis, optional local
// educational LLM hover feedback, team policy sync and finding synchronization.

import * as vscode from 'vscode'
import * as fs from 'node:fs'
import * as path from 'node:path'
import {
  runAnalyzer,
  runProjectAnalyzer,
  findingsOutDir,
  hsdFindingsPathForFolder,
  netFindingsPathForFolder,
  idsFindingsPathForFolder,
  iivFindingsPathForFolder,
  findWorkspaceFolderForDoc,
} from './analyzer/runAnalyzer.js'
import { diagCollection } from './analyzer/findingsStore.js'
import { registerHoverProvider } from './diagnostics/hoverllm.js'
import { openDashboard } from './web/hsd/dashboard.js'
import { openNetDashboard, refreshNetDashboard } from './web/net/dasboard.js'
import { openIDSDashboard } from './web/ids/dashboard.js'
import { openIIVDashboard } from './web/iiv/dashboard.js'
import { registerFlusecNavigationView } from './ui/flusecNavigation.js'
import { uploadFindings } from './cloud/uploadFindings.js'
import {
  connectAccount,
  disconnectAccount,
  registerAuthUriHandler,
  switchTeam,
} from './cloud/auth.js'
import { recordExplicitScan } from './cloud/scanContext.js'
import { syncPoliciesForAllWorkspaces } from './policies/policySync.js'

let lastDartDoc: vscode.TextDocument | undefined
let clearedFindingsThisSession = false

function clearFindingsForAllWorkspaceFoldersOnce() {
  if (clearedFindingsThisSession) return

  const folders = vscode.workspace.workspaceFolders ?? []
  if (!folders.length) return

  try {
    for (const folder of folders) {
      for (const filePath of [
        hsdFindingsPathForFolder(folder),
        netFindingsPathForFolder(folder),
        idsFindingsPathForFolder(folder),
        iivFindingsPathForFolder(folder),
      ]) {
        if (fs.existsSync(filePath)) fs.unlinkSync(filePath)
      }

      const outDir = findingsOutDir(folder)
      const flusecDir = path.dirname(outDir)
      if (fs.existsSync(outDir) && fs.readdirSync(outDir).length === 0) fs.rmdirSync(outDir)
      if (fs.existsSync(flusecDir) && fs.readdirSync(flusecDir).length === 0) fs.rmdirSync(flusecDir)
    }
  } catch (error) {
    console.warn('[FLUSEC] Findings cleanup warning:', error)
  }

  clearedFindingsThisSession = true
}

async function tryPreparePolicies(
  context: vscode.ExtensionContext,
  source: 'startup' | 'periodic' | 'workspace-change',
): Promise<void> {
  try {
    await syncPoliciesForAllWorkspaces(context, {
      allowCachedFallback: true,
      silent: true,
    })
  } catch (error) {
    console.warn(`[FLUSEC] Policy preparation skipped (${source}):`, error)
  }
}

function captureInitialActiveDartEditor() {
  const active = vscode.window.activeTextEditor
  if (active?.document.languageId === 'dart') lastDartDoc = active.document
}

async function safeRunSingleFileScan(
  doc: vscode.TextDocument,
  context: vscode.ExtensionContext,
  opts?: { showSuccessMessage?: boolean },
): Promise<boolean> {
  try {
    await runAnalyzer(doc, context)
    if (opts?.showSuccessMessage) {
      vscode.window.setStatusBarMessage(`FLUSEC: Scan completed for ${path.basename(doc.fileName)}`, 3000)
    }
    return true
  } catch (error) {
    vscode.window.showErrorMessage(`FLUSEC: Scan failed: ${String(error)}`)
    console.error('[FLUSEC] Single-file scan error:', error)
    return false
  }
}

export async function activate(context: vscode.ExtensionContext) {
  context.subscriptions.push(diagCollection)

  // Register the browser -> VS Code OAuth callback as early as possible.
  registerAuthUriHandler(context)

  clearFindingsForAllWorkspaceFoldersOnce()
  captureInitialActiveDartEditor()

  context.subscriptions.push(
    vscode.commands.registerCommand('flusec.updateRulePacks', async () => {
      try {
        await syncPoliciesForAllWorkspaces(context, {
          allowCachedFallback: true,
          silent: false,
        })
      } catch (error) {
        vscode.window.showErrorMessage(`FLUSEC: Failed to sync policies. ${String(error)}`)
      }
    }),
  )

  context.subscriptions.push(
    vscode.commands.registerCommand('flusec.scanFile', async () => {
      const active = vscode.window.activeTextEditor
      let target: vscode.TextDocument | undefined

      if (active?.document.languageId === 'dart') {
        target = active.document
      } else if (lastDartDoc) {
        target = lastDartDoc
      } else {
        target = vscode.workspace.textDocuments.find((document) => document.languageId === 'dart')
      }

      if (!target) {
        vscode.window.showInformationMessage('FLUSEC: No Dart file is available to scan. Open a Dart file first.')
        return
      }

      const success = await safeRunSingleFileScan(target, context, { showSuccessMessage: true })
      if (success) {
        const folder = findWorkspaceFolderForDoc(target)
        if (folder) await recordExplicitScan(context, folder, 'file', target.fileName)
      }
    }),
  )

  context.subscriptions.push(
    vscode.commands.registerCommand('flusec.scanProject', async () => {
      const folder = vscode.workspace.workspaceFolders?.[0]
      if (!folder) {
        vscode.window.showInformationMessage('FLUSEC: No workspace folder is open.')
        return
      }

      let scanDir = path.join(folder.uri.fsPath, 'lib')
      if (!fs.existsSync(scanDir)) scanDir = folder.uri.fsPath

      await vscode.window.withProgress(
        {
          location: vscode.ProgressLocation.Notification,
          title: 'FLUSEC: Scanning entire project…',
          cancellable: false,
        },
        async (progress) => {
          progress.report({ message: 'Initializing project scan…' })
          try {
            const result = await runProjectAnalyzer(context, folder, scanDir)
            await recordExplicitScan(context, folder, 'project', scanDir)
            await refreshNetDashboard()

            vscode.window.showInformationMessage(
              [
                'FLUSEC: Project scan complete.',
                `${result.totalFiles} files scanned; ${result.filesWithIssues} with issues.`,
                `${result.totalIssues} findings`,
                `(HSD ${result.hsdCount}, NET ${result.netCount}, IDS ${result.idsCount}, IIV ${result.iivCount}).`,
              ].join(' '),
            )
          } catch (error) {
            vscode.window.showErrorMessage(`FLUSEC: Project scan failed: ${String(error)}`)
            console.error('[FLUSEC] Project scan error:', error)
          }
        },
      )
    }),
  )

  context.subscriptions.push(
    vscode.commands.registerCommand('flusec.openFindings', () => openDashboard(context)),
    vscode.commands.registerCommand('flusec.openNetDashboard', () => openNetDashboard(context)),
    vscode.commands.registerCommand('flusec.openIDSDashboard', () => openIDSDashboard(context)),
    vscode.commands.registerCommand('flusec.openIIVDashboard', () => openIIVDashboard(context)),
  )

  context.subscriptions.push(
    vscode.commands.registerCommand('flusec.uploadFindings', async () => {
      try {
        await uploadFindings(context)
      } catch (error) {
        vscode.window.showErrorMessage(`FLUSEC: Finding sync failed: ${String(error)}`)
      }
    }),
  )

  // Browser-based OAuth. connectAccount() only starts the flow; the URI
  // callback in cloud/auth.ts completes it, selects the team, and syncs policy.
  context.subscriptions.push(
    vscode.commands.registerCommand('flusec.loginToTeam', async () => {
      try {
        await connectAccount(context)
      } catch (error) {
        vscode.window.showErrorMessage(`FLUSEC: Could not start account connection: ${String(error)}`)
      }
    }),
    vscode.commands.registerCommand('flusec.switchTeam', async () => {
      await switchTeam(context)
    }),
    vscode.commands.registerCommand('flusec.logoutFromTeam', async () => {
      await disconnectAccount(context)
    }),
  )

  context.subscriptions.push(
    vscode.workspace.onDidChangeWorkspaceFolders(async () => {
      clearFindingsForAllWorkspaceFoldersOnce()
      await tryPreparePolicies(context, 'workspace-change')
    }),
  )

  context.subscriptions.push(
    vscode.workspace.onDidOpenTextDocument((doc) => {
      if (doc.languageId === 'dart') lastDartDoc = doc
    }),
  )

  // Auto scans update diagnostics/local dashboards only. They intentionally do
  // not overwrite the explicit scan scope used for cloud synchronization.
  context.subscriptions.push(
    vscode.workspace.onDidSaveTextDocument(async (doc) => {
      if (doc.languageId === 'dart') {
        lastDartDoc = doc
        await safeRunSingleFileScan(doc, context)
      }
    }),
  )

  let typingTimeout: NodeJS.Timeout | undefined
  context.subscriptions.push(
    vscode.workspace.onDidChangeTextDocument((event) => {
      const doc = event.document
      if (doc.languageId !== 'dart') return

      lastDartDoc = doc
      clearTimeout(typingTimeout)
      typingTimeout = setTimeout(() => {
        void runAnalyzer(doc, context).catch((error) => {
          console.error('[FLUSEC] Auto-scan failed:', error)
        })
      }, 1500)
    }),
  )

  registerHoverProvider(context)
  registerFlusecNavigationView(context)

  // Offline-first startup: team-specific cache when available, otherwise the
  // bundled defaults. No authentication dialog is shown during activation.
  await tryPreparePolicies(context, 'startup')

  const timer = setInterval(() => {
    void tryPreparePolicies(context, 'periodic')
  }, 6 * 60 * 60 * 1000)

  context.subscriptions.push({ dispose: () => clearInterval(timer) })
}

export function deactivate() {
  diagCollection.clear()
  diagCollection.dispose()
}
