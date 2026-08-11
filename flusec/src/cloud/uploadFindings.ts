import * as vscode from 'vscode'
import * as fs from 'node:fs'
import {
  hsdFindingsPathForFolder,
  netFindingsPathForFolder,
  idsFindingsPathForFolder,
  iivFindingsPathForFolder,
} from '../analyzer/runAnalyzer.js'
import { authenticatedFetch, getSelectedTeam } from './auth.js'
import {
  getLastExplicitScan,
  workspaceIdentity,
  workspaceRelativePath,
} from './scanContext.js'
import { CONFIG } from '../config.js'

type Component = 'HSD' | 'NET' | 'IDS' | 'IIV'
type SecuritySeverity = 'critical' | 'high' | 'medium' | 'low'
type DetectionConfidence = 'high' | 'medium' | 'low'

interface TaintFlowStep {
  type?: string
  line?: number | null
  column?: number | null
  description?: string | null
}

interface ApiFinding {
  component: Component
  fingerprint?: string
  rule_id?: string
  title: string
  description?: string | null
  diagnostic_severity: 'warning'
  security_severity: SecuritySeverity
  confidence: DetectionConfidence
  category?: string | null
  cwe?: string | null
  remediation?: string | null
  evidence: Record<string, unknown>
  file_path?: string | null
  line_number?: number | null
  column_number?: number | null
  code_snippet?: string | null
  function_name?: string | null
  complexity?: number | null
  nesting_depth?: number | null
  function_loc?: number | null
  maintainability_score?: number | null
  maintainability_level?: string | null
  secret_type?: string | null
  taint_flow?: TaintFlowStep[] | null
  data_type?: string | null
  storage_context?: string | null
}

interface UploadResponse {
  data?: {
    session_id?: string
    findings_count?: number
    canonical_findings_updated?: number
    resolved_count?: number
  }
  error?: string
}

function readJsonArray(filePath: string): Record<string, any>[] {
  if (!fs.existsSync(filePath)) return []
  try {
    const parsed = JSON.parse(fs.readFileSync(filePath, 'utf8'))
    return Array.isArray(parsed) ? parsed : []
  } catch (error) {
    console.warn(`[FLUSEC] Could not read findings file ${filePath}:`, error)
    return []
  }
}

function stringValue(value: unknown): string | undefined {
  return typeof value === 'string' && value.trim() ? value.trim() : undefined
}

function numberValue(value: unknown): number | undefined {
  return typeof value === 'number' && Number.isFinite(value) ? value : undefined
}

function objectValue(value: unknown): Record<string, unknown> {
  return value && typeof value === 'object' && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {}
}

function arrayValue<T>(value: unknown): T[] | null {
  return Array.isArray(value) ? (value as T[]) : null
}

function severityValue(value: unknown): SecuritySeverity {
  const normalized = stringValue(value)?.toLowerCase()
  if (normalized === 'critical' || normalized === 'high' || normalized === 'medium' || normalized === 'low') {
    return normalized
  }
  return 'low'
}

function confidenceValue(value: unknown): DetectionConfidence {
  const normalized = stringValue(value)?.toLowerCase()
  if (normalized === 'high' || normalized === 'medium' || normalized === 'low') return normalized
  return 'medium'
}

function canonicalFinding(
  raw: Record<string, any>,
  component: Component,
  folder: vscode.WorkspaceFolder,
): ApiFinding {
  const filePath = workspaceRelativePath(
    folder,
    stringValue(raw.file_path) ?? stringValue(raw.filePath) ?? stringValue(raw.file),
  )

  return {
    component,
    fingerprint: stringValue(raw.fingerprint),
    rule_id: stringValue(raw.rule_id) ?? stringValue(raw.ruleId),
    title: stringValue(raw.title) ?? stringValue(raw.message) ?? `${component} security finding`,
    description: stringValue(raw.description) ?? stringValue(raw.message) ?? null,
    diagnostic_severity: 'warning',
    security_severity: severityValue(raw.security_severity ?? raw.securitySeverity),
    confidence: confidenceValue(raw.confidence),
    category: stringValue(raw.category) ?? null,
    cwe: stringValue(raw.cwe) ?? null,
    remediation: stringValue(raw.remediation) ?? null,
    evidence: objectValue(raw.evidence),
    file_path: filePath,
    line_number: numberValue(raw.line_number) ?? numberValue(raw.line) ?? null,
    column_number: numberValue(raw.column_number) ?? numberValue(raw.column) ?? null,
    code_snippet:
      stringValue(raw.code_snippet) ?? stringValue(raw.codeSnippet) ?? stringValue(raw.snippet) ?? null,
    function_name: stringValue(raw.function_name) ?? stringValue(raw.functionName) ?? null,
    complexity: numberValue(raw.complexity) ?? null,
    nesting_depth: numberValue(raw.nesting_depth) ?? numberValue(raw.nestingDepth) ?? null,
    function_loc: numberValue(raw.function_loc) ?? numberValue(raw.functionLoc) ?? null,
    maintainability_score:
      numberValue(raw.maintainability_score) ?? numberValue(raw.maintainabilityScore) ?? null,
    maintainability_level:
      stringValue(raw.maintainability_level) ?? stringValue(raw.maintainabilityLevel) ?? null,
    secret_type: component === 'HSD'
      ? stringValue(raw.secret_type) ?? stringValue(raw.secretType) ?? null
      : null,
    taint_flow: component === 'HSD'
      ? arrayValue<TaintFlowStep>(raw.taint_flow ?? raw.taintFlow)
      : null,
    data_type: component === 'IDS'
      ? stringValue(raw.data_type) ?? stringValue(raw.dataType) ?? null
      : null,
    storage_context: component === 'IDS'
      ? stringValue(raw.storage_context) ?? stringValue(raw.storageContext) ?? null
      : null,
  }
}

function findingsForFolder(folder: vscode.WorkspaceFolder): ApiFinding[] {
  return [
    ...readJsonArray(hsdFindingsPathForFolder(folder)).map((raw) => canonicalFinding(raw, 'HSD', folder)),
    ...readJsonArray(netFindingsPathForFolder(folder)).map((raw) => canonicalFinding(raw, 'NET', folder)),
    ...readJsonArray(idsFindingsPathForFolder(folder)).map((raw) => canonicalFinding(raw, 'IDS', folder)),
    ...readJsonArray(iivFindingsPathForFolder(folder)).map((raw) => canonicalFinding(raw, 'IIV', folder)),
  ]
}

export async function uploadFindings(context: vscode.ExtensionContext): Promise<void> {
  const folders = vscode.workspace.workspaceFolders ?? []
  if (folders.length === 0) {
    vscode.window.showWarningMessage('FLUSEC: No workspace folder is open.')
    return
  }

  const team = await getSelectedTeam(context)
  if (!team) {
    const action = await vscode.window.showErrorMessage(
      'FLUSEC: No team is selected for this workspace. Connect your account or select a team first.',
      'Connect Account',
    )
    if (action === 'Connect Account') await vscode.commands.executeCommand('flusec.loginToTeam')
    return
  }

  const endpoint = CONFIG.WEB_API_ENDPOINT.replace(/\/$/, '')
  let totalObserved = 0
  let totalResolved = 0
  let failedWorkspaces = 0

  await vscode.window.withProgress(
    {
      location: vscode.ProgressLocation.Notification,
      title: 'FLUSEC: Syncing findings to team…',
      cancellable: false,
    },
    async (progress) => {
      for (const folder of folders) {
        const findings = findingsForFolder(folder)
        const lastScan = getLastExplicitScan(context, folder)

        // If no explicit scan was recorded, use conservative file scope. This
        // prevents a background/autoscan result from resolving unrelated project findings.
        const scanScope = lastScan?.scope ?? 'file'
        const scannedTarget = lastScan?.target ?? '.'

        progress.report({
          message: `${folder.name}: syncing ${findings.length} finding${findings.length === 1 ? '' : 's'}…`,
        })

        try {
          const response = await authenticatedFetch(
            context,
            `${endpoint}/api/v1/findings/upload`,
            {
              method: 'POST',
              headers: {
                'Content-Type': 'application/json',
                Accept: 'application/json',
              },
              body: JSON.stringify({
                team_id: team.id,
                workspace_id: workspaceIdentity(folder),
                scan_scope: scanScope,
                scanned_target: scannedTarget,
                findings,
              }),
            },
          )

          const text = await response.text()
          let payload: UploadResponse = {}
          try { payload = text ? JSON.parse(text) as UploadResponse : {} } catch { /* handled below */ }

          if (!response.ok) {
            failedWorkspaces += 1
            vscode.window.showWarningMessage(
              `FLUSEC: Could not sync ${folder.name}: ${payload.error ?? `HTTP ${response.status}`}`,
            )
            continue
          }

          totalObserved += payload.data?.findings_count ?? findings.length
          totalResolved += payload.data?.resolved_count ?? 0
        } catch (error) {
          failedWorkspaces += 1
          vscode.window.showWarningMessage(`FLUSEC: Could not sync ${folder.name}: ${String(error)}`)
        }
      }
    },
  )

  if (failedWorkspaces > 0) {
    const message = `FLUSEC: Sync finished with ${failedWorkspaces} failed workspace${failedWorkspaces === 1 ? '' : 's'}. ${totalObserved} findings observed.`
    vscode.window.showWarningMessage(message)
    return
  }

  vscode.window.showInformationMessage(
    `FLUSEC: Sync complete. ${totalObserved} findings observed${totalResolved > 0 ? `, ${totalResolved} resolved` : ''}.`,
  )
}
