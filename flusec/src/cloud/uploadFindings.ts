import * as vscode from 'vscode';
import * as fs from 'fs';
import fetch from 'node-fetch';
import {
  hsdFindingsPathForFolder,
  netFindingsPathForFolder,
  idsFindingsPathForFolder,
  iivFindingsPathForFolder,
} from '../analyzer/runAnalyzer.js';
import { getStoredToken, getStoredTeamId } from './auth.js';

type Module = 'HSD' | 'SNC' | 'SDS' | 'IVS';

interface TaintFlowStep {
  type?: string;
  line?: number | null;
  column?: number | null;
  description?: string | null;
}

interface UploadFinding {
  module: Module;
  rule_id?: string;
  title: string;
  description?: string;

  // `severity` is security impact for the web/backend contract.
  severity: string;
  // `original_severity` keeps the editor diagnostic level (currently warning).
  original_severity?: string | null;
  confidence?: string | null;
  category?: string | null;
  cwe?: string | null;
  evidence?: Record<string, unknown> | null;
  fingerprint?: string | null;

  file_path?: string;
  line_number?: number;
  column_number?: number;
  code_snippet?: string;

  // Shared function-level maintainability context.
  function_name?: string | null;
  complexity?: number | null;
  nesting_depth?: number | null;
  function_loc?: number | null;
  maintainability_score?: number | null;
  maintainability_level?: string | null;

  // HSD-only.
  secret_type?: string | null;
  taint_flow?: TaintFlowStep[] | null;

  // Existing web/backend field. It is derived from canonical securitySeverity
  // until the web platform is normalized in the next phase.
  risk_level?: string | null;
  data_type?: string | null;
  storage_context?: string | null;
}

function readJsonArray(filePath: string): any[] {
  if (!fs.existsSync(filePath)) {
    return [];
  }

  try {
    const data = JSON.parse(fs.readFileSync(filePath, 'utf8'));
    return Array.isArray(data) ? data : [];
  } catch {
    return [];
  }
}

function asString(value: unknown): string | undefined {
  return typeof value === 'string' && value.trim() ? value.trim() : undefined;
}

function asNumber(value: unknown): number | undefined {
  return typeof value === 'number' && Number.isFinite(value) ? value : undefined;
}

function asArray<T = unknown>(value: unknown): T[] | null {
  return Array.isArray(value) ? (value as T[]) : null;
}

function getCodeSnippet(raw: any): string | undefined {
  return (
    asString(raw.codeSnippet) ??
    asString(raw.code_snippet) ??
    asString(raw.snippet)
  );
}

function getSecuritySeverity(raw: any, fallback = 'low'): string {
  // Analyzer `severity` is the VS Code diagnostic level. The web platform
  // needs security impact, so prefer the normalized securitySeverity field.
  return (
    asString(raw.security_severity) ??
    asString(raw.securitySeverity) ??
    asString(raw.risk_level) ??
    fallback
  );
}

function getDiagnosticSeverity(raw: any): string {
  return (
    asString(raw.original_severity) ??
    asString(raw.originalSeverity) ??
    asString(raw.severity) ??
    'warning'
  );
}

function baseFinding(
  raw: any,
  module: Module,
  defaultTitle: string
): UploadFinding {
  return {
    module,
    rule_id: asString(raw.rule_id) ?? asString(raw.ruleId) ?? asString(raw.code),
    title: asString(raw.title) ?? asString(raw.message) ?? defaultTitle,
    description: asString(raw.description),
    severity: getSecuritySeverity(raw),
    original_severity: getDiagnosticSeverity(raw),
    confidence: asString(raw.confidence) ?? null,
    category: asString(raw.category) ?? null,
    cwe: asString(raw.cwe) ?? null,
    evidence:
      raw.evidence && typeof raw.evidence === 'object' && !Array.isArray(raw.evidence)
        ? raw.evidence
        : null,
    fingerprint: asString(raw.fingerprint) ?? null,
    file_path:
      asString(raw.file_path) ??
      asString(raw.filePath) ??
      asString(raw.file),
    line_number: asNumber(raw.line_number) ?? asNumber(raw.line),
    column_number: asNumber(raw.column_number) ?? asNumber(raw.column),
    code_snippet: getCodeSnippet(raw),
    function_name: asString(raw.function_name) ?? asString(raw.functionName) ?? null,
    complexity: asNumber(raw.complexity) ?? null,
    nesting_depth: asNumber(raw.nesting_depth) ?? asNumber(raw.nestingDepth) ?? null,
    function_loc: asNumber(raw.function_loc) ?? asNumber(raw.functionLoc) ?? null,
    maintainability_score:
      asNumber(raw.maintainability_score) ??
      asNumber(raw.maintainabilityScore) ??
      null,
    maintainability_level:
      asString(raw.maintainability_level) ??
      asString(raw.maintainabilityLevel) ??
      null,
  };
}

function normaliseHsd(raw: any[]): UploadFinding[] {
  return raw.map((r) => ({
    ...baseFinding(r, 'HSD', 'Hardcoded Secret Detected'),
    secret_type: asString(r.secret_type) ?? asString(r.secretType) ?? null,
    taint_flow: asArray<TaintFlowStep>(r.taint_flow ?? r.taintFlow),
  }));
}

function normaliseNet(raw: any[]): UploadFinding[] {
  return raw.map((r) => ({
    ...baseFinding(r, 'SNC', 'Insecure Network Configuration'),
  }));
}

function normaliseIds(raw: any[]): UploadFinding[] {
  return raw.map((r) => ({
    ...baseFinding(r, 'SDS', 'Insecure Data Storage'),
    risk_level:
      asString(r.security_severity) ??
      asString(r.securitySeverity) ??
      null,
    data_type: asString(r.data_type) ?? asString(r.dataType) ?? null,
    storage_context:
      asString(r.storage_context) ?? asString(r.storageContext) ?? null,
  }));
}

function normaliseIiv(raw: any[]): UploadFinding[] {
  return raw.map((r) => ({
    ...baseFinding(r, 'IVS', 'Insufficient Input Validation'),
  }));
}

export async function uploadFindings(context: vscode.ExtensionContext) {
  const folders = vscode.workspace.workspaceFolders;
  if (!folders || folders.length === 0) {
    vscode.window.showWarningMessage('FLUSEC: No workspace folders open.');
    return;
  }

  const token = await getStoredToken(context);
  const teamId = await getStoredTeamId(context);

  if (!token || !teamId) {
    const action = await vscode.window.showErrorMessage(
      'FLUSEC: You are not logged in. Please run "FluSec: Login to Team" first.',
      'Login now'
    );
    if (action === 'Login now') {
      await vscode.commands.executeCommand('flusec.loginToTeam');
    }
    return;
  }

  const config = vscode.workspace.getConfiguration('flusec');
  const endpoint = (config.get<string>('webApiEndpoint') ?? 'http://localhost:3001').replace(/\/$/, '');

  let totalUploaded = 0;
  let totalErrors = 0;

  await vscode.window.withProgress(
    {
      location: vscode.ProgressLocation.Notification,
      title: 'FLUSEC: Syncing findings to team…',
      cancellable: false,
    },
    async (progress) => {
      for (const folder of folders) {
        const hsdRaw = readJsonArray(hsdFindingsPathForFolder(folder));
        const netRaw = readJsonArray(netFindingsPathForFolder(folder));
        const idsRaw = readJsonArray(idsFindingsPathForFolder(folder));
        const iivRaw = readJsonArray(iivFindingsPathForFolder(folder));

        const findings: UploadFinding[] = [
          ...normaliseHsd(hsdRaw),
          ...normaliseNet(netRaw),
          ...normaliseIds(idsRaw),
          ...normaliseIiv(iivRaw),
        ];

        if (findings.length === 0) {
          progress.report({ message: `${folder.name}: no findings to sync` });
          continue;
        }

        progress.report({
          message: `Uploading ${findings.length} findings from ${folder.name}…`,
        });

        try {
          const res = await fetch(`${endpoint}/api/findings/upload`, {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              Authorization: `Bearer ${token}`,
            },
            body: JSON.stringify({
              team_id: teamId,
              scanned_file: folder.name,
              findings,
            }),
          });

          const json = await res.json().catch(() => ({} as any));

          if (!res.ok) {
            totalErrors += 1;
            vscode.window.showWarningMessage(
              `FLUSEC: Failed to sync ${folder.name}: ${json?.error ?? `HTTP ${res.status}`}`
            );
            continue;
          }

          totalUploaded += json?.data?.findings_count ?? findings.length;
        } catch (e) {
          totalErrors += 1;
          vscode.window.showWarningMessage(
            `FLUSEC: Failed to sync ${folder.name}: ${String(e)}`
          );
        }
      }
    }
  );

  if (totalErrors > 0 && totalUploaded > 0) {
    vscode.window.showWarningMessage(
      `FLUSEC: Sync completed with warnings. Uploaded ${totalUploaded} findings, ${totalErrors} workspace(s) failed.`
    );
    return;
  }

  if (totalErrors > 0) {
    vscode.window.showErrorMessage(
      `FLUSEC: Sync failed. ${totalErrors} workspace(s) could not be uploaded.`
    );
    return;
  }

  vscode.window.showInformationMessage(
    `FLUSEC: Sync completed successfully. Uploaded ${totalUploaded} findings.`
  );
}
