// src/cloud/uploadFindings.ts
//
// Upload findings from all components to the FluSec Web Platform.
// Reads hsd_findings.json, net_findings.json, and ids_findings.json,
// normalises them into the web API format, and POSTs to /api/findings/upload.

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

// ─── Types ────────────────────────────────────────────────────────────────────

type Severity = 'critical' | 'high' | 'medium' | 'low';
type Module = 'HSD' | 'SNC' | 'SDS' | 'IVS';

interface RawFinding {
  module: Module;
  rule_id?: string;
  title: string;
  description?: string;
  severity: Severity;
  file_path?: string;
  line_number?: number;
  code_snippet?: string;
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function readJsonArray(filePath: string): any[] {
  if (!fs.existsSync(filePath)) { return []; }
  try {
    const data = JSON.parse(fs.readFileSync(filePath, 'utf8'));
    return Array.isArray(data) ? data : [];
  } catch {
    return [];
  }
}

// Normalise HSD findings to the web API schema
function normaliseHsd(raw: any[]): RawFinding[] {
  return raw.map(r => ({
    module: 'HSD',
    rule_id: r.ruleId ?? r.rule_id,
    title: r.message ?? r.title ?? 'Hardcoded Secret Detected',
    description: r.description,
    severity: normaliseSeverity(r.severity ?? r.riskLevel),
    file_path: r.filePath ?? r.file_path,
    line_number: r.lineNumber ?? r.line_number,
    code_snippet: r.codeSnippet ?? r.code_snippet,
  }));
}

// Normalise NET/SNC findings
function normaliseNet(raw: any[]): RawFinding[] {
  return raw.map(r => ({
    module: 'SNC',
    rule_id: r.ruleId ?? r.rule_id,
    title: r.message ?? r.title ?? 'Insecure Network Configuration',
    description: r.description,
    severity: normaliseSeverity(r.severity ?? r.riskLevel),
    file_path: r.filePath ?? r.file_path,
    line_number: r.lineNumber ?? r.line_number,
    code_snippet: r.codeSnippet ?? r.code_snippet,
  }));
}

// Normalise IDS/SDS findings
function normaliseIds(raw: any[]): RawFinding[] {
  return raw.map(r => ({
    module: 'SDS',
    rule_id: r.ruleId ?? r.rule_id,
    title: r.message ?? r.title ?? 'Insecure Data Storage',
    description: r.description,
    severity: normaliseSeverity(r.severity ?? r.riskLevel ?? r.dataType),
    file_path: r.filePath ?? r.file_path ?? r.file,
    line_number: r.lineNumber ?? r.line_number ?? r.line,
    code_snippet: r.codeSnippet ?? r.code_snippet,
  }));
}

// Normalise IIV/IVS findings (Insufficient Input Validation → module 'IVS')
function normaliseIiv(raw: any[]): RawFinding[] {
  return raw.map(r => ({
    module: 'IVS',
    rule_id: r.ruleId ?? r.rule_id ?? r.code,
    title: r.message ?? r.title ?? 'Insufficient Input Validation',
    description: r.description,
    severity: normaliseSeverity(r.severity ?? r.riskLevel),
    file_path: r.filePath ?? r.file_path ?? r.file,
    line_number: r.lineNumber ?? r.line_number ?? r.line,
    code_snippet: r.codeSnippet ?? r.code_snippet,
  }));
}

function normaliseSeverity(raw: string | undefined): Severity {
  const s = (raw ?? '').toLowerCase();
  if (s === 'critical') { return 'critical'; }
  if (s === 'high') { return 'high'; }
  if (s === 'medium' || s === 'med') { return 'medium'; }
  return 'low';
}

// ─── Main upload ──────────────────────────────────────────────────────────────

export async function uploadFindings(context: vscode.ExtensionContext) {
  const folders = vscode.workspace.workspaceFolders;
  if (!folders || folders.length === 0) {
    vscode.window.showWarningMessage('FLUSEC: No workspace folders open.');
    return;
  }

  // Check auth
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
    { location: vscode.ProgressLocation.Notification, title: 'FLUSEC: Syncing findings to team…', cancellable: false },
    async (progress) => {
      for (const folder of folders) {
        // Read all component findings files
        const hsdRaw = readJsonArray(hsdFindingsPathForFolder(folder));
        const netRaw = readJsonArray(netFindingsPathForFolder(folder));
        const idsRaw = readJsonArray(idsFindingsPathForFolder(folder));
        const iivRaw = readJsonArray(iivFindingsPathForFolder(folder));

        // Normalise to unified format (IIV → IVS module)
        const findings: RawFinding[] = [
          ...normaliseHsd(hsdRaw),
          ...normaliseNet(netRaw),
          ...normaliseIds(idsRaw),
          ...normaliseIiv(iivRaw),
        ];

        if (findings.length === 0) {
          progress.report({ message: `${folder.name}: no findings to sync` });
          continue;
        }

        progress.report({ message: `Uploading ${findings.length} findings from ${folder.name}…` });

        try {
          const res = await fetch(`${endpoint}/api/findings/upload`, {
            method: 'POST',
            headers: {
              'Content-Type': 'application/json',
              'Authorization': `Bearer ${token}`,
            },
            body: JSON.stringify({
              team_id: teamId,
              scanned_file: folder.name,
              findings,
            }),
          });

          if (!res.ok) {
            const err = await res.json() as { error?: string };
            vscode.window.showWarningMessage(
              `FLUSEC: Upload failed for ${folder.name} — ${err.error ?? res.statusText}`
            );
            totalErrors++;
          } else {
            const result = await res.json() as { data: { findings_count: number } };
            totalUploaded += result.data.findings_count;
          }
        } catch (e) {
          vscode.window.showWarningMessage(`FLUSEC: Network error for ${folder.name} — ${String(e)}`);
          totalErrors++;
        }
      }
    }
  );

  if (totalErrors === 0) {
    vscode.window.showInformationMessage(
      `✅ FLUSEC: Synced ${totalUploaded} finding(s) to your team dashboard!`
    );
  } else {
    vscode.window.showWarningMessage(
      `FLUSEC: Sync completed with ${totalErrors} error(s). ${totalUploaded} finding(s) uploaded.`
    );
  }
}