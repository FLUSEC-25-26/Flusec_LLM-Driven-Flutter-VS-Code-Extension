import * as vscode from 'vscode';
import * as fs from 'node:fs';
import * as path from 'node:path';
import type { ActivePoliciesResponse } from './policyTypes.js';
import { CONFIG } from '../config.js';
import { authenticatedFetch, getSelectedTeam } from '../cloud/auth.js';

function policyCachePath(context: vscode.ExtensionContext, teamId: string): string {
  return path.join(context.globalStorageUri.fsPath, 'policies', teamId, 'active-policies.json');
}

function bundledPoliciesDir(context: vscode.ExtensionContext): string {
  return path.join(context.extensionUri.fsPath, 'resources', 'default-policies');
}

function workspacePolicyDir(workspaceRoot: string): string {
  return path.join(workspaceRoot, '.flusec', 'data');
}

function ensureArray(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

function ensureObject(value: unknown): Record<string, unknown> {
  return value && typeof value === 'object' && !Array.isArray(value)
    ? value as Record<string, unknown>
    : {};
}

function readCachedPolicies(
  context: vscode.ExtensionContext,
  teamId: string,
): ActivePoliciesResponse | null {
  try {
    const filePath = policyCachePath(context, teamId);
    if (!fs.existsSync(filePath)) { return null; }
    return JSON.parse(fs.readFileSync(filePath, 'utf8')) as ActivePoliciesResponse;
  } catch (error) {
    console.warn('[FLUSEC][policies] Failed to read team policy cache:', error);
    return null;
  }
}

function writeCachedPolicies(
  context: vscode.ExtensionContext,
  teamId: string,
  data: ActivePoliciesResponse,
): void {
  const filePath = policyCachePath(context, teamId);
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, JSON.stringify(data, null, 2), 'utf8');
}

export async function clearPolicyCache(context: vscode.ExtensionContext): Promise<void> {
  try {
    const team = await getSelectedTeam(context);
    if (!team) { return; }
    const filePath = policyCachePath(context, team.id);
    if (fs.existsSync(filePath)) { fs.unlinkSync(filePath); }
  } catch (error) {
    console.warn('[FLUSEC][policies] Failed to clear policy cache:', error);
  }
}

function ensureWorkspacePolicyDir(workspaceRoot: string): string {
  const directory = workspacePolicyDir(workspaceRoot);
  fs.mkdirSync(directory, { recursive: true });
  return directory;
}

function writeJsonFile(filePath: string, value: unknown): void {
  fs.writeFileSync(filePath, JSON.stringify(value, null, 2), 'utf8');
}

function writePoliciesToWorkspace(
  workspaceRoot: string,
  payload: ActivePoliciesResponse,
): void {
  const dataDir = ensureWorkspacePolicyDir(workspaceRoot);
  const { HSD: hsd, NET: net, IDS: ids, IIV: iiv } = payload.policies;

  // A missing/removed assignment becomes an empty component policy so stale
  // web rules cannot remain active after the next successful synchronization.
  writeJsonFile(path.join(dataDir, 'hardcoded_secrets_rules.json'), ensureArray(hsd?.rules_json));
  writeJsonFile(path.join(dataDir, 'hardcoded_secrets_heuristics.json'), ensureObject(hsd?.heuristics_json));
  writeJsonFile(path.join(dataDir, 'insecure_network_rules.json'), ensureArray(net?.rules_json));
  writeJsonFile(path.join(dataDir, 'insecure_data_storage_rules.json'), ensureArray(ids?.rules_json));
  writeJsonFile(path.join(dataDir, 'input_validation_rules.json'), ensureArray(iiv?.rules_json));
}

function copyBundledDefaultsToWorkspace(
  context: vscode.ExtensionContext,
  workspaceRoot: string,
): void {
  const sourceDir = bundledPoliciesDir(context);
  const targetDir = ensureWorkspacePolicyDir(workspaceRoot);
  const requiredFiles = [
    'hardcoded_secrets_rules.json',
    'hardcoded_secrets_heuristics.json',
    'insecure_network_rules.json',
    'insecure_data_storage_rules.json',
    'input_validation_rules.json',
  ];

  for (const fileName of requiredFiles) {
    const source = path.join(sourceDir, fileName);
    const destination = path.join(targetDir, fileName);
    if (!fs.existsSync(source)) {
      throw new Error(`Bundled default policy file not found: ${source}`);
    }
    fs.copyFileSync(source, destination);
  }
}

export async function fetchActivePolicies(
  context: vscode.ExtensionContext,
): Promise<ActivePoliciesResponse> {
  const team = await getSelectedTeam(context);
  if (!team) {
    throw new Error('No FLUSEC team is selected for this workspace.');
  }

  const endpoint = CONFIG.WEB_API_ENDPOINT.replace(/\/$/, '');
  if (!endpoint) { throw new Error('FLUSEC web API endpoint is not configured.'); }

  const url = `${endpoint}/api/v1/policies/active?team_id=${encodeURIComponent(team.id)}`;
  const response = await authenticatedFetch(context, url, {
    method: 'GET',
    headers: { Accept: 'application/json' },
  });

  const text = await response.text();
  let payload: { data?: ActivePoliciesResponse; error?: string } = {};
  try { payload = text ? JSON.parse(text) as typeof payload : {}; } catch { /* handled below */ };

  if (!response.ok) {
    throw new Error(payload.error ?? `Policy fetch failed (${response.status} ${response.statusText})`);
  }
  if (!payload.data?.team || !payload.data?.policies) {
    throw new Error('Invalid active policy response from FLUSEC API.');
  }
  if (payload.data.team.id !== team.id) {
    throw new Error('Policy response team does not match the selected workspace team.');
  }

  writeCachedPolicies(context, team.id, payload.data);
  return payload.data;
}

export async function syncPoliciesForWorkspace(
  context: vscode.ExtensionContext,
  workspaceRoot: string,
  opts?: {
    allowCachedFallback?: boolean
    silent?: boolean
    clearCacheBeforeSync?: boolean
  },
): Promise<void> {
  const team = await getSelectedTeam(context);

  if (opts?.clearCacheBeforeSync && team) {
    await clearPolicyCache(context);
  }

  try {
    const payload = await fetchActivePolicies(context);
    writePoliciesToWorkspace(workspaceRoot, payload);

    if (!opts?.silent) {
      vscode.window.showInformationMessage(`FLUSEC: Policies synced for ${payload.team.name}.`);
    }
    return;
  } catch (error) {
    console.warn('[FLUSEC][policies] Backend policy sync failed:', error);

    const cached = team && opts?.allowCachedFallback !== false
      ? readCachedPolicies(context, team.id)
      : null;

    if (cached) {
      writePoliciesToWorkspace(workspaceRoot, cached);
      if (!opts?.silent) {
        vscode.window.showWarningMessage(
          `FLUSEC: Could not reach the web platform. Using cached policies for ${cached.team.name}.`,
        );
      }
      return;
    }

    // No authenticated/team-specific cache is available. Bundled defaults are
    // the safe offline baseline and never borrow policy data from another team.
    copyBundledDefaultsToWorkspace(context, workspaceRoot);
    if (!opts?.silent) {
      const reason = team
        ? 'No cached team policy was available.'
        : 'No team is selected for this workspace.';
      vscode.window.showWarningMessage(`FLUSEC: Using bundled default policies. ${reason}`);
    }
  }
}

export async function syncPoliciesForAllWorkspaces(
  context: vscode.ExtensionContext,
  opts?: {
    allowCachedFallback?: boolean
    silent?: boolean
    clearCacheBeforeSync?: boolean
  },
): Promise<void> {
  const folders = vscode.workspace.workspaceFolders ?? [];
  if (folders.length === 0) {
    if (!opts?.silent) {
      vscode.window.showWarningMessage('FLUSEC: No workspace folder is open.');
    }
    return;
  }

  for (const folder of folders) {
    await syncPoliciesForWorkspace(context, folder.uri.fsPath, opts);
  }
}
