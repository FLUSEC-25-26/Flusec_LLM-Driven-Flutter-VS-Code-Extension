import * as vscode from 'vscode';
import { createHash } from 'node:crypto';
import * as path from 'node:path';

const LAST_EXPLICIT_SCAN_KEY = 'flusec.lastExplicitScan.v1';

export type ExplicitScanScope = 'file' | 'project'

export interface ExplicitScanContext {
  scope: ExplicitScanScope
  target: string
  workspaceUri: string
  recordedAt: number
}

type ExplicitScanMap = Record<string, ExplicitScanContext>

function normalizeSlashes(value: string): string {
  return value.replace(/\\/g, '/');
}

export function workspaceIdentity(folder: vscode.WorkspaceFolder): string {
  return createHash('sha256').update(folder.uri.toString()).digest('hex');
}

export function workspaceRelativePath(
  folder: vscode.WorkspaceFolder,
  absoluteOrRelativePath: string | undefined | null,
): string | null {
  if (!absoluteOrRelativePath) { return null; }

  const value = String(absoluteOrRelativePath).trim();
  if (!value) { return null; }

  if (!path.isAbsolute(value)) {
    return normalizeSlashes(value).replace(/^\.\//, '');
  }

  const relative = path.relative(folder.uri.fsPath, value);
  if (!relative || relative === '.') { return '.'; }
  if (!relative.startsWith('..') && !path.isAbsolute(relative)) {
    return normalizeSlashes(relative);
  }

  // A finding should normally be inside the workspace. If an analyzer returns
  // an external path, avoid uploading the developer's full machine path.
  return path.basename(value);
}

export async function recordExplicitScan(
  context: vscode.ExtensionContext,
  folder: vscode.WorkspaceFolder,
  scope: ExplicitScanScope,
  absoluteTarget: string,
): Promise<void> {
  const key = folder.uri.toString();
  const current = context.workspaceState.get<ExplicitScanMap>(LAST_EXPLICIT_SCAN_KEY, {});
  const next: ExplicitScanMap = {
    ...current,
    [key]: {
      scope,
      target: workspaceRelativePath(folder, absoluteTarget) ?? (scope === 'project' ? '.' : path.basename(absoluteTarget)),
      workspaceUri: key,
      recordedAt: Date.now(),
    },
  };
  await context.workspaceState.update(LAST_EXPLICIT_SCAN_KEY, next);
}

export function getLastExplicitScan(
  context: vscode.ExtensionContext,
  folder: vscode.WorkspaceFolder,
): ExplicitScanContext | undefined {
  const current = context.workspaceState.get<ExplicitScanMap>(LAST_EXPLICIT_SCAN_KEY, {});
  const scan = current[folder.uri.toString()];
  if (!scan) { return undefined; }

  // Explicit scan metadata is only a hint for the next sync. If it is very old,
  // default to the conservative file scope rather than resolving project-wide
  // findings from stale metadata.
  if (Date.now() - scan.recordedAt > 24 * 60 * 60 * 1000) { return undefined; }
  return scan;
}
