import * as vscode from "vscode";
import * as fs from "fs";
import * as path from "path";
import type { ActivePoliciesResponse } from "./policyTypes.js";

// -----------------------------------------------------------------------------
// IMPORTANT:
// Keep these aligned with your existing extension login/session storage.
// These key names were already working in your current flow.
// -----------------------------------------------------------------------------
const TOKEN_SECRET_KEY = "flusec.jwt";
const TEAM_ID_SECRET_KEY = "flusec.teamId";

function policyCachePath(context: vscode.ExtensionContext): string {
  return path.join(
    context.globalStorageUri.fsPath,
    "policies",
    "active-policies.json"
  );
}

function bundledPoliciesDir(context: vscode.ExtensionContext): string {
  return path.join(context.extensionUri.fsPath, "resources", "default-policies");
}

function workspacePolicyDir(workspaceRoot: string): string {
  return path.join(workspaceRoot, ".flusec", "data");
}

async function getStoredToken(
  context: vscode.ExtensionContext
): Promise<string | undefined> {
  return context.secrets.get(TOKEN_SECRET_KEY);
}

async function getStoredTeamId(
  context: vscode.ExtensionContext
): Promise<string | undefined> {
  return context.secrets.get(TEAM_ID_SECRET_KEY);
}

function ensureArray(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

function ensureObject(value: unknown): Record<string, unknown> {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {};
}

function readCachedPolicies(
  context: vscode.ExtensionContext
): ActivePoliciesResponse | null {
  try {
    const p = policyCachePath(context);
    if (!fs.existsSync(p)) {return null;}
    const raw = fs.readFileSync(p, "utf8");
    return JSON.parse(raw) as ActivePoliciesResponse;
  } catch {
    return null;
  }
}

function writeCachedPolicies(
  context: vscode.ExtensionContext,
  data: ActivePoliciesResponse
): void {
  const p = policyCachePath(context);
  fs.mkdirSync(path.dirname(p), { recursive: true });
  fs.writeFileSync(p, JSON.stringify(data, null, 2), "utf8");
}

function ensureWorkspacePolicyDir(workspaceRoot: string): string {
  const dir = workspacePolicyDir(workspaceRoot);
  fs.mkdirSync(dir, { recursive: true });
  return dir;
}

function writePoliciesToWorkspace(
  workspaceRoot: string,
  payload: ActivePoliciesResponse
): void {
  const dataDir = ensureWorkspacePolicyDir(workspaceRoot);

  const hsd = payload.policies.HSD;
  const net = payload.policies.NET;
  const ids = payload.policies.IDS;
  const iiv = payload.policies.IIV;

  fs.writeFileSync(
    path.join(dataDir, "hardcoded_secrets_rules.json"),
    JSON.stringify(ensureArray(hsd?.rules_json), null, 2),
    "utf8"
  );

  fs.writeFileSync(
    path.join(dataDir, "hardcoded_secrets_heuristics.json"),
    JSON.stringify(ensureObject(hsd?.heuristics_json), null, 2),
    "utf8"
  );

  fs.writeFileSync(
    path.join(dataDir, "insecure_network_rules.json"),
    JSON.stringify(ensureArray(net?.rules_json), null, 2),
    "utf8"
  );

  fs.writeFileSync(
    path.join(dataDir, "insecure_data_storage_rules.json"),
    JSON.stringify(ensureArray(ids?.rules_json), null, 2),
    "utf8"
  );

  fs.writeFileSync(
    path.join(dataDir, "input_validation_rules.json"),
    JSON.stringify(ensureArray(iiv?.rules_json), null, 2),
    "utf8"
  );
}

function copyBundledDefaultsToWorkspace(
  context: vscode.ExtensionContext,
  workspaceRoot: string
): void {
  const sourceDir = bundledPoliciesDir(context);
  const targetDir = ensureWorkspacePolicyDir(workspaceRoot);

  const requiredFiles = [
    "hardcoded_secrets_rules.json",
    "hardcoded_secrets_heuristics.json",
    "insecure_network_rules.json",
    "insecure_data_storage_rules.json",
    "input_validation_rules.json",
  ];

  for (const fileName of requiredFiles) {
    const src = path.join(sourceDir, fileName);
    const dest = path.join(targetDir, fileName);

    if (!fs.existsSync(src)) {
      throw new Error(`Bundled default policy file not found: ${src}`);
    }

    fs.copyFileSync(src, dest);
  }
}

export async function fetchActivePolicies(
  context: vscode.ExtensionContext
): Promise<ActivePoliciesResponse> {
  const token = await getStoredToken(context);
  const teamId = await getStoredTeamId(context);

  if (!token || !teamId) {
    throw new Error(
      'FLUSEC: Missing login session. Please run "FluSec: Login to Team" first.'
    );
  }

  const config = vscode.workspace.getConfiguration("flusec");
  const endpoint = (
    config.get<string>("webApiEndpoint") ?? "http://localhost:3001"
  ).replace(/\/$/, "");
  const url = `${endpoint}/api/policies/active?team_id=${encodeURIComponent(
    teamId
  )}`;

  const res = await fetch(url, {
    method: "GET",
    headers: {
      Authorization: `Bearer ${token}`,
    },
  });

  if (!res.ok) {
    const text = await res.text().catch(() => "");
    throw new Error(
      `Policy fetch failed (${res.status} ${res.statusText})${
        text ? `: ${text}` : ""
      }`
    );
  }

  const json = (await res.json()) as { data: ActivePoliciesResponse };

  if (!json?.data?.policies) {
    throw new Error("Invalid active policy response from backend.");
  }

  writeCachedPolicies(context, json.data);
  return json.data;
}

export async function syncPoliciesForWorkspace(
  context: vscode.ExtensionContext,
  workspaceRoot: string,
  opts?: { allowCachedFallback?: boolean; silent?: boolean }
): Promise<void> {
  try {
    const payload = await fetchActivePolicies(context);
    writePoliciesToWorkspace(workspaceRoot, payload);

    if (!opts?.silent) {
      console.log("[FLUSEC][policies] synced from backend ->", workspaceRoot);
    }
    return;
  } catch (err) {
    const cached =
      opts?.allowCachedFallback !== false ? readCachedPolicies(context) : null;

    if (cached) {
      writePoliciesToWorkspace(workspaceRoot, cached);
      console.warn(
        "[FLUSEC][policies] backend sync failed, using cached policies:",
        err
      );
      return;
    }

    // Final offline fallback: bundled default policies packaged with the extension
    copyBundledDefaultsToWorkspace(context, workspaceRoot);
    console.warn(
      "[FLUSEC][policies] backend/cache unavailable, using bundled default policies:",
      err
    );
  }
}

export async function syncPoliciesForAllWorkspaces(
  context: vscode.ExtensionContext,
  opts?: { allowCachedFallback?: boolean; silent?: boolean }
): Promise<void> {
  const folders = vscode.workspace.workspaceFolders ?? [];
  for (const folder of folders) {
    await syncPoliciesForWorkspace(context, folder.uri.fsPath, opts);
  }
}