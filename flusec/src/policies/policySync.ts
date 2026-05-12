import * as vscode from "vscode";
import * as fs from "fs";
import * as path from "path";
import type { ActivePoliciesResponse } from "./policyTypes.js";
import { CONFIG } from "../config";

// -----------------------------------------------------------------------------
// IMPORTANT:
// Keep these aligned with your existing extension login/session storage.
// These key names are used by the login flow.
// -----------------------------------------------------------------------------
const TOKEN_SECRET_KEY = "flusec.jwt";
const TEAM_ID_SECRET_KEY = "flusec.teamId";

// -----------------------------------------------------------------------------
// Paths
// -----------------------------------------------------------------------------

function policyCachePath(context: vscode.ExtensionContext): string {
  return path.join(
    context.globalStorageUri.fsPath,
    "policies",
    "active-policies.json"
  );
}

function bundledPoliciesDir(context: vscode.ExtensionContext): string {
  return path.join(
    context.extensionUri.fsPath,
    "resources",
    "default-policies"
  );
}

function workspacePolicyDir(workspaceRoot: string): string {
  return path.join(workspaceRoot, ".flusec", "data");
}

// -----------------------------------------------------------------------------
// Session helpers
// -----------------------------------------------------------------------------

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

// -----------------------------------------------------------------------------
// Safe JSON helpers
// -----------------------------------------------------------------------------

function ensureArray(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [];
}

function ensureObject(value: unknown): Record<string, unknown> {
  return value && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : {};
}

// -----------------------------------------------------------------------------
// Cache helpers
// -----------------------------------------------------------------------------

function readCachedPolicies(
  context: vscode.ExtensionContext
): ActivePoliciesResponse | null {
  try {
    const p = policyCachePath(context);

    if (!fs.existsSync(p)) {
      return null;
    }

    const raw = fs.readFileSync(p, "utf8");
    return JSON.parse(raw) as ActivePoliciesResponse;
  } catch (err) {
    console.warn("[FLUSEC][policies] failed to read policy cache:", err);
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

export function clearPolicyCache(context: vscode.ExtensionContext): void {
  try {
    const p = policyCachePath(context);

    if (fs.existsSync(p)) {
      fs.unlinkSync(p);
      console.log("[FLUSEC][policies] local policy cache cleared:", p);
    }
  } catch (err) {
    console.warn("[FLUSEC][policies] failed to clear policy cache:", err);
  }
}

// -----------------------------------------------------------------------------
// Workspace write helpers
// -----------------------------------------------------------------------------

function ensureWorkspacePolicyDir(workspaceRoot: string): string {
  const dir = workspacePolicyDir(workspaceRoot);
  fs.mkdirSync(dir, { recursive: true });
  return dir;
}

function writeJsonFile(filePath: string, value: unknown): void {
  fs.writeFileSync(filePath, JSON.stringify(value, null, 2), "utf8");
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

  // If a policy component is deleted or not assigned in the web app,
  // backend should return null for that component.
  // In that case, write an empty rule file instead of keeping old rules.
  writeJsonFile(
    path.join(dataDir, "hardcoded_secrets_rules.json"),
    ensureArray(hsd?.rules_json)
  );

  writeJsonFile(
    path.join(dataDir, "hardcoded_secrets_heuristics.json"),
    ensureObject(hsd?.heuristics_json)
  );

  writeJsonFile(
    path.join(dataDir, "insecure_network_rules.json"),
    ensureArray(net?.rules_json)
  );

  writeJsonFile(
    path.join(dataDir, "insecure_data_storage_rules.json"),
    ensureArray(ids?.rules_json)
  );

  writeJsonFile(
    path.join(dataDir, "input_validation_rules.json"),
    ensureArray(iiv?.rules_json)
  );

  console.log("[FLUSEC][policies] workspace policy files updated:", dataDir);
}

// -----------------------------------------------------------------------------
// Bundled fallback helpers
// -----------------------------------------------------------------------------

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

  console.log(
    "[FLUSEC][policies] bundled default policies copied to workspace:",
    targetDir
  );
}

// -----------------------------------------------------------------------------
// Backend sync
// -----------------------------------------------------------------------------

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

  const endpoint = CONFIG.WEB_API_ENDPOINT.replace(/\/$/, "");

  if (!endpoint || endpoint.includes("localhost")) {
    throw new Error(
      `FLUSEC: Invalid backend endpoint for deployed sync: ${endpoint}`
    );
  }

  const url = `${endpoint}/api/policies/active?team_id=${encodeURIComponent(
    teamId
  )}`;

  console.log("[FLUSEC][policies] syncing from backend:", url);

  const res = await fetch(url, {
    method: "GET",
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: "application/json",
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

  const json = (await res.json()) as { data?: ActivePoliciesResponse };

  if (!json?.data?.team || !json?.data?.policies) {
    throw new Error("Invalid active policy response from backend.");
  }

  writeCachedPolicies(context, json.data);

  console.log("[FLUSEC][policies] backend sync successful:", {
    teamId: json.data.team.id,
    teamName: json.data.team.name,
    hsdRules: ensureArray(json.data.policies.HSD?.rules_json).length,
    netRules: ensureArray(json.data.policies.NET?.rules_json).length,
    idsRules: ensureArray(json.data.policies.IDS?.rules_json).length,
    iivRules: ensureArray(json.data.policies.IIV?.rules_json).length,
  });

  return json.data;
}

// -----------------------------------------------------------------------------
// Public sync functions
// -----------------------------------------------------------------------------

export async function syncPoliciesForWorkspace(
  context: vscode.ExtensionContext,
  workspaceRoot: string,
  opts?: {
    allowCachedFallback?: boolean;
    silent?: boolean;
    clearCacheBeforeSync?: boolean;
  }
): Promise<void> {
  if (opts?.clearCacheBeforeSync) {
    clearPolicyCache(context);
  }

  try {
    const payload = await fetchActivePolicies(context);

    // Important:
    // This replaces the workspace policy JSON files with the backend response.
    // Deleted web rules will disappear if backend no longer returns them.
    writePoliciesToWorkspace(workspaceRoot, payload);

    if (!opts?.silent) {
      vscode.window.showInformationMessage(
        "FLUSEC: Policies synced from web app."
      );
    }

    console.log("[FLUSEC][policies] synced from backend ->", workspaceRoot);
    return;
  } catch (err) {
    console.error("[FLUSEC][policies] backend sync failed:", err);

    const cached =
      opts?.allowCachedFallback !== false ? readCachedPolicies(context) : null;

    if (cached) {
      writePoliciesToWorkspace(workspaceRoot, cached);

      console.warn(
        "[FLUSEC][policies] backend sync failed, using cached policies:",
        err
      );

      if (!opts?.silent) {
        vscode.window.showWarningMessage(
          "FLUSEC: Backend policy sync failed. Using cached policies, so recent web app changes may not appear."
        );
      }

      return;
    }

    // Final offline fallback:
    // Only use bundled defaults if backend and cache are both unavailable.
    copyBundledDefaultsToWorkspace(context, workspaceRoot);

    console.warn(
      "[FLUSEC][policies] backend/cache unavailable, using bundled default policies:",
      err
    );

    if (!opts?.silent) {
      vscode.window.showWarningMessage(
        "FLUSEC: Backend policy sync failed and no cache was found. Using bundled default policies."
      );
    }
  }
}

export async function syncPoliciesForAllWorkspaces(
  context: vscode.ExtensionContext,
  opts?: {
    allowCachedFallback?: boolean;
    silent?: boolean;
    clearCacheBeforeSync?: boolean;
  }
): Promise<void> {
  const folders = vscode.workspace.workspaceFolders ?? [];

  if (folders.length === 0) {
    if (!opts?.silent) {
      vscode.window.showWarningMessage(
        "FLUSEC: No workspace folder is open. Open a Flutter project and try again."
      );
    }
    return;
  }

  for (const folder of folders) {
    await syncPoliciesForWorkspace(context, folder.uri.fsPath, opts);
  }
}