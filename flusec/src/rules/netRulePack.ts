// src/rules/netRulePack.ts
//
// Insecure Network Communication — rulepack sync & workspace writer.
// Follows the EXACT same pattern as hsdRulePack.ts.
//
// Flow:
// 1. bootstrapCacheFromBundled() → copies bundled baseline if cache empty
// 2. syncNetRulePack()           → downloads from GitHub rulepack repo
// 3. writeNetWorkspaceData()     → writes to <workspace>/.flusec/data/
// 4. Dart analyzer reads from    → <cwd>/data/insecure_network_rules.json

import * as vscode from "vscode";
import * as fs from "fs";
import * as path from "path";
import * as https from "https";

// ─── Types ───────────────────────────────────────────────────────────────────

type NetManifest = {
  component: "network";
  version: string;
  updated: string;
  files: { baseRules: string };
};

// ─── Shared helpers (same as hsdRulePack.ts) ─────────────────────────────────

function readJson<T>(p: string): T | null {
  try {
    if (!fs.existsSync(p)) {return null;}
    return JSON.parse(fs.readFileSync(p, "utf8")) as T;
  } catch {
    return null;
  }
}

function writeAtomic(p: string, content: string) {
  fs.mkdirSync(path.dirname(p), { recursive: true });
  const tmp = p + ".tmp";
  fs.writeFileSync(tmp, content, "utf8");
  fs.renameSync(tmp, p);
}

function httpsGetText(url: string): Promise<string> {
  return new Promise((resolve, reject) => {
    https
      .get(url, (res) => {
        if (!res.statusCode || res.statusCode >= 400) {
          reject(new Error(`HTTP ${res.statusCode} for ${url}`));
          return;
        }
        const chunks: Buffer[] = [];
        res.on("data", (d) => chunks.push(Buffer.isBuffer(d) ? d : Buffer.from(d)));
        res.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
      })
      .on("error", reject);
  });
}

function repoBaseUrl(): string {
  const cfg = vscode.workspace.getConfiguration("flusec");
  const v = (cfg.get<string>("ruleRepoBaseUrl") ?? "").trim();
  return v.replace(/\/+$/, "");
}

// ─── Storage paths ───────────────────────────────────────────────────────────

export function netStoragePaths(context: vscode.ExtensionContext) {
  const root = path.join(context.globalStorageUri.fsPath, "rulepacks", "network");
  return {
    root,
    manifest: path.join(root, "manifest.json"),
    baseRules: path.join(root, "base_rules.json"),
    lastCheck: path.join(root, ".lastCheck.json"),
  };
}

// ─── Bundled baseline ────────────────────────────────────────────────────────

function bundledNetPaths(context: vscode.ExtensionContext) {
  const base = path.join(context.extensionPath, "resources", "rulepacks", "network");
  return {
    baseRules: path.join(base, "base_rules.json"),
    manifest: path.join(base, "manifest.json"),
  };
}

function bootstrapCacheFromBundled(context: vscode.ExtensionContext) {
  const sp = netStoragePaths(context);
  const bundled = bundledNetPaths(context);

  const cachedRules = readJson<any[]>(sp.baseRules);
  if (!cachedRules || cachedRules.length === 0) {
    if (fs.existsSync(bundled.baseRules)) {
      const txt = fs.readFileSync(bundled.baseRules, "utf8");
      writeAtomic(sp.baseRules, txt);
      console.log("[FLUSEC][net-rulepack] Bootstrapped cached rules from bundled baseline.");
    } else {
      console.warn("[FLUSEC][net-rulepack] Missing bundled insecure_network_rules.json:", bundled.baseRules);
    }
  }
}

// ─── Sync from GitHub rulepack repo ──────────────────────────────────────────

/**
 * Downloads insecure_network_rules.json into globalStorage.
 * - Throttled: once per 12h unless force
 * - Safe offline: if download fails, keep cached copy
 */
export async function syncNetRulePack(
  context: vscode.ExtensionContext,
  opts?: { force?: boolean }
) {
  const sp = netStoragePaths(context);
  fs.mkdirSync(sp.root, { recursive: true });

  // Ensure we always have something usable even offline
  bootstrapCacheFromBundled(context);

  const base = repoBaseUrl();
  console.log("[FLUSEC][net-rulepack] repoBaseUrl =", base || "<empty>");
  console.log("[FLUSEC][net-rulepack] storageRoot =", sp.root);

  if (!base) {
    console.log("[FLUSEC][net-rulepack] No base URL -> skip download");
    return;
  }

  const now = Date.now();
  const last = readJson<{ t: number }>(sp.lastCheck)?.t ?? 0;
  const ageMs = now - last;

  if (!opts?.force && ageMs < 12 * 60 * 60 * 1000) {
    console.log("[FLUSEC][net-rulepack] Throttled (12h) -> skip");
    return;
  }

  let remote: NetManifest;
  try {
    const manifestUrl = `${base}/network/manifest.json`;
    console.log("[FLUSEC][net-rulepack] manifestUrl =", manifestUrl);
    remote = JSON.parse(await httpsGetText(manifestUrl)) as NetManifest;
  } catch (e) {
    console.error("[FLUSEC][net-rulepack] manifest download/parse FAILED:", e);
    return;
  }

  const local = readJson<NetManifest>(sp.manifest);
  const needs = opts?.force || !local || local.version !== remote.version;

  console.log(
    "[FLUSEC][net-rulepack] localVersion =",
    local?.version,
    "remoteVersion =",
    remote.version,
    "needs =",
    needs
  );

  if (!needs) {return;}

  try {
    const baseRulesUrl = `${base}/${remote.files.baseRules}`;
    console.log("[FLUSEC][net-rulepack] baseRulesUrl =", baseRulesUrl);

    const baseRulesTxt = await httpsGetText(baseRulesUrl);

    writeAtomic(sp.baseRules, baseRulesTxt);
    writeAtomic(sp.manifest, JSON.stringify(remote, null, 2));
    writeAtomic(sp.lastCheck, JSON.stringify({ t: now }, null, 2));

    console.log("[FLUSEC][net-rulepack] Download OK. Cached updated files.");
  } catch (e) {
    console.error("[FLUSEC][net-rulepack] rules download FAILED:", e);
  }
}

// ─── Write to workspace .flusec/data/ ────────────────────────────────────────

/**
 * Writes insecure_network_rules.json into:
 * <workspace>/.flusec/data/
 * so the Dart analyzer can load it via RulesPathResolver (cwd/data).
 *
 * Network component has NO user rules — only base rules from repo.
 */
export function writeNetWorkspaceData(
  context: vscode.ExtensionContext,
  workspaceFolderFsPath: string
) {
  const sp = netStoragePaths(context);

  bootstrapCacheFromBundled(context);

  const baseRules = readJson<any[]>(sp.baseRules) ?? [];

  console.log("[FLUSEC][net-rules] base=", baseRules.length);

  const dataDir = path.join(workspaceFolderFsPath, ".flusec", "data");
  fs.mkdirSync(dataDir, { recursive: true });

  const rulesOut = path.join(dataDir, "insecure_network_rules.json");

  console.log("[FLUSEC][net-rules] writing rules ->", rulesOut);

  writeAtomic(rulesOut, JSON.stringify(baseRules, null, 2));
}