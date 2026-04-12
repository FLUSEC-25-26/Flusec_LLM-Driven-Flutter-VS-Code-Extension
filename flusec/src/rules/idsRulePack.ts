// src/rules/idsRulePack.ts
//
// IDS (Insecure Data Storage) rulepack sync — mirrors netRulePack.ts pattern.
// Downloads rules from the rule repo under storage/ folder.
// Writes effective workspace rule file: insecure_data_storage_rules.json

import * as vscode from "vscode";
import * as fs from "fs";
import * as path from "path";

// ---------------------------------------------------------------------------
// Paths
// ---------------------------------------------------------------------------

export interface IdsStoragePaths {
  storageRoot: string;       // globalStorage/.../rulepacks/storage
  manifestJson: string;
  baseRulesJson: string;
}

export function idsStoragePaths(ctx: vscode.ExtensionContext): IdsStoragePaths {
  const root = path.join(
    ctx.globalStorageUri.fsPath,
    "rulepacks",
    "storage"
  );
  return {
    storageRoot: root,
    manifestJson: path.join(root, "manifest.json"),
    baseRulesJson: path.join(root, "base_rules.json"),
  };
}

// ---------------------------------------------------------------------------
// Throttle
// ---------------------------------------------------------------------------

let lastSyncMs = 0;
const THROTTLE_MS = 12 * 60 * 60 * 1000; // 12 hours

// ---------------------------------------------------------------------------
// Bootstrap from bundled fallback
// ---------------------------------------------------------------------------

function bootstrapCacheFromBundled(ctx: vscode.ExtensionContext): void {
  const sp = idsStoragePaths(ctx);
  if (fs.existsSync(sp.baseRulesJson)) {return;}

  const bundled = path.join(
    ctx.extensionUri.fsPath,
    "resources",
    "rulepacks",
    "storage",
    "base_rules.json"
  );

  if (fs.existsSync(bundled)) {
    fs.mkdirSync(sp.storageRoot, { recursive: true });
    fs.copyFileSync(bundled, sp.baseRulesJson);
    console.log("[FLUSEC][ids-rulepack] Bootstrapped from bundled base_rules.json");
  } else {
    console.log(`[FLUSEC][ids-rulepack] Missing bundled insecure_data_storage_rules.json: ${bundled}`);
  }
}

// ---------------------------------------------------------------------------
// Sync
// ---------------------------------------------------------------------------

export async function syncIdsRulePack(ctx: vscode.ExtensionContext): Promise<void> {
  bootstrapCacheFromBundled(ctx);

  const cfg = vscode.workspace.getConfiguration("flusec");
  const baseUrl: string = cfg.get<string>(
    "ruleRepoBaseUrl",
    "https://raw.githubusercontent.com/FLUSEC-25-26/flusec-rulepacks/main"
  );

  console.log("[FLUSEC][ids-rulepack] repoBaseUrl =", baseUrl);

  const sp = idsStoragePaths(ctx);
  console.log("[FLUSEC][ids-rulepack] storageRoot =", sp.storageRoot);

  // Throttle
  if (Date.now() - lastSyncMs < THROTTLE_MS) {
    console.log("[FLUSEC][ids-rulepack] Throttled (12h) -> skip");
    return;
  }

  const manifestUrl = `${baseUrl}/storage/manifest.json`;
  console.log("[FLUSEC][ids-rulepack] manifestUrl =", manifestUrl);

  try {
    const manifestRes = await fetch(manifestUrl);
    if (!manifestRes.ok) {
      console.error(`[FLUSEC][ids-rulepack] manifest ${manifestRes.status}`);
      return;
    }
    const manifest: any = await manifestRes.json();
    const remoteVersion: string = manifest.version ?? "0.0.0";

    let localVersion: string | undefined;
    if (fs.existsSync(sp.manifestJson)) {
      try {
        localVersion = JSON.parse(fs.readFileSync(sp.manifestJson, "utf8")).version;
      } catch { /* ignore */ }
    }

    console.log(
      `[FLUSEC][ids-rulepack] localVersion = ${localVersion} remoteVersion = ${remoteVersion} needs = ${localVersion !== remoteVersion}`
    );

    if (localVersion === remoteVersion) {
      lastSyncMs = Date.now();
      return;
    }

    // Download base_rules.json
    const baseRulesUrl = `${baseUrl}/storage/${manifest.files?.base_rules ?? "base_rules.json"}`;
    console.log("[FLUSEC][ids-rulepack] baseRulesUrl =", baseRulesUrl);

    const rulesRes = await fetch(baseRulesUrl);
    if (!rulesRes.ok) {
      console.error(`[FLUSEC][ids-rulepack] base_rules ${rulesRes.status}`);
      return;
    }
    const rulesText = await rulesRes.text();

    // Write to globalStorage cache
    fs.mkdirSync(sp.storageRoot, { recursive: true });
    fs.writeFileSync(sp.baseRulesJson, rulesText, "utf8");
    fs.writeFileSync(sp.manifestJson, JSON.stringify(manifest, null, 2), "utf8");

    lastSyncMs = Date.now();
    console.log("[FLUSEC][ids-rulepack] Download OK. Cached updated files.");
  } catch (e) {
    console.error("[FLUSEC][ids-rulepack] sync error:", e);
  }
}

// ---------------------------------------------------------------------------
// Write effective workspace rules
// ---------------------------------------------------------------------------

export function writeIdsWorkspaceData(
  ctx: vscode.ExtensionContext,
  workspaceRoot: string
): void {
  const sp = idsStoragePaths(ctx);
  const dataDir = path.join(workspaceRoot, ".flusec", "data");
  fs.mkdirSync(dataDir, { recursive: true });

  // IDS has no user-defined rules currently — just write base rules.
  let baseRules: any[] = [];
  if (fs.existsSync(sp.baseRulesJson)) {
    try {
      baseRules = JSON.parse(fs.readFileSync(sp.baseRulesJson, "utf8"));
      if (!Array.isArray(baseRules)) {baseRules = [];}
    } catch (e) {
      console.error("[FLUSEC][ids-rules] error reading base rules:", e);
      baseRules = [];
    }
  }

  console.log(`[FLUSEC][ids-rules] base= ${baseRules.length}`);

  const outPath = path.join(dataDir, "insecure_data_storage_rules.json");
  fs.writeFileSync(outPath, JSON.stringify(baseRules, null, 2), "utf8");
  console.log(`[FLUSEC][ids-rules] writing rules -> ${outPath}`);
}