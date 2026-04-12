// src/rules/iivRulePack.ts
//
// IIV (Insufficient Input Validation) rulepack sync — mirrors idsRulePack.ts pattern.
// Downloads rules from the rule repo under input_validation/ folder.
// Writes effective workspace rule file: input_validation_rules.json

import * as vscode from "vscode";
import * as fs from "fs";
import * as path from "path";

// ---------------------------------------------------------------------------
// Paths
// ---------------------------------------------------------------------------

export interface IivStoragePaths {
  storageRoot: string;       // globalStorage/.../rulepacks/input_validation
  manifestJson: string;
  baseRulesJson: string;
}

export function iivStoragePaths(ctx: vscode.ExtensionContext): IivStoragePaths {
  const root = path.join(
    ctx.globalStorageUri.fsPath,
    "rulepacks",
    "input_validation"
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
  const sp = iivStoragePaths(ctx);
  if (fs.existsSync(sp.baseRulesJson)) { return; }

  const bundled = path.join(
    ctx.extensionUri.fsPath,
    "resources",
    "rulepacks",
    "input_validation",
    "base_rules.json"
  );

  if (fs.existsSync(bundled)) {
    fs.mkdirSync(sp.storageRoot, { recursive: true });
    fs.copyFileSync(bundled, sp.baseRulesJson);
    console.log("[FLUSEC][iiv-rulepack] Bootstrapped from bundled base_rules.json");
  } else {
    console.log(`[FLUSEC][iiv-rulepack] Missing bundled input_validation_rules.json: ${bundled}`);
  }
}

// ---------------------------------------------------------------------------
// Sync
// ---------------------------------------------------------------------------

// 🔥 FIX: Added opts parameter to allow force overriding
export async function syncIivRulePack(
  ctx: vscode.ExtensionContext,
  opts?: { force?: boolean }
): Promise<void> {
  bootstrapCacheFromBundled(ctx);

  const cfg = vscode.workspace.getConfiguration("flusec");
  const baseUrl: string = cfg.get<string>(
    "ruleRepoBaseUrl",
    "https://raw.githubusercontent.com/FLUSEC-25-26/flusec-rulepacks/main"
  );

  console.log("[FLUSEC][iiv-rulepack] repoBaseUrl =", baseUrl);

  const sp = iivStoragePaths(ctx);
  console.log("[FLUSEC][iiv-rulepack] storageRoot =", sp.storageRoot);

  // 🔥 FIX: Bypass throttle if force is true
  if (!opts?.force && Date.now() - lastSyncMs < THROTTLE_MS) {
    console.log("[FLUSEC][iiv-rulepack] Throttled (12h) -> skip");
    return;
  }

  const manifestUrl = `${baseUrl}/input_validation/manifest.json`;
  console.log("[FLUSEC][iiv-rulepack] manifestUrl =", manifestUrl);

  try {
    const manifestRes = await fetch(manifestUrl);
    if (!manifestRes.ok) {
      console.error(`[FLUSEC][iiv-rulepack] manifest ${manifestRes.status}`);
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
      `[FLUSEC][iiv-rulepack] localVersion = ${localVersion} remoteVersion = ${remoteVersion} needs = ${localVersion !== remoteVersion}`
    );

    // 🔥 FIX: Bypass version check if force is true
    if (!opts?.force && localVersion === remoteVersion) {
      lastSyncMs = Date.now();
      return;
    }

    // Download base_rules.json
    const baseRulesUrl = `${baseUrl}/input_validation/${manifest.files?.base_rules ?? "base_rules.json"}`;
    console.log("[FLUSEC][iiv-rulepack] baseRulesUrl =", baseRulesUrl);

    const rulesRes = await fetch(baseRulesUrl);
    if (!rulesRes.ok) {
      console.error(`[FLUSEC][iiv-rulepack] base_rules ${rulesRes.status}`);
      return;
    }
    const rulesText = await rulesRes.text();

    // Write to globalStorage cache
    fs.mkdirSync(sp.storageRoot, { recursive: true });
    fs.writeFileSync(sp.baseRulesJson, rulesText, "utf8");
    fs.writeFileSync(sp.manifestJson, JSON.stringify(manifest, null, 2), "utf8");

    lastSyncMs = Date.now();
    console.log("[FLUSEC][iiv-rulepack] Download OK. Cached updated files.");
  } catch (e) {
    console.error("[FLUSEC][iiv-rulepack] sync error:", e);
  }
}

// ---------------------------------------------------------------------------
// Write effective workspace rules
// ---------------------------------------------------------------------------

export function writeIivWorkspaceData(
  ctx: vscode.ExtensionContext,
  workspaceRoot: string
): void {
  const sp = iivStoragePaths(ctx);
  const dataDir = path.join(workspaceRoot, ".flusec", "data");
  fs.mkdirSync(dataDir, { recursive: true });

  // IIV has no user-defined rules (rule manager removed) — just write base rules.
  let baseRules: any[] = [];
  if (fs.existsSync(sp.baseRulesJson)) {
    try {
      baseRules = JSON.parse(fs.readFileSync(sp.baseRulesJson, "utf8"));
      if (!Array.isArray(baseRules)) { baseRules = []; }
    } catch (e) {
      console.error("[FLUSEC][iiv-rules] error reading base rules:", e);
      baseRules = [];
    }
  }

  console.log(`[FLUSEC][iiv-rules] base= ${baseRules.length}`);

  const outPath = path.join(dataDir, "input_validation_rules.json");
  fs.writeFileSync(outPath, JSON.stringify(baseRules, null, 2), "utf8");
  console.log(`[FLUSEC][iiv-rules] writing rules -> ${outPath}`);
}