import * as vscode from "vscode";
import * as fs from "fs";
import * as path from "path";
import * as https from "https";

type HsdManifest = {
  component: "hsd";
  version: string;
  updated: string;
  files: { baseRules: string; heuristics: string };
};

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
  const v = cfg.get<string>("ruleRepoBaseUrl") ?? "";
  return v.trim().replace(/\/+$/, "");
}

export function hsdStoragePaths(context: vscode.ExtensionContext) {
  const root = path.join(context.globalStorageUri.fsPath, "rulepacks", "hsd");
  return {
    root,
    manifest: path.join(root, "manifest.json"),
    baseRules: path.join(root, "base_rules.json"),
    heuristics: path.join(root, "heuristics.json"),
    userRules: path.join(root, "user_rules.json"),
    lastCheck: path.join(root, ".lastCheck.json")
  };
}

function ensureUserRulesFile(p: string) {
  if (!fs.existsSync(p)) {writeAtomic(p, "[]\n");}
}

/**
 * Downloads base_rules.json + heuristics.json into globalStorage.
 * - Throttled: once per 12h unless force
 * - Safe offline: if download fails, keep cached copies
 */
export async function syncHsdRulePack(
  context: vscode.ExtensionContext,
  opts?: { force?: boolean }
) {
  const sp = hsdStoragePaths(context);
  fs.mkdirSync(sp.root, { recursive: true });
  ensureUserRulesFile(sp.userRules);

  const base = repoBaseUrl();
  console.log("[FLUSEC][rulepack] repoBaseUrl =", base || "<empty>");
  console.log("[FLUSEC][rulepack] storageRoot =", sp.root);

  if (!base) {
    console.log("[FLUSEC][rulepack] No base URL set -> skip download");
    return;
  }

  const now = Date.now();
  const last = readJson<{ t: number }>(sp.lastCheck)?.t ?? 0;
  const ageMs = now - last;
  console.log("[FLUSEC][rulepack] lastCheckAgeMs =", ageMs, "force =", !!opts?.force);

  if (!opts?.force && ageMs < 12 * 60 * 60 * 1000) {
    console.log("[FLUSEC][rulepack] Throttled (12h) -> skip");
    return;
  }

  let remote: any;
  try {
    const manifestUrl = `${base}/hsd/manifest.json`;
    console.log("[FLUSEC][rulepack] manifestUrl =", manifestUrl);
    remote = JSON.parse(await httpsGetText(manifestUrl));
  } catch (e) {
    console.error("[FLUSEC][rulepack] manifest download/parse FAILED:", e);
    return;
  }

  const local = readJson<any>(sp.manifest);
  const needs = opts?.force || !local || local.version !== remote.version;
  console.log("[FLUSEC][rulepack] localVersion =", local?.version, "remoteVersion =", remote?.version, "needs =", needs);

  if (!needs) {return;}

  try {
    const baseRulesUrl = `${base}/${remote.files.baseRules}`;
    const heuristicsUrl = `${base}/${remote.files.heuristics}`;
    console.log("[FLUSEC][rulepack] baseRulesUrl =", baseRulesUrl);
    console.log("[FLUSEC][rulepack] heuristicsUrl =", heuristicsUrl);

    const baseRulesTxt = await httpsGetText(baseRulesUrl);
    const heuristicsTxt = await httpsGetText(heuristicsUrl);

    writeAtomic(sp.baseRules, baseRulesTxt);
    writeAtomic(sp.heuristics, heuristicsTxt);
    writeAtomic(sp.manifest, JSON.stringify(remote, null, 2));

    // ✅ Write lastCheck ONLY after success
    writeAtomic(sp.lastCheck, JSON.stringify({ t: now }, null, 2));

    console.log("[FLUSEC][rulepack] Download OK. Saved to:", sp.baseRules, sp.heuristics);
  } catch (e) {
    console.error("[FLUSEC][rulepack] baseRules/heuristics download FAILED:", e);
  }
}


/**
 * Writes effective files into:
 * <workspace>/dart-analyzer/data/
 * so the Dart analyzer can load them via RulesPathResolver.
 */
export function writeHsdWorkspaceData(
  context: vscode.ExtensionContext,
  workspaceFolderFsPath: string
) {
  const sp = hsdStoragePaths(context);
  ensureUserRulesFile(sp.userRules);

  const baseRules = readJson<any[]>(sp.baseRules) ?? [];
  const userRules = readJson<any[]>(sp.userRules) ?? [];
  const heuristics = readJson<any>(sp.heuristics) ?? null;

  console.log("[FLUSEC][rules] baseRules =", baseRules.length, "userRules =", userRules.length);
  console.log("[FLUSEC][rules] globalStorage paths:", sp.baseRules, sp.userRules, sp.heuristics);

  // priority: user rules first, then base rules
  const effectiveRules = ([] as any[]).concat(userRules, baseRules);

  const dataDir = path.join(workspaceFolderFsPath, "dart-analyzer", "data");
  fs.mkdirSync(dataDir, { recursive: true });

  const rulesOut = path.join(dataDir, "hardcoded_secrets_rules.json");
  const heurOut  = path.join(dataDir, "hardcoded_secrets_heuristics.json");

  console.log("[FLUSEC][rules] writing workspace rules to:", rulesOut);
  console.log("[FLUSEC][rules] writing workspace heuristics to:", heurOut);

  writeAtomic(rulesOut, JSON.stringify(effectiveRules, null, 2));
  writeAtomic(heurOut, JSON.stringify(heuristics ?? {}, null, 2));
}

