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

  const now = Date.now();
  const last = readJson<{ t: number }>(sp.lastCheck)?.t ?? 0;
  if (!opts?.force && now - last < 12 * 60 * 60 * 1000) {return;}
  writeAtomic(sp.lastCheck, JSON.stringify({ t: now }, null, 2));

  const base = repoBaseUrl();
  if (!base) {return;}

  let remote: HsdManifest;
  try {
    remote = JSON.parse(await httpsGetText(`${base}/hsd/manifest.json`)) as HsdManifest;
  } catch {
    return; // offline/bad URL -> ignore
  }

  const local = readJson<HsdManifest>(sp.manifest);
  const needs = opts?.force || !local || local.version !== remote.version;
  if (!needs) {return;}

  const baseRulesTxt = await httpsGetText(`${base}/${remote.files.baseRules}`);
  const heuristicsTxt = await httpsGetText(`${base}/${remote.files.heuristics}`);

  writeAtomic(sp.baseRules, baseRulesTxt);
  writeAtomic(sp.heuristics, heuristicsTxt);
  writeAtomic(sp.manifest, JSON.stringify(remote, null, 2));
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

  // priority: user rules first, then base rules
  const effectiveRules = ([] as any[]).concat(userRules, baseRules);

  const dataDir = path.join(workspaceFolderFsPath, "dart-analyzer", "data");
  fs.mkdirSync(dataDir, { recursive: true });

  writeAtomic(
    path.join(dataDir, "hardcoded_secrets_rules.json"),
    JSON.stringify(effectiveRules, null, 2)
  );

  writeAtomic(
    path.join(dataDir, "hardcoded_secrets_heuristics.json"),
    JSON.stringify(heuristics ?? {}, null, 2)
  );
}
