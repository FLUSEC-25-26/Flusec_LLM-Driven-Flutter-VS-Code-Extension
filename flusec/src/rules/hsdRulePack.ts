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

const DEFAULT_RULEPACK_BASE_URL =
  "https://raw.githubusercontent.com/FLUSEC-25-26/flusec-rulepacks/main";

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
  const base = v.length ? v : DEFAULT_RULEPACK_BASE_URL;
  return base.replace(/\/+$/, "");
}

export function hsdStoragePaths(context: vscode.ExtensionContext) {
  const root = path.join(context.globalStorageUri.fsPath, "rulepacks", "hsd");
  return {
    root,
    manifest: path.join(root, "manifest.json"),
    baseRules: path.join(root, "base_rules.json"),
    heuristics: path.join(root, "heuristics.json"),
    userRules: path.join(root, "user_rules.json"),
    lastCheck: path.join(root, ".lastCheck.json"),
  };
}

function ensureJsonArrayFile(p: string) {
  if (!fs.existsSync(p)) {writeAtomic(p, "[]\n");}
}

function bundledHsdPaths(context: vscode.ExtensionContext) {
  const base = path.join(context.extensionPath, "resources", "rulepacks", "hsd");
  return {
    baseRules: path.join(base, "base_rules.json"),
    heuristics: path.join(base, "heuristics.json"),
    manifest: path.join(base, "manifest.json"),
  };
}

function bootstrapCacheFromBundled(context: vscode.ExtensionContext) {
  const sp = hsdStoragePaths(context);
  const bundled = bundledHsdPaths(context);

  const cachedRules = readJson<any[]>(sp.baseRules);
  if (!cachedRules || cachedRules.length === 0) {
    if (fs.existsSync(bundled.baseRules)) {
      const txt = fs.readFileSync(bundled.baseRules, "utf8");
      writeAtomic(sp.baseRules, txt);
      console.log("[FLUSEC][rulepack] Bootstrapped cached base_rules from bundled baseline.");
    } else {
      console.warn("[FLUSEC][rulepack] Missing bundled base_rules.json:", bundled.baseRules);
    }
  }

  const cachedHeur = readJson<any>(sp.heuristics);
  const isEmptyObj =
    !cachedHeur || (typeof cachedHeur === "object" && Object.keys(cachedHeur).length === 0);

  if (isEmptyObj) {
    if (fs.existsSync(bundled.heuristics)) {
      const txt = fs.readFileSync(bundled.heuristics, "utf8");
      writeAtomic(sp.heuristics, txt);
      console.log("[FLUSEC][rulepack] Bootstrapped cached heuristics from bundled baseline.");
    } else {
      console.warn("[FLUSEC][rulepack] Missing bundled heuristics.json:", bundled.heuristics);
    }
  }
}

export async function syncHsdRulePack(
  context: vscode.ExtensionContext,
  opts?: { force?: boolean }
) {
  const sp = hsdStoragePaths(context);
  fs.mkdirSync(sp.root, { recursive: true });
  ensureJsonArrayFile(sp.userRules);

  bootstrapCacheFromBundled(context);

  const base = repoBaseUrl();
  console.log("[FLUSEC][rulepack] repoBaseUrl =", base || "<empty>");
  console.log("[FLUSEC][rulepack] storageRoot =", sp.root);

  const now = Date.now();
  const last = readJson<{ t: number }>(sp.lastCheck)?.t ?? 0;
  const ageMs = now - last;

  if (!opts?.force && ageMs < 12 * 60 * 60 * 1000) {
    console.log("[FLUSEC][rulepack] Throttled (12h) -> skip");
    return;
  }

  let remote: HsdManifest;
  try {
    const manifestUrl = `${base}/hsd/manifest.json`;
    console.log("[FLUSEC][rulepack] manifestUrl =", manifestUrl);
    remote = JSON.parse(await httpsGetText(manifestUrl)) as HsdManifest;
  } catch (e) {
    console.error("[FLUSEC][rulepack] manifest download/parse FAILED:", e);
    return;
  }

  const local = readJson<HsdManifest>(sp.manifest);
  const needs = opts?.force || !local || local.version !== remote.version;

  console.log(
    "[FLUSEC][rulepack] localVersion =",
    local?.version,
    "remoteVersion =",
    remote.version,
    "needs =",
    needs
  );

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

    writeAtomic(sp.lastCheck, JSON.stringify({ t: now }, null, 2));

    console.log("[FLUSEC][rulepack] Download OK. Cached updated files.");
  } catch (e) {
    console.error("[FLUSEC][rulepack] baseRules/heuristics download FAILED:", e);
  }
}

export function hsdWorkspaceRoot(workspaceFolderFsPath: string) {
  return path.join(workspaceFolderFsPath, ".flusec");
}



export function writeHsdWorkspaceData(
  context: vscode.ExtensionContext,
  workspaceFolderFsPath: string
) {
  const sp = hsdStoragePaths(context);
  ensureJsonArrayFile(sp.userRules);

  bootstrapCacheFromBundled(context);

  const baseRules = readJson<any[]>(sp.baseRules) ?? [];
  const globalUserRules = readJson<any[]>(sp.userRules) ?? [];
  const heuristics = readJson<any>(sp.heuristics) ?? {};

  

  console.log(
    "[FLUSEC][rules] base=",
    baseRules.length,
    "globalUser=",
    globalUserRules.length
  );

  const effectiveRules = ([] as any[]).concat(globalUserRules, baseRules);

  const dataDir = path.join(hsdWorkspaceRoot(workspaceFolderFsPath), "data");
  fs.mkdirSync(dataDir, { recursive: true });

  const rulesOut = path.join(dataDir, "hardcoded_secrets_rules.json");
  const heurOut = path.join(dataDir, "hardcoded_secrets_heuristics.json");

  console.log("[FLUSEC][rules] writing rules ->", rulesOut);
  console.log("[FLUSEC][rules] writing heuristics ->", heurOut);

  writeAtomic(rulesOut, JSON.stringify(effectiveRules, null, 2));
  writeAtomic(heurOut, JSON.stringify(heuristics ?? {}, null, 2));
}
