// src/net/couplingAnalysis.ts
//
// Network dependency coupling analysis for Flutter/Dart projects.
// Extracts HTTP/WebSocket endpoints from Dart source, maps them to services,
// computes outgoing/incoming coupling metrics, and a 0-100 health index.
//
// Project-scan behavior:
// - Prefer <workspace>/lib when it exists, matching FLUSEC's normal Flutter scan.
// - Fall back to the workspace root when lib/ does not exist.
// - Ignore generated/build/FLUSEC working folders.
// - Process open documents first so unsaved editor content is reflected.
// - Process remaining Dart files from disk so files do not need to be opened manually.

import * as vscode from "vscode";
import * as path from "path";

// ─── Types ──────────────────────────────────────────────────────────────────

export type ServiceConfig = {
  aliases?: Record<string, string[]>;
  ignoreHosts?: string[];
  normalizeHost?: Record<string, string>;
  redundancyServices?: string[];
};

export type CouplingPayload = {
  modules: string[];
  services: string[];
  cdOut: Record<string, number>;
  afferent: Record<string, number>;
  healthIndex?: number;
  healthComponents?: {
    riskOut: number;
    riskIn: number;
    riskRed: number;
    avgCdOut: number;
    avgAff: number;
    redundancyRatio: number;
  };
};

type AutoCall = {
  fromModule: string;
  toUrl: string;
  file: string;
  line?: number;
};

// ─── Service config (optional flusec.services.json in workspace root) ────────

export async function loadServiceConfig(): Promise<ServiceConfig | null> {
  const folders = vscode.workspace.workspaceFolders;
  if (!folders?.length) {
    return null;
  }

  const cfgUri = vscode.Uri.joinPath(folders[0].uri, "flusec.services.json");

  try {
    const buf = await vscode.workspace.fs.readFile(cfgUri);
    return JSON.parse(Buffer.from(buf).toString("utf8")) as ServiceConfig;
  } catch {
    return null;
  }
}

// ─── Endpoint extraction from Dart source ───────────────────────────────────

export function extractEndpointsFromDart(
  doc: vscode.TextDocument
): Array<{ url: string; line: number }> {
  const text = doc.getText();

  const patterns: RegExp[] = [
    /http\.(get|post|put|delete|patch)\s*\(\s*(['"])(https?:\/\/[^'"]+)\2/gi,
    /dio\.(get|post|put|delete|patch)\s*\(\s*(['"])(https?:\/\/[^'"]+)\2/gi,
    /Uri\.parse\(\s*(['"])(https?:\/\/[^'"]+)\1\s*\)/gi,
    /GraphQLClient\([^)]*endpoint:\s*(['"])(https?:\/\/[^'"]+)\1/gi,
    /WebSocketChannel\.connect\(\s*Uri\.parse\(\s*(['"])(wss?:\/\/[^'"]+)\1\s*\)\s*\)/gi,
  ];

  const out: Array<{ url: string; line: number }> = [];

  for (const rx of patterns) {
    for (const m of text.matchAll(rx)) {
      const url = (m[3] ?? m[2]) as string;
      const idx = m.index ?? 0;
      const line = doc.positionAt(idx).line + 1;

      if (url) {
        out.push({ url, line });
      }
    }
  }

  return out;
}

// ─── Service ID resolution ──────────────────────────────────────────────────

export function autoServiceId(urlStr: string): string | null {
  try {
    const u = new URL(urlStr);
    const host = u.hostname.toLowerCase();

    const normalizedHost = host
      .replace(/^api\./, "")
      .replace(/^svc\./, "");

    const seg =
      (u.pathname || "/").split("/").filter(Boolean)[0] || "";

    return seg ? `${normalizedHost}/${seg}` : normalizedHost;
  } catch {
    return null;
  }
}

export function resolveServiceIdFlexible(
  url: string,
  cfg?: ServiceConfig
): string | null {
  if (cfg) {
    try {
      const u = new URL(url);
      const host = u.hostname.toLowerCase();

      if (cfg.ignoreHosts?.includes(host)) {
        return null;
      }

      for (const [friendly, prefixes] of Object.entries(cfg.aliases ?? {})) {
        for (const p of prefixes) {
          if (url.startsWith(p)) {
            return friendly;
          }

          try {
            const phost = new URL(p).hostname.toLowerCase();
            if (host === phost) {
              return friendly;
            }
          } catch {
            // Ignore malformed configured prefixes.
          }
        }
      }

      const normHost = cfg.normalizeHost?.[host] ?? host;
      const seg =
        (u.pathname || "/").split("/").filter(Boolean)[0] || "";

      return seg ? `${normHost}/${seg}` : normHost;
    } catch {
      // Fall through to automatic service ID resolution.
    }
  }

  return autoServiceId(url);
}

// ─── Module inference from file path ────────────────────────────────────────

export function inferModuleFromPath(filePath: string): string {
  const norm = filePath.replace(/\\/g, "/").toLowerCase();

  const m = norm.match(/\/lib\/([^/]+)/);
  if (m?.[1]) {
    return m[1];
  }

  const m2 = norm.match(/\/(features|modules|src)\/([^/]+)/);
  if (m2?.[2]) {
    return m2[2];
  }

  return "app";
}

// ─── Project-scan scope helpers ─────────────────────────────────────────────

async function directoryExists(uri: vscode.Uri): Promise<boolean> {
  try {
    const stat = await vscode.workspace.fs.stat(uri);
    return (stat.type & vscode.FileType.Directory) !== 0;
  } catch {
    return false;
  }
}

/**
 * Match the scope used by the FLUSEC "Scan Entire Project" command:
 * - Flutter project: scan lib/
 * - Test/minimal workspace without lib/: scan workspace root
 */
async function resolveCouplingScanRoot(
  folder: vscode.WorkspaceFolder
): Promise<vscode.Uri> {
  const libUri = vscode.Uri.joinPath(folder.uri, "lib");

  if (await directoryExists(libUri)) {
    return libUri;
  }

  return folder.uri;
}

function isPathInside(basePath: string, candidatePath: string): boolean {
  const relative = path.relative(basePath, candidatePath);

  return (
    relative === "" ||
    (!relative.startsWith("..") && !path.isAbsolute(relative))
  );
}

function shouldIgnoreDartPath(filePath: string): boolean {
  const segments = filePath
    .replace(/\\/g, "/")
    .toLowerCase()
    .split("/")
    .filter(Boolean);

  return (
    segments.includes(".dart_tool") ||
    segments.includes("build") ||
    segments.includes(".flusec") ||
    segments.includes("generated")
  );
}

// ─── Build coupling graph ───────────────────────────────────────────────────

export function buildCouplingFromCalls(
  calls: AutoCall[],
  cfg?: ServiceConfig
): CouplingPayload {
  const services = new Set<string>();
  const modules = new Set<string>();
  const edgesOut: Record<string, Set<string>> = {};
  const edgesIn: Record<string, Set<string>> = {};

  for (const c of calls) {
    const toSvc = resolveServiceIdFlexible(c.toUrl, cfg);

    if (!toSvc) {
      continue;
    }

    const from = c.fromModule;

    if (!from || from === toSvc) {
      continue;
    }

    modules.add(from);
    services.add(toSvc);

    (edgesOut[from] ||= new Set()).add(toSvc);
    (edgesIn[toSvc] ||= new Set()).add(from);
  }

  const cdOut: Record<string, number> = {};
  const afferent: Record<string, number> = {};

  for (const m of modules) {
    cdOut[m] = edgesOut[m]?.size ?? 0;
  }

  for (const s of services) {
    afferent[s] = edgesIn[s]?.size ?? 0;
  }

  return {
    services: [...services],
    modules: [...modules],
    cdOut,
    afferent,
  };
}

// ─── Health index ───────────────────────────────────────────────────────────

function clamp100(n: number): number {
  return Math.max(0, Math.min(100, n));
}

export function computeHealthIndex(
  payload: CouplingPayload,
  opts?: {
    maxOut?: number;
    maxIn?: number;
    wOut?: number;
    wIn?: number;
    wRed?: number;
    redundancyServices?: string[];
  }
): {
  health: number;
  components: CouplingPayload["healthComponents"];
} {
  const maxOut = opts?.maxOut ?? 6;
  const maxIn = opts?.maxIn ?? 6;
  const wOut = opts?.wOut ?? 0.5;
  const wIn = opts?.wIn ?? 0.5;
  const wRed = opts?.wRed ?? 0.0;

  const outVals = (payload.modules ?? []).map(
    (m) => payload.cdOut?.[m] ?? 0
  );

  const inVals = (payload.services ?? []).map(
    (s) => payload.afferent?.[s] ?? 0
  );

  const avgCdOut = outVals.length
    ? outVals.reduce((a, b) => a + b, 0) / outVals.length
    : 0;

  const avgAff = inVals.length
    ? inVals.reduce((a, b) => a + b, 0) / inVals.length
    : 0;

  const riskOut = clamp100(
    (avgCdOut / Math.max(1, maxOut)) * 100
  );

  const riskIn = clamp100(
    (avgAff / Math.max(1, maxIn)) * 100
  );

  let redundancyRatio = 0;
  const declared = opts?.redundancyServices ?? [];

  if (declared.length && payload.services?.length) {
    const serviceSet = new Set(declared);
    const count = (payload.services ?? []).filter((s) =>
      serviceSet.has(s)
    ).length;

    redundancyRatio =
      clamp100((count / payload.services.length) * 100) / 100;
  }

  const riskRed = clamp100(100 - redundancyRatio * 100);
  const riskTotal = wOut * riskOut + wIn * riskIn + wRed * riskRed;
  const health = clamp100(100 - riskTotal);

  return {
    health,
    components: {
      riskOut,
      riskIn,
      riskRed,
      avgCdOut,
      avgAff,
      redundancyRatio,
    },
  };
}

// ─── Main: compute and post coupling data to webview panel ──────────────────

export async function computeAndPostCoupling(
  panel: vscode.WebviewPanel
): Promise<void> {
  const cfg =
    (await loadServiceConfig().catch(() => null)) ?? null;

  const calls: AutoCall[] = [];
  const seenFiles = new Set<string>();

  const folders = vscode.workspace.workspaceFolders;
  const folder = folders?.[0];

  // If a workspace exists, use the same scope as Scan Entire Project.
  // If not, we can still use currently open Dart documents.
  const scanRoot = folder
    ? await resolveCouplingScanRoot(folder)
    : undefined;

  // 1. Open documents first.
  // This preserves unsaved editor changes while avoiding files outside
  // the project-scan scope when a workspace folder is available.
  const dartDocs = vscode.workspace.textDocuments.filter((doc) => {
    if (doc.languageId !== "dart") {
      return false;
    }

    if (shouldIgnoreDartPath(doc.uri.fsPath)) {
      return false;
    }

    if (!scanRoot) {
      return true;
    }

    return isPathInside(scanRoot.fsPath, doc.uri.fsPath);
  });

  for (const doc of dartDocs) {
    seenFiles.add(path.normalize(doc.uri.fsPath));

    const endpoints = extractEndpointsFromDart(doc);
    const fromModule = inferModuleFromPath(doc.uri.fsPath);

    for (const ep of endpoints) {
      calls.push({
        fromModule,
        toUrl: ep.url,
        file: doc.uri.fsPath,
        line: ep.line,
      });
    }
  }

  // 2. Scan the remaining Dart files from disk.
  //
  // Old behavior always searched <workspace>/lib/**/*.dart.
  // That made coupling empty for test/minimal workspaces such as:
  //   D:\FLUSEC_TEST\net_manual_cases.dart
  // because those workspaces do not have a lib/ directory.
  //
  // New behavior:
  //   lib/ exists    -> scan lib/**/*.dart
  //   lib/ missing   -> scan <workspace>/**/*.dart
  if (scanRoot) {
    try {
      const dartFiles = await vscode.workspace.findFiles(
        new vscode.RelativePattern(scanRoot, "**/*.dart"),
        undefined,
        1000
      );

      let processedFromDisk = 0;

      for (const fileUri of dartFiles) {
        const normalizedPath = path.normalize(fileUri.fsPath);

        if (shouldIgnoreDartPath(fileUri.fsPath)) {
          continue;
        }

        // Skip files already processed from open documents.
        if (seenFiles.has(normalizedPath)) {
          continue;
        }

        seenFiles.add(normalizedPath);

        try {
          const doc = await vscode.workspace.openTextDocument(fileUri);
          const endpoints = extractEndpointsFromDart(doc);
          const fromModule = inferModuleFromPath(doc.uri.fsPath);

          for (const ep of endpoints) {
            calls.push({
              fromModule,
              toUrl: ep.url,
              file: doc.uri.fsPath,
              line: ep.line,
            });
          }

          processedFromDisk++;
        } catch (e) {
          console.warn(
            `[NET] Coupling: skipped unreadable Dart file ${fileUri.fsPath}:`,
            e
          );
        }
      }

      console.log(
        `[NET] Coupling scan root: ${scanRoot.fsPath}; ` +
        `open Dart files: ${dartDocs.length}; ` +
        `disk Dart files processed: ${processedFromDisk}; ` +
        `endpoint calls found: ${calls.length}`
      );
    } catch (e) {
      console.warn("[NET] Coupling project scan failed:", e);
    }
  }

  const graph = buildCouplingFromCalls(
    calls,
    cfg || undefined
  );

  const health = computeHealthIndex(graph, {
    maxOut: 6,
    maxIn: 6,
    wOut: 0.5,
    wIn: 0.5,
    wRed: 0.0,
    redundancyServices: cfg?.redundancyServices,
  });

  panel.webview.postMessage({
    type: "coupling-data",
    payload: {
      ...graph,
      healthIndex: health.health,
      healthComponents: health.components,
    },
  });
}
