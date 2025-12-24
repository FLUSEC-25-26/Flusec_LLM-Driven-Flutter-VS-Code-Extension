
import * as vscode from 'vscode';

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
    riskOut: number; riskIn: number; riskRed: number;
    avgCdOut: number; avgAff: number; redundancyRatio: number;
  };
};

type AutoCall = { fromModule: string; toUrl: string; file: string; line?: number };

export async function loadServiceConfig(): Promise<ServiceConfig | null> {
  const folders = vscode.workspace.workspaceFolders;
  if (!folders?.length) return null;
  const cfgUri = vscode.Uri.joinPath(folders[0].uri, 'flusec.services.json');
  try {
    const buf = await vscode.workspace.fs.readFile(cfgUri);
    return JSON.parse(Buffer.from(buf).toString('utf8')) as ServiceConfig;
  } catch { return null; }
}

export function extractEndpointsFromDart(doc: vscode.TextDocument): Array<{ url: string; line: number }> {
  const text = doc.getText();
  const patterns: RegExp[] = [
    /http\.(get|post|put|delete|patch)\s*\(\s*(['"])(https?:\/\/[^'"]+)\2/gi,
    /dio\.(get|post|put|delete|patch)\s*\(\s*(['"])(https?:\/\/[^'"]+)\2/gi,
    /Uri\.parse\(\s*(['"])(https?:\/\/[^'"]+)\1\s*\)/gi,
    // Optional extras:
    /GraphQLClient\([^)]*endpoint:\s*(['"])(https?:\/\/[^'"]+)\1/gi,
    /WebSocketChannel\.connect\(\s*Uri\.parse\(\s*(['"])(wss?:\/\/[^'"]+)\1\s*\)\s*\)/gi
  ];
  const out: Array<{ url: string; line: number }> = [];
  for (const rx of patterns) {
    for (const m of text.matchAll(rx)) {
      const url = (m[3] ?? m[2]) as string;
      const idx = m.index ?? 0;
      const line = doc.positionAt(idx).line + 1;
      if (url) out.push({ url, line });
    }
  }
  return out;
}

export function autoServiceId(urlStr: string): string | null {
  try {
    const u = new URL(urlStr);
    const host = u.hostname.toLowerCase();
    const normalizedHost = host.replace(/^api\./, '').replace(/^svc\./, '');
    const seg = (u.pathname || '/').split('/').filter(Boolean)[0] || '';
    return seg ? `${normalizedHost}/${seg}` : normalizedHost;
  } catch { return null; }
}

export function resolveServiceIdFlexible(url: string, cfg?: ServiceConfig): string | null {
  if (cfg) {
    try {
      const u = new URL(url);
      const host = u.hostname.toLowerCase();
      if (cfg.ignoreHosts?.includes(host)) return null;

      for (const [friendly, prefixes] of Object.entries(cfg.aliases ?? {})) {
        for (const p of prefixes) {
          if (url.startsWith(p)) return friendly;
          try {
            const phost = new URL(p).hostname.toLowerCase();
            if (host === phost) return friendly;
          } catch { /* ignore */ }
        }
      }

      const normHost = cfg.normalizeHost?.[host] ?? host;
      const seg = (u.pathname || '/').split('/').filter(Boolean)[0] || '';
      return seg ? `${normHost}/${seg}` : normHost;
    } catch { /* fall through */ }
  }
  return autoServiceId(url);
}

export function inferModuleFromPath(filePath: string): string {
  const norm = filePath.replace(/\\/g, '/').toLowerCase();
  const m = norm.match(/\/lib\/([^\/]+)/);
  if (m?.[1]) return m[1];
  const m2 = norm.match(/\/(features|modules|src)\/([^\/]+)/);
  if (m2?.[2]) return m2[2];
  return 'app';
}

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
    if (!toSvc) continue;
    const from = c.fromModule;
    if (!from || from === toSvc) continue;

    modules.add(from);
    services.add(toSvc);
    (edgesOut[from] ||= new Set()).add(toSvc);
    (edgesIn[toSvc] ||= new Set()).add(from);
  }

  const cdOut: Record<string, number> = {};
  const afferent: Record<string, number> = {};
  for (const m of modules) cdOut[m] = edgesOut[m]?.size ?? 0;
  for (const s of services) afferent[s] = edgesIn[s]?.size ?? 0;

  return { services: [...services], modules: [...modules], cdOut, afferent };
}

function clamp100(n: number): number {
  return Math.max(0, Math.min(100, n));
}

export function computeHealthIndex(
  payload: CouplingPayload,
  opts?: {
    maxOut?: number; maxIn?: number;
    wOut?: number; wIn?: number; wRed?: number;
    redundancyServices?: string[];
  }
): { health: number; components: CouplingPayload['healthComponents'] } {
  const maxOut = opts?.maxOut ?? 6;
  const maxIn  = opts?.maxIn  ?? 6;
  const wOut   = opts?.wOut   ?? 0.5;
  const wIn    = opts?.wIn    ?? 0.5;
  const wRed   = opts?.wRed   ?? 0.0;

  const outVals = (payload.modules ?? []).map(m => payload.cdOut?.[m] ?? 0);
  const inVals  = (payload.services ?? []).map(s => payload.afferent?.[s] ?? 0);

  const avgCdOut = outVals.length ? outVals.reduce((a,b)=>a+b,0) / outVals.length : 0;
  const avgAff   = inVals.length  ? inVals.reduce((a,b)=>a+b,0) / inVals.length  : 0;

  const riskOut = clamp100((avgCdOut / Math.max(1, maxOut)) * 100);
  const riskIn  = clamp100((avgAff   / Math.max(1, maxIn )) * 100);

  let redundancyRatio = 0;
  const declared = opts?.redundancyServices ?? [];
  if (declared.length && payload.services?.length) {
    const S = new Set(declared);
    const count = (payload.services ?? []).filter(s => S.has(s)).length;
    redundancyRatio = clamp100((count / payload.services.length) * 100) / 100; // 0..1
  }
  const riskRed = clamp100(100 - redundancyRatio * 100);

  const riskTotal = wOut * riskOut + wIn * riskIn + wRed * riskRed;
  const health = clamp100(100 - riskTotal);

  return { health, components: { riskOut, riskIn, riskRed, avgCdOut, avgAff, redundancyRatio } };
}

export async function computeAndPostCoupling(panel: vscode.WebviewPanel): Promise<void> {
  const cfg = await loadServiceConfig().catch(() => null) ?? null;
  const dartDocs = vscode.workspace.textDocuments.filter(d => d.languageId === 'dart');

  const calls: AutoCall[] = [];
  for (const doc of dartDocs) {
    const endpoints = extractEndpointsFromDart(doc);
    const fromModule = inferModuleFromPath(doc.uri.fsPath);
    for (const ep of endpoints) {
      calls.push({ fromModule, toUrl: ep.url, file: doc.uri.fsPath, line: ep.line });
    }
  }

  const g = buildCouplingFromCalls(calls, cfg || undefined);
  const hi = computeHealthIndex(g, {
    maxOut: 6, maxIn: 6,
    wOut: 0.5, wIn: 0.5, wRed: 0.0,
    redundancyServices: cfg?.redundancyServices
  });

  panel.webview.postMessage({
    type: 'coupling-data',
    payload: { ...g, healthIndex: hi.health, healthComponents: hi.components }
  });
}
