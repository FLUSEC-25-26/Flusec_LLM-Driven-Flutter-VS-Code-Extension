// src/cloud/uploadFindings.ts
//
// Uploads HSD and NET findings separately to the cloud backend.
// Reads from hsd_findings.json and net_findings.json per workspace folder.

import * as vscode from "vscode";
import * as fs from "fs";
import * as path from "path";
import fetch from "node-fetch";

import {
  hsdFindingsPathForFolder,
  netFindingsPathForFolder,
  findWorkspaceFolderForDoc,
} from "../analyzer/runAnalyzer.js";

function sleep(ms: number) {
  return new Promise((r) => setTimeout(r, ms));
}

function readFindingsJson(fp: string): any[] {
  if (!fs.existsSync(fp)) {
    console.warn("[FLUSEC] findings file not found:", fp);
    return [];
  }

  try {
    let text = fs.readFileSync(fp, "utf8");

    // Remove UTF-8 BOM if present
    if (text && text.charCodeAt(0) === 0xfeff) {
      text = text.slice(1);
    }

    const raw = JSON.parse(text);
    if (Array.isArray(raw)) {return raw;}

    console.warn("[FLUSEC] findings file parsed but top-level is not an array:", fp);
    return [];
  } catch (e: any) {
    console.error("[FLUSEC] JSON parse failed:", fp, e?.message || e);
    return [];
  }
}

async function readFindingsJsonStable(fp: string): Promise<any[]> {
  for (let i = 0; i < 6; i++) {
    const arr = readFindingsJson(fp);
    if (arr.length > 0) {return arr;}
    await sleep(200);
  }
  return readFindingsJson(fp);
}

function toRelativeFindingPaths(findings: any[], workspaceRoot: string) {
  return findings.map((f) => {
    const abs = String(f?.file || "");
    let rel = abs;
    try {
      const candidate = path.relative(workspaceRoot, abs);
      if (candidate && !candidate.startsWith("..") && !path.isAbsolute(candidate)) {
        rel = candidate;
      }
    } catch {
      // ignore
    }
    return { ...f, file: rel };
  });
}

function getCloudEndpoint(): string {
  const cfg = vscode.workspace.getConfiguration("flusec");
  return String(cfg.get<string>("cloudUploadEndpoint") || "")
    .trim()
    .replace(/\/+$/, "");
}

export async function uploadFindingsCommand(context: vscode.ExtensionContext) {
  const endpoint = getCloudEndpoint();
  if (!endpoint) {
    vscode.window.showErrorMessage("FLUSEC: Set flusec.cloudUploadEndpoint in Settings first.");
    return;
  }

  const folders = vscode.workspace.workspaceFolders ?? [];
  if (!folders.length) {
    vscode.window.showErrorMessage("FLUSEC: No workspace folder open.");
    return;
  }

  // 1) GitHub Sign-in
  const session = await vscode.authentication.getSession("github", ["read:user"], {
    createIfNone: true,
  });

  const token = session.accessToken;

  // 2) Gather findings from all workspace folders — separated by component
  const allPayloads: any[] = [];

  for (const f of folders) {
    const workspaceRoot = f.uri.fsPath;

    // Read HSD findings
    const hsdFp = hsdFindingsPathForFolder(f);
    const hsdFindingsAbs = await readFindingsJsonStable(hsdFp);
    const hsdFindings = toRelativeFindingPaths(hsdFindingsAbs, workspaceRoot);

    // Read NET findings
    const netFp = netFindingsPathForFolder(f);
    const netFindingsAbs = await readFindingsJsonStable(netFp);
    const netFindings = toRelativeFindingPaths(netFindingsAbs, workspaceRoot);

    // Debug logs
    console.log("[FLUSEC] workspaceRoot =", workspaceRoot);
    console.log("[FLUSEC] hsd findings  =", hsdFindings.length, "from", hsdFp);
    console.log("[FLUSEC] net findings  =", netFindings.length, "from", netFp);

    const safeWorkspaceName =
      (f.name && f.name.trim()) || path.basename(workspaceRoot) || "workspace";

    allPayloads.push({
      workspaceName: safeWorkspaceName,
      workspaceId: "",
      hsd: {
        findingsFile: hsdFp,
        count: hsdFindings.length,
        findings: hsdFindings,
      },
      net: {
        findingsFile: netFp,
        count: netFindings.length,
        findings: netFindings,
      },
    });
  }

  const totalFindings = allPayloads.reduce(
    (n, p) => n + (p.hsd?.count || 0) + (p.net?.count || 0), 0
  );

  if (totalFindings === 0) {
    const ok = await vscode.window.showWarningMessage(
      "FLUSEC: No findings found. Upload anyway?",
      "Upload",
      "Cancel"
    );
    if (ok !== "Upload") {return;}
  }

  // 3) Upload (ONE request containing ALL workspaces with component separation)
  const body = {
    extensionVersion: context.extension.packageJSON?.version ?? "",
    generatedAt: new Date().toISOString(),
    totalFindings,
    workspaces: allPayloads,
  };

  const res = await fetch(`${endpoint}/v1/findings`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${token}`,
    },
    body: JSON.stringify(body),
  });

  if (!res.ok) {
    const text = await res.text().catch(() => "");
    vscode.window.showErrorMessage(`FLUSEC: Upload failed (HTTP ${res.status}). ${text}`.trim());
    return;
  }

  const json = await res.json().catch(() => ({} as any));

  const serverTotal = typeof json?.totalFindings === "number" ? json.totalFindings : totalFindings;

  vscode.window.showInformationMessage(
    `FLUSEC: Uploaded ${serverTotal} finding(s) as GitHub user "${json.username || "unknown"}".`
  );
}