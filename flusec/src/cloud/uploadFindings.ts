import * as vscode from "vscode";
import * as fs from "fs";
import * as path from "path";
import fetch from "node-fetch";

function findingsPathForWorkspaceRoot(workspaceRoot: string) {
  // Your current analyzer output:
  return path.join(workspaceRoot, ".flusec", ".out", "findings.json");
}

function sleep(ms: number) {
  return new Promise((r) => setTimeout(r, ms));
}

function readFindingsJson(fp: string): any[] {
  if (!fs.existsSync(fp)) {
    console.warn("[FLUSEC] findings.json not found:", fp);
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

    console.warn("[FLUSEC] findings.json parsed but top-level is not an array.");
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

  // 2) Gather findings from all workspace folders
  const allPayloads: any[] = [];

  for (const f of folders) {
    const workspaceRoot = f.uri.fsPath;
    const fp = findingsPathForWorkspaceRoot(workspaceRoot);

    // Debug proof logs (path + file size + first characters)
    const rawText = fs.existsSync(fp) ? fs.readFileSync(fp, "utf8") : "";
    console.log("[FLUSEC] workspaceRoot =", workspaceRoot);
    console.log("[FLUSEC] findings fp     =", fp);
    console.log("[FLUSEC] findings size   =", Buffer.byteLength(rawText, "utf8"));
    console.log("[FLUSEC] findings head   =", rawText.slice(0, 80).replace(/\s+/g, " "));

    const findingsAbs = await readFindingsJsonStable(fp);
    console.log("[FLUSEC] findings count  =", findingsAbs.length);

    const findings = toRelativeFindingPaths(findingsAbs, workspaceRoot);

    const safeWorkspaceName =
      (f.name && f.name.trim()) || path.basename(workspaceRoot) || "workspace";

    allPayloads.push({
      workspaceName: safeWorkspaceName,
      workspaceId: "", // optional
      findingsFile: fp,
      findingsCount: findings.length,
      findings,
    });
  }

  const totalFindings = allPayloads.reduce((n, p) => n + (p.findingsCount || 0), 0);

  if (totalFindings === 0) {
    const ok = await vscode.window.showWarningMessage(
      "FLUSEC: No findings found. Upload anyway?",
      "Upload",
      "Cancel"
    );
    if (ok !== "Upload") {return;}
  }

  // 3) Upload (ONE request containing ALL workspaces)
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

  // backend multi-workspace response now returns totals/batchIds
  const serverTotal = typeof json?.totalFindings === "number" ? json.totalFindings : totalFindings;

  vscode.window.showInformationMessage(
    `FLUSEC: Uploaded ${serverTotal} finding(s) as GitHub user "${json.username || "unknown"}".`
  );
}
