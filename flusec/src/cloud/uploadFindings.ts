import * as vscode from "vscode";
import * as fs from "fs";
import * as path from "path";
import fetch from "node-fetch";

function findingsPathForWorkspaceRoot(workspaceRoot: string) {
  // You confirmed: .flusec/out/findings.json
  return path.join(workspaceRoot, ".flusec", "out", "findings.json");
}

function readFindingsJson(fp: string): any[] {
  if (!fs.existsSync(fp)) {return [];}
  try {
    const raw = JSON.parse(fs.readFileSync(fp, "utf8"));
    return Array.isArray(raw) ? raw : [];
  } catch {
    return [];
  }
}

function toRelativeFindingPaths(findings: any[], workspaceRoot: string) {
  return findings.map((f) => {
    const abs = String(f?.file || "");
    let rel = abs;
    try {
      // Only convert if it looks like it is inside the workspace
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
  return String(cfg.get<string>("cloudUploadEndpoint") || "").trim().replace(/\/+$/, "");
}

export async function uploadFindingsCommand(context: vscode.ExtensionContext) {
  const endpoint = getCloudEndpoint();
  if (!endpoint) {
    vscode.window.showErrorMessage(
      "FLUSEC: Set flusec.cloudUploadEndpoint in Settings first."
    );
    return;
  }

  const folders = vscode.workspace.workspaceFolders ?? [];
  if (!folders.length) {
    vscode.window.showErrorMessage("FLUSEC: No workspace folder open.");
    return;
  }

  // 1) GitHub Sign-in (this is the required consent path)
  const session = await vscode.authentication.getSession(
    "github",
    ["read:user"],
    { createIfNone: true }
  );

  const token = session.accessToken;

  // 2) Gather findings from all workspace folders
  const allPayloads: any[] = [];

  for (const f of folders) {
    const workspaceRoot = f.uri.fsPath;
    const fp = findingsPathForWorkspaceRoot(workspaceRoot);

    const findingsAbs = readFindingsJson(fp);
    const findings = toRelativeFindingPaths(findingsAbs, workspaceRoot);

    allPayloads.push({
      workspaceName: f.name,
      workspaceId: "", // optional (add later if you want)
      findingsFile: fp,
      findingsCount: findings.length,
      findings
    });
  }

  // If everything is empty, still allow upload but warn
  const totalFindings = allPayloads.reduce((n, p) => n + (p.findingsCount || 0), 0);
  if (totalFindings === 0) {
    const ok = await vscode.window.showWarningMessage(
      "FLUSEC: No findings found. Upload anyway?",
      "Upload",
      "Cancel"
    );
    if (ok !== "Upload") {return;}
  }

  // 3) Upload (one request containing all workspaces)
  const body = {
    extensionVersion: context.extension.packageJSON?.version ?? "",
    generatedAt: new Date().toISOString(),
    workspaces: allPayloads
  };

  const res = await fetch(`${endpoint}/v1/findings`, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      "Authorization": `Bearer ${token}`
    },
    body: JSON.stringify(body)
  });

  if (!res.ok) {
    const text = await res.text().catch(() => "");
    vscode.window.showErrorMessage(
      `FLUSEC: Upload failed (HTTP ${res.status}). ${text}`.trim()
    );
    return;
  }

  const json = await res.json().catch(() => ({} as any));
  vscode.window.showInformationMessage(
    `FLUSEC: Uploaded ${totalFindings} finding(s) as GitHub user "${json.username || "unknown"}".`
  );
}
