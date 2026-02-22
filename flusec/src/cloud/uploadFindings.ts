// src/cloud/uploadFindings.ts
//
// Upload findings from all components to the cloud.
// Reads hsd_findings.json, net_findings.json, and ids_findings.json separately.

import * as vscode from "vscode";
import * as fs from "fs";
import {
  hsdFindingsPathForFolder,
  netFindingsPathForFolder,
  idsFindingsPathForFolder,
} from "../analyzer/runAnalyzer.js";

function readJsonArray(filePath: string): any[] {
  if (!fs.existsSync(filePath)) {return [];}
  try {
    const data = JSON.parse(fs.readFileSync(filePath, "utf8"));
    return Array.isArray(data) ? data : [];
  } catch {
    return [];
  }
}

export async function uploadFindings(context: vscode.ExtensionContext) {
  const folders = vscode.workspace.workspaceFolders;
  if (!folders || folders.length === 0) {
    vscode.window.showWarningMessage("No workspace folders open.");
    return;
  }

  const workspaces = folders.map((f) => {
    const hsdFindings = readJsonArray(hsdFindingsPathForFolder(f));
    const netFindings = readJsonArray(netFindingsPathForFolder(f));
    const idsFindings = readJsonArray(idsFindingsPathForFolder(f));

    return {
      workspaceName: f.name,
      hsd: {
        findingsFile: "hsd_findings.json",
        count: hsdFindings.length,
        findings: hsdFindings,
      },
      net: {
        findingsFile: "net_findings.json",
        count: netFindings.length,
        findings: netFindings,
      },
      ids: {
        findingsFile: "ids_findings.json",
        count: idsFindings.length,
        findings: idsFindings,
      },
    };
  });

  const payload = { workspaces };

  // TODO: Replace with actual cloud endpoint
  console.log("[FLUSEC][upload] payload:", JSON.stringify(payload, null, 2));
  vscode.window.showInformationMessage(
    `FLUSEC: Upload prepared — ${workspaces.length} workspace(s).`
  );
}