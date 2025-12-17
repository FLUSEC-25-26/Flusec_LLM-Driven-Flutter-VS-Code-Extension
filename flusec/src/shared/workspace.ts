// src/shared/workspace.ts
//
// Shared helper: find which workspace folder owns a given document.
// Needed because VS Code can open multiple folders (multi-root workspace).

import * as vscode from "vscode";

export function findWorkspaceFolderForDoc(
  doc: vscode.TextDocument
): vscode.WorkspaceFolder | undefined {
  return (
    vscode.workspace.getWorkspaceFolder(doc.uri) ??
    vscode.workspace.workspaceFolders?.[0]
  );
}
