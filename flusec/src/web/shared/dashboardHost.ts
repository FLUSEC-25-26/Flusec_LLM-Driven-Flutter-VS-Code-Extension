// src/web/shared/dashboardHost.ts
//
// Shared host-side helpers for FLUSEC VS Code webview dashboards.
// Keeps HSD, NET, IDS and IIV behavior consistent without coupling their
// component-specific analyzer logic.

import * as vscode from "vscode";
import * as fs from "fs";
import * as path from "path";

export type DashboardLoadStatus =
  | "ready"
  | "no-workspace"
  | "no-scan-data"
  | "error";

export type DashboardFindingsPayload = {
  status: DashboardLoadStatus;
  findings: unknown[];
  message?: string;
};

export function getDashboardNonce(): string {
  const chars =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
  let value = "";

  for (let i = 0; i < 32; i++) {
    value += chars.charAt(Math.floor(Math.random() * chars.length));
  }

  return value;
}

export function readDashboardFindings(
  findingsPath: string | undefined
): DashboardFindingsPayload {
  if (!findingsPath) {
    return {
      status: "no-workspace",
      findings: [],
      message: "Open a workspace folder to view FLUSEC findings.",
    };
  }

  if (!fs.existsSync(findingsPath)) {
    return {
      status: "no-scan-data",
      findings: [],
      message: "No scan data is available yet. Run a FLUSEC scan first.",
    };
  }

  try {
    const parsed = JSON.parse(fs.readFileSync(findingsPath, "utf8"));
    return {
      status: "ready",
      findings: Array.isArray(parsed) ? parsed : [],
    };
  } catch (error) {
    return {
      status: "error",
      findings: [],
      message: `Unable to read FLUSEC findings: ${String(error)}`,
    };
  }
}

export function buildDashboardHtml(
  context: vscode.ExtensionContext,
  webview: vscode.Webview,
  componentFolder: "hsd" | "net" | "ids" | "iiv"
): string {
  const webRoot = vscode.Uri.joinPath(context.extensionUri, "src", "web");
  const componentRoot = vscode.Uri.joinPath(webRoot, componentFolder);
  const sharedRoot = vscode.Uri.joinPath(webRoot, "shared");
  const htmlPath = vscode.Uri.joinPath(componentRoot, "dashboard.html");

  if (!fs.existsSync(htmlPath.fsPath)) {
    return "<html><body>FLUSEC dashboard template not found.</body></html>";
  }

  const nonce = getDashboardNonce();
  const cssUri = webview
    .asWebviewUri(vscode.Uri.joinPath(sharedRoot, "dashboard.css"))
    .toString();
  const jsUri = webview
    .asWebviewUri(vscode.Uri.joinPath(sharedRoot, "dashboard.js"))
    .toString();

  const cspMeta = `
    <meta http-equiv="Content-Security-Policy"
      content="
        default-src 'none';
        img-src ${webview.cspSource} data:;
        style-src ${webview.cspSource} 'unsafe-inline';
        script-src 'nonce-${nonce}';
        font-src ${webview.cspSource};
      ">
  `;

  let html = fs.readFileSync(htmlPath.fsPath, "utf8");
  html = html
    .replace(/\{\{sharedCssUri\}\}/g, cssUri)
    .replace(/\{\{sharedJsUri\}\}/g, jsUri)
    .replace(/\{\{nonce\}\}/g, nonce);

  return html.replace(/<head>/i, `<head>\n${cspMeta}`);
}

export async function revealDashboardFinding(
  file: unknown,
  line: unknown,
  column: unknown
): Promise<void> {
  const fsPath = typeof file === "string" ? file : "";
  if (!fsPath) {return;}

  try {
    const document = await vscode.workspace.openTextDocument(
      vscode.Uri.file(fsPath)
    );
    const editor = await vscode.window.showTextDocument(document, {
      preview: false,
    });

    const lineIndex = Math.max(0, Number(line ?? 1) - 1);
    const columnIndex = Math.max(0, Number(column ?? 1) - 1);
    const position = new vscode.Position(lineIndex, columnIndex);

    editor.selection = new vscode.Selection(position, position);
    editor.revealRange(
      new vscode.Range(position, position),
      vscode.TextEditorRevealType.InCenter
    );
  } catch (error) {
    vscode.window.showErrorMessage(
      `FLUSEC: Failed to open finding location: ${String(error)}`
    );
  }
}

/**
 * Watch the parent directory of a component findings file. The watcher is
 * intentionally best-effort: dashboard refresh remains available even when
 * the .flusec output directory does not exist yet.
 */
export function createFindingsWatcher(
  findingsPath: string,
  onChange: () => void
): fs.FSWatcher | undefined {
  const directory = path.dirname(findingsPath);
  if (!fs.existsSync(directory)) {return undefined;}

  try {
    let debounce: NodeJS.Timeout | undefined;
    const expectedName = path.basename(findingsPath).toLowerCase();

    const watcher = fs.watch(directory, (_event, filename) => {
      if (!filename) {return;}
      if (String(filename).toLowerCase() !== expectedName) {return;}

      if (debounce) {clearTimeout(debounce);}
      debounce = setTimeout(onChange, 200);
    });

    watcher.on("close", () => {
      if (debounce) {clearTimeout(debounce);}
    });

    return watcher;
  } catch {
    return undefined;
  }
}
