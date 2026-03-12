// // web/ivd/dashboard.ts

// import * as vscode from "vscode";
// import * as fs from "fs";
// import { findingsPathForFolder } from "../../analyzer/runAnalyzer.js";

// let currentPanel: vscode.WebviewPanel | undefined;

// export function openIvdDashboard(context: vscode.ExtensionContext) {

//   const column =
//     vscode.window.activeTextEditor?.viewColumn ?? vscode.ViewColumn.One;

//   if (currentPanel) {
//     currentPanel.reveal(column);
//     return;
//   }

//   currentPanel = vscode.window.createWebviewPanel(
//     "flusecIvdDashboard",
//     "🛡️ Input Validation Dashboard",
//     column,
//     {
//       enableScripts: true,
//       retainContextWhenHidden: true
//     }
//   );

//   const webview = currentPanel.webview;

//   // Paths
//   const ivdRoot = vscode.Uri.joinPath(context.extensionUri, "src", "web", "ivd");
//   const webRoot = vscode.Uri.joinPath(context.extensionUri, "src", "web");

//   const htmlPath = vscode.Uri.joinPath(ivdRoot, "dashboard.html");
//   const cssPath = vscode.Uri.joinPath(webRoot, "css", "dashboard.css");

//   const cssUri = webview.asWebviewUri(cssPath);

//   let htmlContent = `<html><body>Dashboard not found</body></html>`;

//   if (fs.existsSync(htmlPath.fsPath)) {
//     htmlContent = fs
//       .readFileSync(htmlPath.fsPath, "utf8")
//       .replace(/{{cssUri}}/g, cssUri.toString())
//       .replace(/{{cspSource}}/g, webview.cspSource);
//   }

//   webview.html = htmlContent;

//   const folder = vscode.workspace.workspaceFolders?.[0];

//   if (!folder) {
//     vscode.window.showErrorMessage("Flusec: No workspace folder open.");
//     return;
//   }

//   const findingsPath = findingsPathForFolder(folder);

//   function sendFindings() {

//     let data: any[] = [];

//     try {

//       if (fs.existsSync(findingsPath)) {

//         const raw = JSON.parse(
//           fs.readFileSync(findingsPath, "utf8")
//         );

//         data = Array.isArray(raw) ? raw : [];

//       }

//     } catch (err) {

//       console.error("Error reading findings.json", err);

//     }

//     if (currentPanel) {

//       currentPanel.webview.postMessage({
//         command: "loadFindings",
//         data: data
//       });

//     }

//   }

//   // Wait for webview to say "ready"
//   webview.onDidReceiveMessage((message) => {

//     if (message.command === "ready") {
//       sendFindings();
//     }

//   });

//   // Refresh when dashboard becomes visible
//   currentPanel.onDidChangeViewState(e => {

//     if (e.webviewPanel.visible) {
//       sendFindings();
//     }

//   });

//   // Watch findings.json for changes
//   if (fs.existsSync(findingsPath)) {

//     fs.watch(findingsPath, () => {
//       sendFindings();
//     });

//   }

//   currentPanel.onDidDispose(() => {
//     currentPanel = undefined;
//   }, null, context.subscriptions);
// }







// src/web/ivd/dashboard.ts
import * as vscode from "vscode";
import * as fs from "fs";
import * as path from "path";
import { findingsPathForFolder } from "../../analyzer/runAnalyzer.js";

let currentPanel: vscode.WebviewPanel | undefined;
let findingsWatcher: fs.FSWatcher | undefined;
let isDisposed = true; // Strict tracking to prevent crashes

export function openIvdDashboard(context: vscode.ExtensionContext) {
    const column = vscode.window.activeTextEditor?.viewColumn ?? vscode.ViewColumn.One;

    if (currentPanel && !isDisposed) {
        currentPanel.reveal(column);
        return;
    }

    isDisposed = false;
    currentPanel = vscode.window.createWebviewPanel(
        "flusecIvdDashboard",
        "🛡️ IVD Security Insights",
        column,
        {
            enableScripts: true,
            retainContextWhenHidden: true,
            localResourceRoots: [vscode.Uri.file(path.join(context.extensionPath, "src", "web"))]
        }
    );

    const webview = currentPanel.webview;
    
    // Better Workspace Resolution
    let folder = vscode.workspace.workspaceFolders?.[0];
    if (!folder && vscode.window.activeTextEditor) {
        folder = vscode.workspace.getWorkspaceFolder(vscode.window.activeTextEditor.document.uri);
    }

    if (!folder) {
        vscode.window.showErrorMessage("FLUSEC: Please open a Folder (File > Open Folder) to use the dashboard.");
        isDisposed = true;
        currentPanel.dispose();
        return;
    }

    const findingsPath = findingsPathForFolder(folder);
    const htmlFile = path.join(context.extensionPath, "src", "web", "ivd", "dashboard.html");
    
    let htmlContent = `<html><body><h1>HTML not found at ${htmlFile}</h1></body></html>`;
    if (fs.existsSync(htmlFile)) {
        const cssUri = webview.asWebviewUri(vscode.Uri.file(path.join(context.extensionPath, "src", "web", "css", "dashboard.css")));
        htmlContent = fs.readFileSync(htmlFile, "utf8")
            .replace(/{{cspSource}}/g, webview.cspSource)
            .replace(/{{cssUri}}/g, cssUri.toString());
    }
    webview.html = htmlContent;

    // --- SAFE SENDER ---
    const sendFindings = () => {
        if (isDisposed || !currentPanel) {return;};

        let data: any[] = [];
        if (fs.existsSync(findingsPath)) {
            try {
                const raw = JSON.parse(fs.readFileSync(findingsPath, "utf8"));
                data = Array.isArray(raw) ? raw : [];
            } catch (e) { console.error("Parse error:", e); }
        }

        try {
            currentPanel.webview.postMessage({ command: "loadFindings", data });
        } catch (err) {
            console.warn("Caught webview disposed error.");
        }
    };

    // --- SAFE WATCHER ---
    if (!findingsWatcher && fs.existsSync(findingsPath)) {
        findingsWatcher = fs.watch(findingsPath, (eventType) => {
            if (eventType === "change" && !isDisposed) {
                sendFindings();
            }
        });
    }

    webview.onDidReceiveMessage((msg) => {
        if (msg.command === "ready") {sendFindings();}
    });

    // --- STRICT CLEANUP ---
    currentPanel.onDidDispose(() => {
        isDisposed = true;
        currentPanel = undefined;
        if (findingsWatcher) {
            findingsWatcher.close();
            findingsWatcher = undefined;
        }
    }, null, context.subscriptions);
}