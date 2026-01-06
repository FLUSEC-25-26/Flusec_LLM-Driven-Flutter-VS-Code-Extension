// // import * as vscode from "vscode";
// // import * as fs from "fs";
// // import * as path from "path";
// // import { findingsPathForFolder } from "../../analyzer/runAnalyzer.js";

// // export function openIvdDashboard(context: vscode.ExtensionContext) {
// //   const panel = vscode.window.createWebviewPanel(
// //     "flusecIvdDashboard",
// //     "Flusec: Input Validation",
// //     vscode.ViewColumn.Beside,
// //     { enableScripts: true, retainContextWhenHidden: true }
// //   );

// //   const webview = panel.webview;
// //   // Point to IVD html folder
// //   const ivdRoot = vscode.Uri.joinPath(context.extensionUri, "src", "web", "ivd");
// //   const styleRoot = vscode.Uri.joinPath(context.extensionUri, "src", "web");

// //   const htmlPath = vscode.Uri.joinPath(ivdRoot, "dashboard.html");
// //   // Reuse existing CSS/JS because the layout is the same!
// //   const cssPath = vscode.Uri.joinPath(styleRoot, "css", "dashboard.css");
// //   const jsPath = vscode.Uri.joinPath(styleRoot, "js", "dashboard.js");

// //   const cssUri = webview.asWebviewUri(cssPath);
// //   const jsUri = webview.asWebviewUri(jsPath);

// //   // ... (Rest of the code is identical to hsd/dashboard.ts) ...
// //   // Just ensure you read the HTML file correctly.
  
// //   let html = "";
// //   if (fs.existsSync(htmlPath.fsPath)) {
// //       const raw = fs.readFileSync(htmlPath.fsPath, "utf8");
// //       html = raw
// //         .replace(/{{cssUri}}/g, cssUri.toString())
// //         .replace(/{{jsUri}}/g, jsUri.toString())
// //         .replace(/{{cspSource}}/g, webview.cspSource);
// //   }
// //   panel.webview.html = html;

// //   // ... (Logic to read findings.json is exactly the same) ...
// //   // NOTE: IVD and HSD share the same findings.json. 
// //   // The JS inside the HTML will filter them.
  
// //   const folder = vscode.workspace.workspaceFolders?.[0];
// //   const findingsPath = folder ? findingsPathForFolder(folder) : "";
  
// //   const sendFindings = () => {
// //     let data: any[] = [];
// //     if (fs.existsSync(findingsPath)) {
// //         try {
// //             data = JSON.parse(fs.readFileSync(findingsPath, "utf8"));
// //             if (!Array.isArray(data)) {data = [];}
// //         } catch { data = []; }
// //     }
// //     // Fix: Send 'data' instead of 'allFindings'
// //     panel.webview.postMessage({ command: "loadFindings", data: data });
// // };

// //   sendFindings();
// //   // ... rest of event listeners ...
// // }




// // src/web/ivd/dashboard.ts
// import * as vscode from "vscode";
// import * as fs from "fs";
// import { findingsPathForFolder } from "../../analyzer/runAnalyzer.js";

// let currentPanel: vscode.WebviewPanel | undefined = undefined;

// export function openIvdDashboard(context: vscode.ExtensionContext) {
//   const column = vscode.window.activeTextEditor
//     ? vscode.window.activeTextEditor.viewColumn
//     : undefined;

//   if (currentPanel) {
//     currentPanel.reveal(column);
//     return;
//   }

//   // Create Panel
//   currentPanel = vscode.window.createWebviewPanel(
//     "flusecIvdDashboard",
//     "🛡️ Input Validation",
//     column || vscode.ViewColumn.One,
//     { enableScripts: true, retainContextWhenHidden: true }
//   );

//   const webview = currentPanel.webview;

//   // --- 1. LOAD HTML FILE ---
//   const ivdRoot = vscode.Uri.joinPath(context.extensionUri, "src", "web", "ivd");
//   const styleRoot = vscode.Uri.joinPath(context.extensionUri, "src", "web");

//   // Path to HTML
//   const htmlPath = vscode.Uri.joinPath(ivdRoot, "dashboard.html");
  
//   // Path to Shared CSS (dashboard.css)
//   const cssPath = vscode.Uri.joinPath(styleRoot, "css", "dashboard.css");
//   const cssUri = webview.asWebviewUri(cssPath);

//   let htmlContent = "<html><body>Error loading dashboard.html</body></html>";
  
//   if (fs.existsSync(htmlPath.fsPath)) {
//     try {
//         htmlContent = fs.readFileSync(htmlPath.fsPath, "utf8")
//             .replace(/{{cssUri}}/g, cssUri.toString())
//             .replace(/{{cspSource}}/g, webview.cspSource);
//     } catch (e) {
//         console.error("Error reading IVD dashboard html:", e);
//     }
//   }

//   currentPanel.webview.html = htmlContent;

//   // --- 2. DATA HANDLING ---
//   const folder = vscode.workspace.workspaceFolders?.[0];
//   // Calculate path to findings.json (same as Analyzer)
//   const findingsPath = folder ? findingsPathForFolder(folder) : "";

//   const sendFindings = () => {
//     let data: any[] = [];
//     if (fs.existsSync(findingsPath)) {
//       try {
//         const raw = JSON.parse(fs.readFileSync(findingsPath, "utf8"));
//         if (Array.isArray(raw)) {
//           // 🚨 FILTER: Only keep IVD Findings
//           data = raw.filter((f: any) => f.ruleId && f.ruleId.includes("IVD"));
//         }
//       } catch { data = []; }
//     }
//     // Send to Frontend
//     currentPanel?.webview.postMessage({ command: "loadFindings", data });
//   };

//   // Send initial data
//   sendFindings();

//   // Reload when tab becomes visible
//   currentPanel.onDidChangeViewState(e => {
//     if (e.webviewPanel.visible) sendFindings();
//   });

//   currentPanel.onDidDispose(() => {
//     currentPanel = undefined;
//   }, null, context.subscriptions);
// }




// src/web/ivd/dashboard.ts
import * as vscode from "vscode";
import * as fs from "fs";
import { findingsPathForFolder } from "../../analyzer/runAnalyzer.js";

let currentPanel: vscode.WebviewPanel | undefined = undefined;

export function openIvdDashboard(context: vscode.ExtensionContext) {
  const column = vscode.window.activeTextEditor ? vscode.window.activeTextEditor.viewColumn : undefined;

  if (currentPanel) {
    currentPanel.reveal(column);
    return;
  }

  // Create the Panel
  currentPanel = vscode.window.createWebviewPanel(
    "flusecIvdDashboard",
    "🛡️ Input Validation",
    column || vscode.ViewColumn.One,
    { enableScripts: true, retainContextWhenHidden: true }
  );

  const webview = currentPanel.webview;

  // --- Load HTML ---
  const ivdRoot = vscode.Uri.joinPath(context.extensionUri, "src", "web", "ivd");
  const styleRoot = vscode.Uri.joinPath(context.extensionUri, "src", "web");
  
  // Ensure dashboard.html exists at src/web/ivd/dashboard.html
  const htmlPath = vscode.Uri.joinPath(ivdRoot, "dashboard.html");
  const cssPath = vscode.Uri.joinPath(styleRoot, "css", "dashboard.css");
  const cssUri = webview.asWebviewUri(cssPath);

  let htmlContent = "<html><body>Error: Could not find dashboard.html</body></html>";
  if (fs.existsSync(htmlPath.fsPath)) {
      htmlContent = fs.readFileSync(htmlPath.fsPath, "utf8")
        .replace(/{{cssUri}}/g, cssUri.toString())
        .replace(/{{cspSource}}/g, webview.cspSource);
  }
  currentPanel.webview.html = htmlContent;

  // --- Load Data ---
  const folder = vscode.workspace.workspaceFolders?.[0];
  const findingsPath = folder ? findingsPathForFolder(folder) : "";

  const sendFindings = () => {
    let data: any[] = [];
    if (fs.existsSync(findingsPath)) {
      try {
        const raw = JSON.parse(fs.readFileSync(findingsPath, "utf8"));
        // 🔍 FILTER: Only send IVD findings to this dashboard
        data = raw.filter((f: any) => f.ruleId && f.ruleId.includes("IVD"));
        console.log("IVD Dashboard found items:", data.length);
      } catch (e) {
        console.error("Error reading findings.json", e);
      }
    }
    currentPanel?.webview.postMessage({ command: "loadFindings", data });
  };

  sendFindings();

  currentPanel.onDidChangeViewState(e => {
    if (e.webviewPanel.visible) sendFindings();
  });

  currentPanel.onDidDispose(() => {
    currentPanel = undefined;
  }, null, context.subscriptions);
}