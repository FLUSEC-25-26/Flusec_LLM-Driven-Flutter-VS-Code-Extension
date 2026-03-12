// src/web/arc/dashboard.ts
import * as vscode from "vscode";
import * as fs from "fs";
import * as path from "path";
import { findingsPathForFolder } from "../../analyzer/runAnalyzer.js";

let currentPanel: vscode.WebviewPanel | undefined;
let findingsWatcher: fs.FSWatcher | undefined;
let isDisposed = true;

export function openArcDashboard(context: vscode.ExtensionContext) {
    const column = vscode.window.activeTextEditor?.viewColumn ?? vscode.ViewColumn.One;

    if (currentPanel && !isDisposed) {
        currentPanel.reveal(column);
        return;
    }

    isDisposed = false;
    currentPanel = vscode.window.createWebviewPanel(
        "flusecArcDashboard",
        "🏗️ Architecture Insights",
        column,
        {
            enableScripts: true,
            retainContextWhenHidden: true,
            localResourceRoots: [vscode.Uri.file(path.join(context.extensionPath, "src", "web"))]
        }
    );

    const webview = currentPanel.webview;
    
    let folder = vscode.workspace.workspaceFolders?.[0];
    if (!folder && vscode.window.activeTextEditor) {
        folder = vscode.workspace.getWorkspaceFolder(vscode.window.activeTextEditor.document.uri);
    }

    if (!folder) {
        vscode.window.showErrorMessage("FLUSEC: Please open a Folder to view Architecture Insights.");
        isDisposed = true;
        currentPanel.dispose();
        return;
    }

    const findingsPath = findingsPathForFolder(folder);
    const htmlFile = path.join(context.extensionPath, "src", "web", "arc", "dashboard.html");
    
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
                // 🔍 FILTER: Only grab Architecture (ARC) findings
                data = Array.isArray(raw) ? raw.filter(f => f.ruleId && f.ruleId.startsWith("FLUSEC.ARC")) : [];
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
        if (msg.command === "ready") {sendFindings();
        }
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