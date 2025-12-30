// src/web/ids/dashboard.ts
// IDS Dashboard Controller - Manages the webview panel for IDS vulnerability findings

import * as vscode from 'vscode';
import * as path from 'path';
import * as fs from 'fs';

/**
 * Opens the IDS Dashboard in a webview panel
 */
export function openIDSDashboard(context: vscode.ExtensionContext) {
    // Create webview panel
    const panel = vscode.window.createWebviewPanel(
        'idsDashboard',
        'IDS Vulnerability Dashboard',
        vscode.ViewColumn.Beside,
        {
            enableScripts: true,
            retainContextWhenHidden: true,
            localResourceRoots: [
                vscode.Uri.file(path.join(context.extensionPath, 'src', 'web', 'ids'))
            ]
        }
    );

    // Set webview HTML content
    panel.webview.html = getWebviewContent(panel.webview, context);

    // Get workspace folder
    const workspaceFolder = vscode.workspace.workspaceFolders?.[0];
    if (!workspaceFolder) {
        panel.webview.postMessage({ command: 'loadFindings', data: [] });
        return;
    }

    // IDS findings path
    const findingsPath = path.join(
        workspaceFolder.uri.fsPath,
        'flusec',
        'dart-analyzer',
        '.out',
        'ids-findings.json'
    );

    // Function to send findings to webview
    const sendFindings = () => {
        let findings: any[] = [];

        if (fs.existsSync(findingsPath)) {
            try {
                const content = fs.readFileSync(findingsPath, 'utf8');
                findings = JSON.parse(content);
                if (!Array.isArray(findings)) {
                    findings = [];
                }
            } catch (error) {
                console.error('Error reading IDS findings:', error);
                findings = [];
            }
        }

        panel.webview.postMessage({ command: 'loadFindings', data: findings });
    };

    // Send findings initially
    sendFindings();

    // Refresh when panel becomes visible
    panel.onDidChangeViewState(() => {
        if (panel.visible) {
            sendFindings();
        }
    });

    // Watch for changes to findings file
    const watcher = fs.watch(path.dirname(findingsPath), (eventType, filename) => {
        if (filename === 'ids-findings.json' && panel.visible) {
            setTimeout(sendFindings, 100); // Debounce
        }
    });

    // Handle messages from webview
    panel.webview.onDidReceiveMessage(
        async (message) => {
            switch (message.command) {
                case 'reveal':
                    await revealFileLocation(message.file, message.line, message.column);
                    break;

                case 'rescan':
                    await triggerRescan();
                    setTimeout(sendFindings, 500);
                    break;
            }
        },
        undefined,
        context.subscriptions
    );

    // Cleanup watcher when panel is disposed
    panel.onDidDispose(() => {
        watcher.close();
    });
}

/**
 * Generate HTML content for the webview
 */
function getWebviewContent(webview: vscode.Webview, context: vscode.ExtensionContext): string {
    // Get URIs for resources
    const htmlPath = path.join(context.extensionPath, 'src', 'web', 'ids', 'dashboard.html');
    const cssPath = path.join(context.extensionPath, 'src', 'web', 'ids', 'dashboard.css');
    const jsPath = path.join(context.extensionPath, 'src', 'web', 'ids', 'dashboard.js');

    const cssUri = webview.asWebviewUri(vscode.Uri.file(cssPath));
    const jsUri = webview.asWebviewUri(vscode.Uri.file(jsPath));
    const cspSource = webview.cspSource;

    // Read HTML template
    let html = fs.readFileSync(htmlPath, 'utf8');

    // Replace template variables
    html = html.replace(/\{\{cssUri\}\}/g, cssUri.toString());
    html = html.replace(/\{\{jsUri\}\}/g, jsUri.toString());
    html = html.replace(/\{\{cspSource\}\}/g, cspSource);

    return html;
}

/**
 * Reveal file location in editor
 */
async function revealFileLocation(filePath: string, line: number, column: number) {
    try {
        const uri = vscode.Uri.file(filePath);
        const document = await vscode.workspace.openTextDocument(uri);
        const editor = await vscode.window.showTextDocument(document, { preview: false });

        const position = new vscode.Position(
            Math.max(0, (line || 1) - 1),
            Math.max(0, (column || 1) - 1)
        );

        editor.selection = new vscode.Selection(position, position);
        editor.revealRange(
            new vscode.Range(position, position),
            vscode.TextEditorRevealType.InCenter
        );
    } catch (error) {
        vscode.window.showErrorMessage(`Failed to open file: ${error}`);
    }
}

/**
 * Trigger a rescan of the current file
 */
async function triggerRescan() {
    const editor = vscode.window.activeTextEditor;
    if (!editor) {
        vscode.window.showWarningMessage('No active editor to rescan');
        return;
    }

    try {
        // Trigger the scan command
        await vscode.commands.executeCommand('flusec.scanFile');
        vscode.window.showInformationMessage('Rescan triggered successfully');
    } catch (error) {
        vscode.window.showErrorMessage(`Failed to trigger rescan: ${error}`);
    }
}
