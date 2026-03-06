// src/analyzer/runAnalyzer.ts

import * as vscode from "vscode";
import { execFile } from "child_process";
import * as path from "path";
import * as fs from "fs";

import { diagCollection, severityToVS, upsertFindingsForDoc } from "./findingsStore.js";
import { resetLLMState, clearFeedbackForDocument } from "../diagnostics/hoverllm.js";

export function findWorkspaceFolderForDoc(doc: vscode.TextDocument): vscode.WorkspaceFolder | undefined {
    return vscode.workspace.getWorkspaceFolder(doc.uri) ?? vscode.workspace.workspaceFolders?.[0];
}

export function findingsPathForFolder(folder: vscode.WorkspaceFolder): string {
    return path.join(folder.uri.fsPath, ".flusec", ".out", "findings.json");
}

export async function runAnalyzer(doc: vscode.TextDocument, context: vscode.ExtensionContext): Promise<void> {
    resetLLMState();
    clearFeedbackForDocument(doc.uri);

    const folder = findWorkspaceFolderForDoc(doc);
    if (!folder) {return;}

    const findingsFile = findingsPathForFolder(folder);
    // Use context.extensionPath to reliably find the bin folder
    const analyzerPath = path.join(context.extensionPath, "dart-analyzer", "bin", "analyzer.exe");

    if (!fs.existsSync(analyzerPath)) {
        vscode.window.showErrorMessage(`Analyzer missing at: ${analyzerPath}`);
        return;
    }

    const analyzerCwd = path.join(folder.uri.fsPath, ".flusec");
    if (!fs.existsSync(analyzerCwd)) {
        fs.mkdirSync(analyzerCwd, { recursive: true });
    }

    const stdout = await new Promise<string>((resolve, reject) => {
        execFile(
            analyzerPath,
            [doc.fileName],
            { shell: true, cwd: analyzerCwd, maxBuffer: 10 * 1024 * 1024 },
            (err, stdout, stderr) => {
                if (err) {return reject(err);}
                if (stderr) {console.warn("Analyzer Stderr:", stderr);}
                resolve(stdout.trim());
            }
        );
    });

    // 🛡️ Robust JSON validation
    if (!stdout.startsWith("[") && !stdout.startsWith("{")) {
        console.error("Analyzer error output:", stdout);
        vscode.window.showErrorMessage(`FLUSEC Analyzer Error: ${stdout.substring(0, 60)}`);
        return;
    }

    let findings: any[] = [];
    try {
        findings = JSON.parse(stdout);
        if (!Array.isArray(findings)) {findings = [];}
    } catch (e) {
        console.error("JSON Parse failed:", e);
        return;
    }

    const diags: vscode.Diagnostic[] = [];
    for (const f of findings) {
        const lineIdx = Math.max(0, (f.line ?? 1) - 1);
        let range: vscode.Range;
        
        try {
            const textLine = doc.lineAt(lineIdx);
            range = new vscode.Range(lineIdx, 0, lineIdx, textLine.text.length);
        } catch {
            range = new vscode.Range(lineIdx, 0, lineIdx, 0);
        }

        const diag = new vscode.Diagnostic(range, f.message || "", severityToVS(f.severity || "warning"));
        diag.source = "flusec";
        diag.code = f.ruleId;
        diags.push(diag);
    }

    diagCollection.set(doc.uri, diags);
    upsertFindingsForDoc(findingsFile, doc, findings);
}