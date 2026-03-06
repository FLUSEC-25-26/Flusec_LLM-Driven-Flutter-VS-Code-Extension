// src/analyzer/findingsStore.ts

import * as vscode from "vscode";
import * as fs from "fs";
import * as path from "path";

/** * Ensure the directory for a given file path exists.
 */
function ensureDirForFile(filePath: string) {
    const dir = path.dirname(filePath);
    if (!fs.existsSync(dir)) {
        fs.mkdirSync(dir, { recursive: true });
    }
}

// Shared diagnostics collection for the whole extension.
export const diagCollection = vscode.languages.createDiagnosticCollection("flusec");

/**
 * Maps severity strings to VS Code DiagnosticSeverity.
 */
export function severityToVS(sev: string): vscode.DiagnosticSeverity {
    return sev?.toLowerCase() === "error"
        ? vscode.DiagnosticSeverity.Error
        : vscode.DiagnosticSeverity.Warning;
}

/**
 * Read findings.json from the given path and update all diagnostics.
 */
export function refreshDiagnosticsFromFindings(fp: string) {
    if (!fs.existsSync(fp)) {
        diagCollection.clear();
        return;
    }

    let raw: any[] = [];
    try {
        raw = JSON.parse(fs.readFileSync(fp, "utf8"));
    } catch (e) {
        console.error("Failed to parse findings.json:", e);
        return;
    }

    const map = new Map<string, vscode.Diagnostic[]>();
    for (const f of raw) {
        const file = String(f.file || "");
        if (!file) {continue;}

        const line = Math.max(0, (f.line ?? 1) - 1);
        const col = Math.max(0, (f.column ?? 1) - 1);
        // Default width if snippet length isn't provided
        const endCol = col + 10; 

        const diag = new vscode.Diagnostic(
            new vscode.Range(line, col, line, endCol),
            `[${f.ruleId}] ${f.message || ""}`,
            severityToVS(f.severity || "warning")
        );

        diag.source = "flusec";
        diag.code = f.ruleId;

        const list = map.get(file) ?? [];
        list.push(diag);
        map.set(file, list);
    }

    diagCollection.clear();
    for (const [fsPath, diags] of map) {
        diagCollection.set(vscode.Uri.file(fsPath), diags);
    }
}

/**
 * Merge new findings for a single document into findings.json,
 * then refresh diagnostics.
 * THIS WAS THE MISSING EXPORT
 */
export function upsertFindingsForDoc(
    findingsFilePath: string,
    doc: vscode.TextDocument,
    newFindings: any[]
) {
    ensureDirForFile(findingsFilePath);
    let all: any[] = [];
    
    if (fs.existsSync(findingsFilePath)) {
        try {
            all = JSON.parse(fs.readFileSync(findingsFilePath, "utf8"));
            if (!Array.isArray(all)) {all = [];}
        } catch {
            all = [];
        }
    }

    const filePath = doc.fileName;
    // Remove old findings for this specific file to avoid duplicates
    all = all.filter((x) => x?.file !== filePath);

    for (const f of newFindings) {
        const lineIdx = Math.max(0, f.line - 1);
        const lineText = doc.lineAt(lineIdx).text;
        all.push({
            file: filePath,
            line: f.line,
            column: f.column,
            endColumn: lineText.length,
            ruleId: f.ruleId,
            message: f.message,
            severity: f.severity || "warning"
        });
    }

    fs.writeFileSync(findingsFilePath, JSON.stringify(all, null, 2), "utf8");
    refreshDiagnosticsFromFindings(findingsFilePath);
}