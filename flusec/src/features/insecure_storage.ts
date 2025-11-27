import * as vscode from 'vscode';
import * as cp from 'child_process';
import * as path from 'path';
import * as fs from 'fs';

interface Finding {
    ruleId: string;
    message: string;
    severity: string;
    filePath: string;
    lineNumber: number;
    columnNumber: number;
    codeSnippet: string;
    remediation: string;
}

export class InsecureStorageScanner {
    private diagnosticCollection: vscode.DiagnosticCollection;

    constructor() {
        this.diagnosticCollection = vscode.languages.createDiagnosticCollection('flusec-storage');
    }

    public async scan(document: vscode.TextDocument): Promise<void> {
        if (document.languageId !== 'dart') {
            return;
        }

        const findings = await this.runAnalyzer(document.fileName);
        this.reportFindings(document, findings);
    }

    private runAnalyzer(filePath: string): Promise<Finding[]> {
        return new Promise((resolve, reject) => {
            // Determine path to analyzer script
            // Assuming we are running from the extension source for now, or compiled
            // In production, this should point to the compiled exe or dart script

            const extensionPath = vscode.extensions.getExtension('flusec.flusec')?.extensionPath || '';
            const analyzerScript = path.join(extensionPath, 'flusec', 'dart-analyzer', 'bin', 'analyzer.dart');

            // We use 'dart' command. Ensure it's in PATH or configured.
            const command = `dart run "${analyzerScript}" "${filePath}"`;
            const cwd = path.join(extensionPath, 'flusec', 'dart-analyzer');

            console.log(`Running analyzer: ${command}`);

            cp.exec(command, { cwd: cwd }, (error, stdout, stderr) => {
                if (error) {
                    console.error(`Analyzer error: ${error}`);
                    console.error(`Stderr: ${stderr}`);
                    // If dart is not found, we might want to notify user, but for now just resolve empty
                    resolve([]);
                    return;
                }

                try {
                    const findings: Finding[] = JSON.parse(stdout);
                    resolve(findings);
                } catch (e) {
                    console.error(`Failed to parse analyzer output: ${e}`);
                    resolve([]);
                }
            });
        });
    }

    private reportFindings(document: vscode.TextDocument, findings: Finding[]) {
        const diagnostics: vscode.Diagnostic[] = [];

        for (const finding of findings) {
            // Line numbers from analyzer are 1-based (usually), VS Code is 0-based
            // But wait, our visitor used LineInfo which returns 1-based line numbers?
            // Analyzer LineInfo.getLocation returns 1-based line and column.
            const line = finding.lineNumber > 0 ? finding.lineNumber - 1 : 0;
            const col = finding.columnNumber > 0 ? finding.columnNumber - 1 : 0;

            const range = new vscode.Range(line, col, line, col + finding.codeSnippet.length);

            const severity = this.mapSeverity(finding.severity);

            const diagnostic = new vscode.Diagnostic(range, finding.message, severity);
            diagnostic.source = 'FluSec';
            diagnostic.code = finding.ruleId;
            diagnostic.relatedInformation = [
                new vscode.DiagnosticRelatedInformation(
                    new vscode.Location(document.uri, range),
                    `Remediation: ${finding.remediation}`
                )
            ];

            diagnostics.push(diagnostic);
        }

        this.diagnosticCollection.set(document.uri, diagnostics);
    }

    private mapSeverity(severity: string): vscode.DiagnosticSeverity {
        switch (severity.toUpperCase()) {
            case 'CRITICAL':
            case 'HIGH':
                return vscode.DiagnosticSeverity.Error;
            case 'MEDIUM':
                return vscode.DiagnosticSeverity.Warning;
            case 'LOW':
                return vscode.DiagnosticSeverity.Information;
            default:
                return vscode.DiagnosticSeverity.Hint;
        }
    }

    public dispose() {
        this.diagnosticCollection.dispose();
    }
}
