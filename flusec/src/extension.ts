//extension.ts
import * as vscode from "vscode";
import { execFile } from "child_process";
import * as path from "path";
import * as fs from "fs";
import { getLLMFeedback } from "../src/llm.js";
import { openRuleManager } from "./ui/ruleManager/hardcoded_secrets/ruleManager.js";

// -------------------------------
// LLM hover feedback support
// -------------------------------
const feedbackCache = new Map<string, string>();
const llmQueue: (() => Promise<void>)[] = [];
let processingQueue = false;

function makeKey(uri: vscode.Uri, range: vscode.Range) {
  return `${uri.toString()}:${range.start.line}:${range.start.character}`;
}

function enqueueLLMRequest(key: string, message: string) {
  llmQueue.push(async () => {
    try {
      const feedback = await getLLMFeedback(message);
      feedbackCache.set(key, feedback);

      //  Double-trigger hover refresh to reduce delay
      vscode.commands.executeCommand("editor.action.showHover");
      setTimeout(() => vscode.commands.executeCommand("editor.action.showHover"), 500);

      vscode.window.setStatusBarMessage("✅ LLM feedback ready", 2000);
    } catch (err) {
      console.error("Error fetching LLM feedback:", err);
      feedbackCache.set(key, "⚠️ Error fetching LLM feedback.");
    }
  });

  if (!processingQueue) {processQueue();}
}

async function processQueue() {
  if (processingQueue) {return;}
  processingQueue = true;
  while (llmQueue.length > 0) {
    const job = llmQueue.shift();
    if (job) {await job();}
  }
  processingQueue = false;
}

// ----------------------------------------
// Helpers
// ----------------------------------------
function findWorkspaceFolderForDoc(
  doc: vscode.TextDocument
): vscode.WorkspaceFolder | undefined {
  return (
    vscode.workspace.getWorkspaceFolder(doc.uri) ??
    vscode.workspace.workspaceFolders?.[0]
  );
}

function findingsPathForFolder(folder: vscode.WorkspaceFolder): string {
  return path.join(folder.uri.fsPath, "dart-analyzer", ".out", "findings.json");
}

function ensureDirForFile(filePath: string) {
  const dir = path.dirname(filePath);
  if (!fs.existsSync(dir)) {fs.mkdirSync(dir, { recursive: true });}
}

function formatFeedbackForHover(raw: string): vscode.MarkdownString {
  const md = new vscode.MarkdownString();
  md.isTrusted = false;

  try {
    const obj = JSON.parse(raw);

    md.appendMarkdown(`### 💡 Educational feedback\n\n`);

    if (obj.why) {
      md.appendMarkdown(`**Why**: ${obj.why}\n\n`);
    }

    if (Array.isArray(obj.fix) && obj.fix.length > 0) {
      md.appendMarkdown(`**Fix**:\n`);
      for (const step of obj.fix.slice(0, 3)) {
        md.appendMarkdown(`- ${String(step).replace(/^\d+\.\s*/, "")}\n`);
      }
      md.appendMarkdown(`\n`);
    }

    if (obj.example && String(obj.example).trim()) {
      md.appendMarkdown(`**Example**:\n\n`);
      md.appendCodeblock(String(obj.example), "dart");
    }

    return md;
  } catch {
    // fallback if JSON parsing fails
    md.appendMarkdown(`### 💡 Educational feedback\n\n`);
    md.appendMarkdown(raw);
    return md;
  }
}


// ----------------------------------------
// Diagnostics
// ----------------------------------------
const diagCollection = vscode.languages.createDiagnosticCollection("flusec");

function severityToVS(sev: string): vscode.DiagnosticSeverity {
  return sev?.toLowerCase() === "error"
    ? vscode.DiagnosticSeverity.Error
    : vscode.DiagnosticSeverity.Warning;
}

function refreshDiagnosticsFromFindings(fp: string) {
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
    const endCol = col + Math.max(1, (f.snippet?.length ?? 80));

    const cx =
      typeof f.complexity === "number" ? ` (Cx: ${f.complexity})` : "";
    const diag = new vscode.Diagnostic(
      new vscode.Range(line, col, line, endCol),
      `[${f.ruleId}] ${f.message || ""}${cx}`,
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

function upsertFindingsForDoc(
  findingsFilePath: string,
  doc: vscode.TextDocument,
  newFindings: Array<{
    ruleId: string;
    severity: string;
    message: string;
    line: number;
    column: number;
    functionName?: string;
    complexity?: number;
  }>
){
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
      severity: f.severity || "warning",
      // NEW:
      functionName: (f as any).functionName,
      complexity: (f as any).complexity,
    });
  }


  fs.writeFileSync(findingsFilePath, JSON.stringify(all, null, 2), "utf8");
  refreshDiagnosticsFromFindings(findingsFilePath);
}

// ----------------------------------------
// Hover provider
// ----------------------------------------
function registerHoverProvider(context: vscode.ExtensionContext) {
  const provider = vscode.languages.registerHoverProvider("dart", {
    provideHover: async (document, position) => {
      const diags = vscode.languages.getDiagnostics(document.uri);
      for (const diag of diags) {
        if (diag.range.contains(position)) {
          const key = makeKey(document.uri, diag.range);

          if (feedbackCache.has(key)) {
            return new vscode.Hover(
               formatFeedbackForHover(feedbackCache.get(key)!)
           );
         }


          enqueueLLMRequest(key, diag.message);
          return new vscode.Hover("💡 Loading feedback from LLM...");
        }
      }
      return undefined;
    },
  });
  context.subscriptions.push(provider);
}

// ----------------------------------------
// Activation
// ----------------------------------------
export function activate(context: vscode.ExtensionContext) {
  context.subscriptions.push(diagCollection);

  // Manual scan
  context.subscriptions.push(
    vscode.commands.registerCommand("flusec.scanFile", async () => {
      const editor = vscode.window.activeTextEditor;
      if (editor) {await runAnalyzer(editor.document, context);}
    })
  );

  context.subscriptions.push(
    vscode.commands.registerCommand("flusec.manageRules", () => openRuleManager(context))
  );

  context.subscriptions.push(
    vscode.commands.registerCommand("flusec.openFindings", () => openDashboard(context))
  );

   //  AUTO scan on SAVE
  context.subscriptions.push(
    vscode.workspace.onDidSaveTextDocument(async (doc) => {
      if (doc.languageId === "dart") {
        await runAnalyzer(doc, context);
      }
    })
  );

  //  AUTO scan while TYPING
  let typingTimeout: NodeJS.Timeout | undefined;

  context.subscriptions.push(
    vscode.workspace.onDidChangeTextDocument((event) => {
      const doc = event.document;
      if (doc.languageId !== "dart") {return;}

      clearTimeout(typingTimeout);
      typingTimeout = setTimeout(() => {
        runAnalyzer(doc, context);
      }, 1500);
    })
  );

  registerHoverProvider(context);
}

export function deactivate() {
  diagCollection.clear();
  diagCollection.dispose();
}

// ----------------------------------------
// Analyzer
// ----------------------------------------
async function runAnalyzer(doc: vscode.TextDocument, context: vscode.ExtensionContext) {

  // clear old LLM queue & state before new scan
  llmQueue.length = 0;
  processingQueue = false;

  const folder = findWorkspaceFolderForDoc(doc);
  if (!folder) {
    vscode.window.showErrorMessage("No workspace folder found for this document.");
    return;
  }
  const findingsFile = findingsPathForFolder(folder);
  const analyzerPath = path.join(__dirname, "..", "dart-analyzer", "bin", "analyzer.exe");
  if (!fs.existsSync(analyzerPath)) {
    vscode.window.showErrorMessage(`Analyzer not found at path: ${analyzerPath}`);
    return;
  }

  execFile(analyzerPath, [doc.fileName], { shell: true }, (err, stdout, stderr) => {
    if (err) {
      console.error("Analyzer execution error:", err);
      return;
    }
    if (stderr) {console.error("Analyzer stderr:", stderr);}

    let findings: any[] = [];
    try {
      findings = JSON.parse(stdout);
    } catch (e) {
      console.error("Failed to parse analyzer output:", e);
      return;
    }

    for (const key of Array.from(feedbackCache.keys())) {
      if (key.startsWith(doc.uri.toString())) {feedbackCache.delete(key);}
    }

    const diags: vscode.Diagnostic[] = [];
    for (const f of findings) {
      const lineIdx = Math.max(0, f.line - 1);
      const text = doc.lineAt(lineIdx).text;
      const range = new vscode.Range(lineIdx, 0, lineIdx, text.length);

      const cx =
        typeof f.complexity === "number"
          ? ` (Complexity: ${f.complexity})`
          : "";
      const message = `${f.message}${cx}`;

      const diag = new vscode.Diagnostic(
        range,
        message,
        severityToVS(f.severity || "warning")
      );
      diag.source = "flusec";
      diag.code = f.ruleId;
      diags.push(diag);

      // 🧠 Prefetch feedback immediately after scan (now with complexity in prompt)
   //   const key = makeKey(doc.uri, range);
   //   if (!feedbackCache.has(key)) {
   //     enqueueLLMRequest(key, message);
   //   }
    }


    diagCollection.set(doc.uri, diags);
    upsertFindingsForDoc(findingsFile, doc, findings);
  });
}

// ----------------------------------------
// Dashboard webview
// ----------------------------------------
function openDashboard(context: vscode.ExtensionContext) {
  const panel = vscode.window.createWebviewPanel(
    "flusecDashboard",
    "Flusec Findings",
    vscode.ViewColumn.Beside,
    { enableScripts: true, retainContextWhenHidden: true }
  );
  const htmlPath = path.join(context.extensionUri.fsPath, "web", "dashboard.html");
  panel.webview.html = fs.existsSync(htmlPath)
    ? fs.readFileSync(htmlPath, "utf8")
    : "<html><body>Dashboard not found</body></html>";
}

