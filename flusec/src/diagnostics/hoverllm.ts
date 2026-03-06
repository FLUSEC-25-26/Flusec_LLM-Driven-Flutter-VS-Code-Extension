import * as vscode from "vscode";
import { getLLMFeedback } from "../llm.js";

const feedbackCache = new Map<string, string>();
const llmQueue: (() => Promise<void>)[] = [];
let processingQueue = false;

function makeKey(uri: vscode.Uri, range: vscode.Range): string {
  return `${uri.toString()}:${range.start.line}:${range.start.character}`;
}

function enqueueLLMRequest(key: string, message: string, codeSnippet: string, uri: vscode.Uri, range: vscode.Range) {
  llmQueue.push(async () => {
    try {
      const feedback = await getLLMFeedback(message, codeSnippet);
      feedbackCache.set(key, feedback);

      const editor = vscode.window.visibleTextEditors.find((e) => e.document.uri.toString() === uri.toString());
      if (editor) {
        const pos = range.start;
        editor.selection = new vscode.Selection(pos, pos);
        setTimeout(() => {
          vscode.commands.executeCommand("editor.action.showHover");
        }, 50);
      }
      vscode.window.setStatusBarMessage("✅ FLUSEC: LLM feedback ready", 2000);
    } catch (err) {
      feedbackCache.set(key, "⚠️ Error fetching LLM feedback.");
    }
  });

  if (!processingQueue) processQueue();
}

async function processQueue() {
  if (processingQueue) return;
  processingQueue = true;
  while (llmQueue.length > 0) {
    const job = llmQueue.shift();
    if (job) await job();
  }
  processingQueue = false;
}

function formatFeedbackForHover(raw: string): vscode.MarkdownString {
  const md = new vscode.MarkdownString();
  md.isTrusted = false;

  try {
    const obj = JSON.parse(raw);
    md.appendMarkdown(`### 💡 Security Feedback (IVD)\n\n`);

    if (obj.why) md.appendMarkdown(`**Vulnerability**: ${obj.why}\n\n`);

    if (Array.isArray(obj.fix)) {
      md.appendMarkdown(`**Recommended Fix**:\n`);
      for (const step of obj.fix) {
        md.appendMarkdown(`- ${String(step)}\n`);
      }
      md.appendMarkdown(`\n`);
    }

    if (obj.example) {
      md.appendMarkdown(`**Secure Code Example**:\n\n`);
      md.appendCodeblock(String(obj.example), "dart");
    }
    return md;
  } catch {
    md.appendMarkdown(`### 💡 Security Feedback\n\n${raw}`);
    return md;
  }
}

export function registerHoverProvider(context: vscode.ExtensionContext) {
  const provider = vscode.languages.registerHoverProvider("dart", {
    provideHover: async (document, position) => {
      const diags = vscode.languages.getDiagnostics(document.uri);
      for (const diag of diags) {
        if (diag.range.contains(position)) {
          const key = makeKey(document.uri, diag.range);
          if (feedbackCache.has(key)) {
            return new vscode.Hover(formatFeedbackForHover(feedbackCache.get(key)!));
          }

          const startLine = Math.max(0, diag.range.start.line - 2);
          const endLine = Math.min(document.lineCount - 1, diag.range.end.line + 2);
          const codeSnippet = document.getText(new vscode.Range(startLine, 0, endLine, document.lineAt(endLine).text.length));

          enqueueLLMRequest(key, diag.message, codeSnippet, document.uri, diag.range);
          return new vscode.Hover("💡 Loading educational security feedback...");
        }
      }
      return undefined;
    },
  });
  context.subscriptions.push(provider);
}

export function resetLLMState() {
    llmQueue.length = 0;
    processingQueue = false;
}

export function clearFeedbackForDocument(uri: vscode.Uri) {
    for (const key of Array.from(feedbackCache.keys())) {
        if (key.startsWith(uri.toString())) {
            feedbackCache.delete(key);
        }
    }
}