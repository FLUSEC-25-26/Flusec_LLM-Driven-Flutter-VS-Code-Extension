// src/diagnostics/hoverLLM.ts
//
// Handles:
// - LLM feedback caching
// - request queue (to avoid too many parallel calls)
// - JSON → Markdown formatting for hover
// - VS Code hover provider registration
//
// Exposes helpers to reset state when a new analyzer run starts.

import * as vscode from "vscode";
import { getLLMFeedback } from "../llm.js";

// Feedback cache keyed by: "<uri>:<line>:<character>"
const feedbackCache = new Map<string, string>();

// Queue of pending LLM jobs to execute sequentially.
const llmQueue: (() => Promise<void>)[] = [];
let processingQueue = false;

/**
 * Build a stable cache key based on document URI + start position.
 */
function makeKey(uri: vscode.Uri, range: vscode.Range): string {
  return `${uri.toString()}:${range.start.line}:${range.start.character}`;
}

/**
 * Enqueue an LLM feedback request for a diagnostic message.
 */
function enqueueLLMRequest(key: string, message: string, codeSnippet: string) {
  llmQueue.push(async () => {
    try {
      const feedback = await getLLMFeedback(message,codeSnippet);
      feedbackCache.set(key, feedback);

      // Double-trigger hover refresh to reduce perceived delay.
      vscode.commands.executeCommand("editor.action.showHover");
      setTimeout(
        () => vscode.commands.executeCommand("editor.action.showHover"),
        500
      );

      vscode.window.setStatusBarMessage("✅ LLM feedback ready", 2000);
    } catch (err) {
      console.error("Error fetching LLM feedback:", err);
      feedbackCache.set(key, "⚠️ Error fetching LLM feedback.");
    }
  });

  if (!processingQueue) {
    processQueue();
  }
}

/**
 * Sequentially process queued LLM jobs.
 */
async function processQueue() {
  if (processingQueue) {return;}
  processingQueue = true;

  while (llmQueue.length > 0) {
    const job = llmQueue.shift();
    if (job) {
      await job();
    }
  }

  processingQueue = false;
}

/**
 * Parse LLM JSON response (if possible) into a Markdown hover.
 * Fallback: show raw string.
 */
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

    // 🔹 NEW — maintainability if provided
    if (obj.maintainability) {
      md.appendMarkdown(`**Maintainability**: ${obj.maintainability}\n\n`);
    }

    if (obj.example && String(obj.example).trim()) {
      md.appendMarkdown(`**Example**:\n\n`);
      md.appendCodeblock(String(obj.example), "dart");
    }

    return md;
  } catch {
    // Fallback if JSON parsing fails → plain text.
     console.log("[Flusec] JSON parse failed. Raw:", raw);
    md.appendMarkdown(`### 💡 Educational feedback\n\n`);
    md.appendMarkdown(raw);
    return md;
  }
}

/**
 * Register the hover provider for Dart files.
 * When user hovers over a diagnostic, we either:
 * - show cached feedback
 * - or enqueue a new LLM request and show a loading message.
 */
export function registerHoverProvider(context: vscode.ExtensionContext) {
  const provider = vscode.languages.registerHoverProvider("dart", {
    provideHover: async (document, position) => {
      const diags = vscode.languages.getDiagnostics(document.uri);

      for (const diag of diags) {
        if (diag.range.contains(position)) {
          const key = makeKey(document.uri, diag.range);

          // If we already have feedback, show it immediately.
          if (feedbackCache.has(key)) {
            return new vscode.Hover(
              formatFeedbackForHover(feedbackCache.get(key)!)
            );
          }

          // Build a small code snippet around the diagnostic.
          // Here we take 2 lines above and 2 lines below for context.
          const doc = document;
          const startLine = Math.max(0, diag.range.start.line - 2);
          const endLine = Math.min(doc.lineCount - 1, diag.range.end.line + 2);
          const snippetRange = new vscode.Range(
            startLine,
            0,
            endLine,
            doc.lineAt(endLine).text.length
          );
          const codeSnippet = doc.getText(snippetRange);

          // Enqueue LLM request with both the message and the code snippet.
          enqueueLLMRequest(key, diag.message, codeSnippet);
          return new vscode.Hover("💡 Loading feedback from LLM...");
        }
      }

      return undefined;
    },
  });

  context.subscriptions.push(provider);
}

/**
 * Reset global LLM queue state before starting a new analysis pass.
 */
export function resetLLMState() {
  llmQueue.length = 0;
  processingQueue = false;
}

/**
 * Remove cached feedback entries associated with a specific document.
 * Called from runAnalyzer() after fresh findings are generated.
 */
export function clearFeedbackForDocument(uri: vscode.Uri) {
  for (const key of Array.from(feedbackCache.keys())) {
    if (key.startsWith(uri.toString())) {
      feedbackCache.delete(key);
    }
  }
}



