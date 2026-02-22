// src/diagnostics/hoverLLM.ts
//
// Handles:
// - LLM feedback caching
// - request queue (to avoid too many parallel calls)
// - JSON → Markdown formatting for hover
// - VS Code hover provider registration
// - Component-aware routing: HSD / NET / IDS each have their own LLM prompt
//
// Exposes helpers to reset state when a new analyzer run starts.

import * as vscode from "vscode";
import { getLLMFeedback } from "../hsd/llm.js";
import { getNetLLMFeedback } from "../net/llm.js";
import { getIdsLLMFeedback } from "../ids/llm.js";

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
 * Detect which component a diagnostic belongs to based on its ruleId.
 *
 * Rule ID prefixes:
 *   - FLUSEC.NET*  → net
 *   - FLUSEC.IDS*  → ids
 *   - Everything else (FLUSEC.SEC*, FLUSEC.JWT, FLUSEC.SEC.H*, etc.) → hsd
 */
function detectComponent(diag: vscode.Diagnostic): "hsd" | "net" | "ids" {
  const ruleId = String(diag.code ?? "");

  if (ruleId.startsWith("FLUSEC.NET")) {return "net";}
  if (ruleId.startsWith("FLUSEC.IDS")) {return "ids";}

  // Default: HSD
  return "hsd";
}

/**
 * Enqueue an LLM feedback request for a diagnostic.
 * Routes to the correct component-specific LLM based on the ruleId.
 */
function enqueueLLMRequest(
  key: string,
  message: string,
  codeSnippet: string,
  uri: vscode.Uri,
  range: vscode.Range,
  component: "hsd" | "net" | "ids"
) {
  llmQueue.push(async () => {
    try {
      let feedbackStr: string;

      if (component === "net") {
        // NET component LLM — network security focused prompt
        const netFeedback = await getNetLLMFeedback(message);
        feedbackStr = netFeedback
          ? JSON.stringify(netFeedback)
          : "No feedback returned by LLM.";
      } else if (component === "ids") {
        // IDS component LLM — storage security focused prompt
        const idsFeedback = await getIdsLLMFeedback(message);
        feedbackStr = idsFeedback
          ? JSON.stringify(idsFeedback)
          : "No feedback returned by LLM.";
      } else {
        // HSD component LLM — hardcoded secrets focused prompt (default)
        feedbackStr = await getLLMFeedback(message, codeSnippet);
      }

      feedbackCache.set(key, feedbackStr);

      // Try to re-trigger hover at the diagnostic position
      const editor = vscode.window.visibleTextEditors.find(
        (e) => e.document.uri.toString() === uri.toString()
      );

      if (editor) {
        const pos = range.start;
        editor.selection = new vscode.Selection(pos, pos);
        editor.revealRange(
          range,
          vscode.TextEditorRevealType.InCenterIfOutsideViewport
        );

        // Small delay so VS Code updates selection before showing hover
        setTimeout(() => {
          vscode.commands.executeCommand("editor.action.showHover");
        }, 50);
      }

      const badge = component.toUpperCase();
      vscode.window.setStatusBarMessage(
        `✅ FLUSEC [${badge}]: LLM feedback ready`,
        2000
      );
    } catch (err) {
      console.error(
        `Error fetching ${component.toUpperCase()} LLM feedback:`,
        err
      );
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
  if (processingQueue) {
    return;
  }
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
 * Handles both formats:
 *   HSD: { why, fix, maintainability, example }
 *   NET/IDS: { why, risk, fix, example }
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

    // NET/IDS specific: risk field
    if (obj.risk) {
      md.appendMarkdown(`**Security Impact**: ${obj.risk}\n\n`);
    }

    if (Array.isArray(obj.fix) && obj.fix.length > 0) {
      md.appendMarkdown(`**Fix**:\n`);
      for (const step of obj.fix.slice(0, 3)) {
        md.appendMarkdown(`- ${String(step).replace(/^\d+\.\s*/, "")}\n`);
      }
      md.appendMarkdown(`\n`);
    }

    // HSD specific: maintainability field
    if (obj.maintainability) {
      md.appendMarkdown(`**Maintainability**: ${obj.maintainability}\n\n`);
    }

    if (obj.example && String(obj.example).trim()) {
      md.appendMarkdown(`**Example**:\n\n`);
      md.appendCodeblock(String(obj.example), "dart");
    }

    return md;
  } catch {
    console.log("[FLUSEC] JSON parse failed. Raw:", raw);
    md.appendMarkdown(`### 💡 Educational feedback\n\n`);
    md.appendMarkdown(raw);
    return md;
  }
}

/**
 * Register the hover provider for Dart files.
 * When user hovers over a diagnostic, we either:
 * - show cached feedback
 * - or enqueue a new LLM request (routed to the correct component LLM)
 *   and show a loading message.
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

          // Build a small code snippet around the diagnostic:
          // 2 lines above and 2 lines below for context.
          const startLine = Math.max(0, diag.range.start.line - 2);
          const endLine = Math.min(
            document.lineCount - 1,
            diag.range.end.line + 2
          );
          const snippetRange = new vscode.Range(
            startLine,
            0,
            endLine,
            document.lineAt(endLine).text.length
          );
          const codeSnippet = document.getText(snippetRange);

          // Detect component from ruleId and route to correct LLM
          const component = detectComponent(diag);

          // Enqueue LLM request routed to the correct component
          enqueueLLMRequest(
            key,
            diag.message,
            codeSnippet,
            document.uri,
            diag.range,
            component
          );

          const badge = component.toUpperCase();
          return new vscode.Hover(
            `💡 Loading ${badge} feedback from FLUSEC LLM...`
          );
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