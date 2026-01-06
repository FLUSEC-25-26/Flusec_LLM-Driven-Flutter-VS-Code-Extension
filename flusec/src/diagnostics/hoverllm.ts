// // src/diagnostics/hoverLLM.ts
// //
// // Handles:
// // - LLM feedback caching
// // - request queue (to avoid too many parallel calls)
// // - JSON → Markdown formatting for hover
// // - VS Code hover provider registration
// //
// // Exposes helpers to reset state when a new analyzer run starts.

// import * as vscode from "vscode";
// import { getLLMFeedback } from "../llm.js";

// // Feedback cache keyed by: "<uri>:<line>:<character>"
// const feedbackCache = new Map<string, string>();

// // Queue of pending LLM jobs to execute sequentially.
// const llmQueue: (() => Promise<void>)[] = [];
// let processingQueue = false;

// /**
//  * Build a stable cache key based on document URI + start position.
//  */
// function makeKey(uri: vscode.Uri, range: vscode.Range): string {
//   return `${uri.toString()}:${range.start.line}:${range.start.character}`;
// }

// /**
//  * Enqueue an LLM feedback request for a diagnostic message + code snippet.
//  *
//  * We also carry the URI + range so that when the feedback is ready,
//  * we can programmatically re-show the hover at the correct location
//  * (so the user doesn't have to move the mouse out and back in).
//  */
// function enqueueLLMRequest(
//   key: string,
//   message: string,
//   codeSnippet: string,
//   uri: vscode.Uri,
//   range: vscode.Range
// ) {
//   llmQueue.push(async () => {
//     try {
//       const feedback = await getLLMFeedback(message, codeSnippet);
//       feedbackCache.set(key, feedback);

//       // Try to re-trigger hover at the diagnostic position
//       const editor = vscode.window.visibleTextEditors.find(
//         (e) => e.document.uri.toString() === uri.toString()
//       );

//       if (editor) {
//         const pos = range.start;
//         editor.selection = new vscode.Selection(pos, pos);
//         editor.revealRange(
//           range,
//           vscode.TextEditorRevealType.InCenterIfOutsideViewport
//         );

//         // Small delay so VS Code updates selection before showing hover
//         setTimeout(() => {
//           vscode.commands.executeCommand("editor.action.showHover");
//         }, 50);
//       }

//       vscode.window.setStatusBarMessage("✅ FLUSEC: LLM feedback ready", 2000);
//     } catch (err) {
//       console.error("Error fetching LLM feedback:", err);
//       feedbackCache.set(key, "⚠️ Error fetching LLM feedback.");
//     }
//   });

//   if (!processingQueue) {
//     processQueue();
//   }
// }

// /**
//  * Sequentially process queued LLM jobs.
//  */
// async function processQueue() {
//   if (processingQueue) { return; }
//   processingQueue = true;

//   while (llmQueue.length > 0) {
//     const job = llmQueue.shift();
//     if (job) {
//       await job();
//     }
//   }

//   processingQueue = false;
// }

// /**
//  * Parse LLM JSON response (if possible) into a Markdown hover.
//  * Fallback: show raw string.
//  */
// function formatFeedbackForHover(raw: string): vscode.MarkdownString {
//   const md = new vscode.MarkdownString();
//   md.isTrusted = false;

//   // Try JSON → if it fails, we show raw.
//   try {
//     const obj = JSON.parse(raw);

//     md.appendMarkdown(`### 💡 Educational feedback\n\n`);

//     if (obj.why) {
//       md.appendMarkdown(`**Why**: ${obj.why}\n\n`);
//     }

//     if (Array.isArray(obj.fix) && obj.fix.length > 0) {
//       md.appendMarkdown(`**Fix**:\n`);
//       for (const step of obj.fix.slice(0, 3)) {
//         md.appendMarkdown(`- ${String(step).replace(/^\d+\.\s*/, "")}\n`);
//       }
//       md.appendMarkdown(`\n`);
//     }

//     if (obj.maintainability) {
//       md.appendMarkdown(`**Maintainability**: ${obj.maintainability}\n\n`);
//     }

//     if (obj.example && String(obj.example).trim()) {
//       md.appendMarkdown(`**Example**:\n\n`);
//       md.appendCodeblock(String(obj.example), "dart");
//     }

//     return md;
//   } catch {
//     console.log("[FLUSEC] JSON parse failed. Raw:", raw);
//     md.appendMarkdown(`### 💡 Educational feedback\n\n`);
//     md.appendMarkdown(raw);
//     return md;
//   }
// }

// /**
//  * Register the hover provider for Dart files.
//  * When user hovers over a diagnostic, we either:
//  * - show cached feedback
//  * - or enqueue a new LLM request and show a loading message.
//  */
// export function registerHoverProvider(context: vscode.ExtensionContext) {
//   const provider = vscode.languages.registerHoverProvider("dart", {
//     provideHover: async (document, position) => {
//       const diags = vscode.languages.getDiagnostics(document.uri);

//       for (const diag of diags) {
//         if (diag.range.contains(position)) {
//           const key = makeKey(document.uri, diag.range);

//           // If we already have feedback, show it immediately.
//           if (feedbackCache.has(key)) {
//             return new vscode.Hover(
//               formatFeedbackForHover(feedbackCache.get(key)!)
//             );
//           }

//           // Build a small code snippet around the diagnostic:
//           // 2 lines above and 2 lines below for context.
//           const startLine = Math.max(0, diag.range.start.line - 2);
//           const endLine = Math.min(
//             document.lineCount - 1,
//             diag.range.end.line + 2
//           );
//           const snippetRange = new vscode.Range(
//             startLine,
//             0,
//             endLine,
//             document.lineAt(endLine).text.length
//           );
//           const codeSnippet = document.getText(snippetRange);

//           // Enqueue LLM request with both the message and the code snippet.
//           enqueueLLMRequest(
//             key,
//             diag.message,
//             codeSnippet,
//             document.uri,
//             diag.range
//           );

//           return new vscode.Hover("💡 Loading feedback from FLUSEC LLM...");
//         }
//       }

//       return undefined;
//     },
//   });

//   context.subscriptions.push(provider);
// }

// /**
//  * Reset global LLM queue state before starting a new analysis pass.
//  */
// export function resetLLMState() {
//   llmQueue.length = 0;
//   processingQueue = false;
// }

// /**
//  * Remove cached feedback entries associated with a specific document.
//  * Called from runAnalyzer() after fresh findings are generated.
//  */
// export function clearFeedbackForDocument(uri: vscode.Uri) {
//   for (const key of Array.from(feedbackCache.keys())) {
//     if (key.startsWith(uri.toString())) {
//       feedbackCache.delete(key);
//     }
//   }
// }








// src/diagnostics/hoverLLM.ts
//
// Handles:
// - LLM feedback caching
// - request queue (to avoid too many parallel calls)
// - JSON → Markdown formatting for hover
// - VS Code hover provider registration

import * as vscode from "vscode";
import { getLLMFeedback } from "../llm.js"; // Ensure path matches your project structure

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
 * Enqueue an LLM feedback request for a diagnostic message + code snippet.
 */
function enqueueLLMRequest(
  key: string,
  message: string,
  codeSnippet: string,
  uri: vscode.Uri,
  range: vscode.Range
) {
  llmQueue.push(async () => {
    try {
      // DEBUG LOG: See if request starts
      console.log(`[FLUSEC] Requesting LLM for: ${message}`);
      
      const feedback = await getLLMFeedback(message, codeSnippet);
      feedbackCache.set(key, feedback);

      // Try to re-trigger hover at the diagnostic position
      const editor = vscode.window.visibleTextEditors.find(
        (e) => e.document.uri.toString() === uri.toString()
      );

      if (editor) {
        const pos = range.start;
        // Optional: Move cursor to force update, or just trigger hover
        // editor.selection = new vscode.Selection(pos, pos);
        
        // Small delay so VS Code updates before showing hover
        setTimeout(() => {
          // This command forces VS Code to refresh the hover UI
          vscode.commands.executeCommand("editor.action.showHover");
        }, 500);
      }

      vscode.window.setStatusBarMessage("✅ FLUSEC: LLM feedback ready", 2000);
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
  if (processingQueue) { return; }
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
 */
function formatFeedbackForHover(raw: string): vscode.MarkdownString {
  const md = new vscode.MarkdownString();
  md.isTrusted = true; // Allow rendering content safely

  try {
    const obj = JSON.parse(raw);

    md.appendMarkdown(`### 💡 **Flusec Security Insight**\n\n`);

    if (obj.why) {
      md.appendMarkdown(`**⚠️ Why is this dangerous?**\n${obj.why}\n\n`);
    }

    if (Array.isArray(obj.fix) && obj.fix.length > 0) {
      md.appendMarkdown(`**🛡️ How to Fix:**\n`);
      for (const step of obj.fix.slice(0, 3)) {
        md.appendMarkdown(`- ${String(step).replace(/^\d+\.\s*/, "")}\n`);
      }
      md.appendMarkdown(`\n`);
    }

    if (obj.maintainability) {
      md.appendMarkdown(`**📊 Maintainability**: ${obj.maintainability}\n\n`);
    }

    if (obj.example && String(obj.example).trim()) {
      md.appendMarkdown(`**📝 Secure Example**:\n\n`);
      md.appendCodeblock(String(obj.example), "dart");
    }

    return md;
  } catch {
    // If raw string, just show it
    md.appendMarkdown(`### 💡 **Flusec Insight**\n\n`);
    md.appendMarkdown(raw);
    return md;
  }
}

/**
 * Register the hover provider for Dart files.
 */
export function registerHoverProvider(context: vscode.ExtensionContext) {
  const provider = vscode.languages.registerHoverProvider("dart", {
    provideHover: async (document, position) => {
      const diags = vscode.languages.getDiagnostics(document.uri);

      for (const diag of diags) {
        if (diag.range.contains(position)) {
          
          // ============================================================
          // 🛑 CRITICAL FIX: IGNORE NON-FLUSEC ERRORS
          // ============================================================
          if (diag.source !== 'flusec') {
             // If this is a standard Dart error (red squiggle), ignore it.
             // We only want to trigger AI for our own Yellow Warnings.
             continue; 
          }

          const key = makeKey(document.uri, diag.range);

          // 1. If we already have feedback, show it.
          if (feedbackCache.has(key)) {
            return new vscode.Hover(
              formatFeedbackForHover(feedbackCache.get(key)!)
            );
          }

          // 2. Prepare code context
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

          // 3. Enqueue LLM request
          enqueueLLMRequest(
            key,
            diag.message,
            codeSnippet,
            document.uri,
            diag.range
          );

          // 4. Show Loading State immediately
          return new vscode.Hover("💡 **Flusec AI**: Analyzing vulnerability... please wait.");
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