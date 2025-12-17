// src/hover/llmQueue.ts
//
// Shared LLM queue + cache.
// This avoids spamming Ollama when user moves mouse across diagnostics.
// Also avoids multiple simultaneous calls.
//
// ✅ Shared for ALL components because hover reads diagnostics, not component type.

import * as vscode from "vscode";
import { getLLMFeedback } from "../llm";

const feedbackCache = new Map<string, string>();
const llmQueue: (() => Promise<void>)[] = [];
let processingQueue = false;

export function makeKey(uri: vscode.Uri, range: vscode.Range) {
  return `${uri.toString()}:${range.start.line}:${range.start.character}`;
}

export function getCachedFeedback(key: string): string | undefined {
  return feedbackCache.get(key);
}

export function clearCacheForDocument(docUri: vscode.Uri) {
  for (const key of Array.from(feedbackCache.keys())) {
    if (key.startsWith(docUri.toString())) feedbackCache.delete(key);
  }
}

export function enqueueLLMRequest(key: string, message: string) {
  llmQueue.push(async () => {
    try {
      const feedback = await getLLMFeedback(message);
      feedbackCache.set(key, feedback);

      // Double-trigger hover refresh to reduce delay
      vscode.commands.executeCommand("editor.action.showHover");
      setTimeout(() => vscode.commands.executeCommand("editor.action.showHover"), 500);

      vscode.window.setStatusBarMessage("✅ LLM feedback ready", 2000);
    } catch (err) {
      console.error("Error fetching LLM feedback:", err);
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
