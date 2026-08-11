// src/diagnostics/hoverllm.ts
//
// FLUSEC educational-feedback hover integration.
// - Provider-agnostic (VS Code Language Model API or Ollama)
// - Default provider is VS Code Language Model API
// - Sequential request queue to reduce quota/rate-limit pressure
// - Per-diagnostic cache and duplicate-request suppression
// - HSD source context is redacted before it reaches any provider
// - Static analysis never depends on LLM availability

import * as vscode from 'vscode';
import {
  getConfiguredLlmProvider,
  getLlmProviderDisplayName,
  requestEducationalFeedback,
} from '../llm/feedbackService.js';
import type {
  LlmComponent,
  LlmFeedbackResult,
} from '../llm/types.js';

// Cache key: "<uri>:<line>:<character>"
const feedbackCache = new Map<string, LlmFeedbackResult>();
const pendingKeys = new Set<string>();

// Keep LLM work sequential. This is safer for provider quotas and prevents a
// hover over several findings from starting many expensive requests at once.
const llmQueue: Array<() => Promise<void>> = [];
let processingQueue = false;

function makeKey(uri: vscode.Uri, range: vscode.Range): string {
  return `${uri.toString()}:${range.start.line}:${range.start.character}`;
}

function detectComponent(diag: vscode.Diagnostic): LlmComponent {
  const ruleId = String(diag.code ?? '');

  if (ruleId.startsWith('FLUSEC.NET')) { return 'net'; }
  if (ruleId.startsWith('FLUSEC.IDS')) { return 'ids'; }
  if (ruleId.startsWith('FLUSEC.IIV')) { return 'iiv'; }
  return 'hsd';
}

function providerLoadingText(): string {
  const provider = getConfiguredLlmProvider();
  return getLlmProviderDisplayName(provider);
}

function appendParagraph(
  markdown: vscode.MarkdownString,
  label: string,
  value: string,
): void {
  if (!value.trim()) { return; }
  markdown.appendMarkdown(`**${label}**: `);
  markdown.appendText(value.trim());
  markdown.appendMarkdown('\n\n');
}

function formatFeedbackForHover(result: LlmFeedbackResult): vscode.MarkdownString {
  const markdown = new vscode.MarkdownString();
  markdown.isTrusted = false;
  markdown.supportHtml = false;

  if (result.status === 'disabled') {
    markdown.appendMarkdown('### 💡 FLUSEC educational feedback\n\n');
    markdown.appendText(result.message);
    return markdown;
  }

  if (result.status === 'unavailable' || result.status === 'error') {
    markdown.appendMarkdown('### 💡 Educational feedback unavailable\n\n');
    markdown.appendMarkdown('**Provider**: ');
    markdown.appendText(result.providerLabel);
    markdown.appendMarkdown('\n\n');
    markdown.appendText(result.message);
    markdown.appendMarkdown('\n\n');
    markdown.appendText(
      'The FLUSEC static-analysis finding remains valid; only the optional LLM explanation is unavailable.',
    );
    return markdown;
  }

  const { feedback } = result;
  markdown.appendMarkdown('### 💡 FLUSEC educational feedback\n\n');

  appendParagraph(markdown, 'Why', feedback.why);
  appendParagraph(markdown, 'Security impact', feedback.risk);

  if (feedback.fix.length > 0) {
    markdown.appendMarkdown('**Fix**:\n');
    for (const step of feedback.fix.slice(0, 3)) {
      markdown.appendMarkdown('- ');
      markdown.appendText(step.replace(/^\d+\.\s*/, ''));
      markdown.appendMarkdown('\n');
    }
    markdown.appendMarkdown('\n');
  }

  if (feedback.example.trim()) {
    markdown.appendMarkdown('**Example**:\n\n');
    markdown.appendCodeblock(feedback.example.trim(), 'dart');
    markdown.appendMarkdown('\n');
  }

  markdown.appendMarkdown('---\n\n');
  markdown.appendMarkdown('**LLM provider**: ');
  markdown.appendText(result.providerLabel);
  if (result.modelLabel.trim()) {
    markdown.appendMarkdown(' · **Model**: ');
    markdown.appendText(result.modelLabel);
  }

  return markdown;
}

function showHoverAgain(uri: vscode.Uri, range: vscode.Range): void {
  const editor = vscode.window.visibleTextEditors.find(
    (candidate) => candidate.document.uri.toString() === uri.toString(),
  );

  if (!editor) { return; }

  const position = range.start;
  editor.selection = new vscode.Selection(position, position);
  editor.revealRange(range, vscode.TextEditorRevealType.InCenterIfOutsideViewport);

  setTimeout(() => {
    void vscode.commands.executeCommand('editor.action.showHover');
  }, 50);
}

function enqueueLlmRequest(
  key: string,
  message: string,
  codeSnippet: string,
  uri: vscode.Uri,
  range: vscode.Range,
  component: LlmComponent,
): void {
  if (pendingKeys.has(key)) { return; }
  pendingKeys.add(key);

  llmQueue.push(async () => {
    try {
      const result = await requestEducationalFeedback(
        component,
        message,
        codeSnippet,
      );
      feedbackCache.set(key, result);

      const badge = component.toUpperCase();
      if (result.status === 'ok') {
        vscode.window.setStatusBarMessage(
          `FLUSEC [${badge}]: Educational feedback ready via ${result.providerLabel}`,
          2500,
        );
      } else if (result.status !== 'disabled') {
        vscode.window.setStatusBarMessage(
          `FLUSEC [${badge}]: LLM feedback unavailable`,
          2500,
        );
      }

      showHoverAgain(uri, range);
    } catch (error) {
      console.error('[FLUSEC] Unexpected LLM feedback error:', error);
      feedbackCache.set(key, {
        status: 'error',
        provider: getConfiguredLlmProvider() === 'ollama' ? 'ollama' : 'vscode',
        providerLabel: providerLoadingText(),
        message: error instanceof Error ? error.message : String(error),
      });
    } finally {
      pendingKeys.delete(key);
    }
  });

  if (!processingQueue) {
    void processQueue();
  }
}

async function processQueue(): Promise<void> {
  if (processingQueue) { return; }
  processingQueue = true;

  try {
    while (llmQueue.length > 0) {
      const job = llmQueue.shift();
      if (job) { await job(); }
    }
  } finally {
    processingQueue = false;
  }
}

function buildCodeSnippet(
  document: vscode.TextDocument,
  diagnostic: vscode.Diagnostic,
): string {
  const startLine = Math.max(0, diagnostic.range.start.line - 2);
  const endLine = Math.min(
    document.lineCount - 1,
    diagnostic.range.end.line + 2,
  );

  const snippetRange = new vscode.Range(
    startLine,
    0,
    endLine,
    document.lineAt(endLine).text.length,
  );

  return document.getText(snippetRange);
}

export function registerHoverProvider(context: vscode.ExtensionContext): void {
  const provider = vscode.languages.registerHoverProvider('dart', {
    provideHover: async (document, position) => {
      const diagnostics = vscode.languages.getDiagnostics(document.uri);

      for (const diagnostic of diagnostics) {
        if (!diagnostic.range.contains(position)) { continue; }

        const key = makeKey(document.uri, diagnostic.range);
        const cached = feedbackCache.get(key);
        if (cached) {
          return new vscode.Hover(formatFeedbackForHover(cached));
        }

        const configuredProvider = getConfiguredLlmProvider();
        if (configuredProvider === 'disabled') {
          const disabled: LlmFeedbackResult = {
            status: 'disabled',
            provider: 'disabled',
            providerLabel: 'Disabled',
            message: 'LLM educational feedback is disabled. FLUSEC static-analysis findings are unaffected.',
          };
          feedbackCache.set(key, disabled);
          return new vscode.Hover(formatFeedbackForHover(disabled));
        }

        const component = detectComponent(diagnostic);
        const codeSnippet = buildCodeSnippet(document, diagnostic);

        enqueueLlmRequest(
          key,
          diagnostic.message,
          codeSnippet,
          document.uri,
          diagnostic.range,
          component,
        );

        return new vscode.Hover(
          `💡 Loading ${component.toUpperCase()} educational feedback using ${providerLoadingText()}...`,
        );
      }

      return undefined;
    },
  });

  context.subscriptions.push(provider);
}

/**
 * Reset queued work before a fresh analyzer pass. Existing cached feedback is
 * cleared separately per document so unchanged documents can keep their cache.
 */
export function resetLLMState(): void {
  llmQueue.length = 0;
  pendingKeys.clear();
  processingQueue = false;
}

export function clearFeedbackForDocument(uri: vscode.Uri): void {
  const prefix = uri.toString();
  for (const key of Array.from(feedbackCache.keys())) {
    if (key.startsWith(prefix)) { feedbackCache.delete(key); }
  }

  for (const key of Array.from(pendingKeys)) {
    if (key.startsWith(prefix)) { pendingKeys.delete(key); }
  }
}

/** Clear all cached feedback when the configured provider/model changes. */
export function clearAllFeedback(): void {
  feedbackCache.clear();
  pendingKeys.clear();
  llmQueue.length = 0;
  processingQueue = false;
}
