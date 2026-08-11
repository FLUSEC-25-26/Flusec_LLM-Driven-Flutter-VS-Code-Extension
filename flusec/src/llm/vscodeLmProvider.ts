// src/llm/vscodeLmProvider.ts
// Default FLUSEC provider using VS Code's official Language Model API.

import * as vscode from 'vscode';
import type { ProviderRawResponse, ProviderTestResult } from './types.js';

function config() {
  return vscode.workspace.getConfiguration('flusec');
}

function getTimeoutMs(): number {
  const seconds = config().get<number>('llmTimeoutSeconds', 60);
  const safeSeconds = Number.isFinite(seconds) ? Math.min(Math.max(seconds, 5), 180) : 60;
  return safeSeconds * 1000;
}

function modelLabel(model: vscode.LanguageModelChat): string {
  const parts = [model.vendor, model.family, model.version]
    .map((part) => String(part ?? '').trim())
    .filter(Boolean);
  return parts.length ? parts.join(' / ') : model.id;
}

async function selectPreferredModel(): Promise<vscode.LanguageModelChat | undefined> {
  const modelId = config().get<string>('vscodeLmModelId', '').trim();
  const vendor = config().get<string>('vscodeLmVendor', 'copilot').trim();

  if (modelId) {
    const exact = await vscode.lm.selectChatModels({ id: modelId });
    if (exact.length > 0) { return exact[0]; }
  }

  if (vendor) {
    const vendorModels = await vscode.lm.selectChatModels({ vendor });
    if (vendorModels.length > 0) { return vendorModels[0]; }
  }

  // Defensive fallback: another VS Code model provider might be installed even
  // when the preferred vendor is unavailable.
  const allModels = await vscode.lm.selectChatModels();
  return allModels[0];
}

async function collectText(response: vscode.LanguageModelChatResponse): Promise<string> {
  let text = '';
  for await (const fragment of response.text) {
    text += fragment;
  }
  return text.trim();
}

function languageModelErrorMessage(error: unknown): string {
  if (error instanceof vscode.LanguageModelError) {
    const code = String(error.code ?? '').trim();
    const detail = code ? ` (${code})` : '';
    return `VS Code Language Model request failed${detail}: ${error.message}`;
  }

  if (error instanceof Error) { return error.message; }
  return String(error);
}

async function sendRequest(
  model: vscode.LanguageModelChat,
  messages: vscode.LanguageModelChatMessage[],
): Promise<string> {
  const cancellation = new vscode.CancellationTokenSource();
  const timeout = setTimeout(() => cancellation.cancel(), getTimeoutMs());

  try {
    const response = await model.sendRequest(messages, {}, cancellation.token);
    const text = await collectText(response);

    if (cancellation.token.isCancellationRequested && !text) {
      throw new Error('VS Code Language Model request timed out.');
    }

    if (!text) {
      throw new Error('VS Code Language Model returned an empty response.');
    }

    return text;
  } catch (error) {
    if (cancellation.token.isCancellationRequested) {
      throw new Error('VS Code Language Model request timed out.');
    }
    throw new Error(languageModelErrorMessage(error));
  } finally {
    clearTimeout(timeout);
    cancellation.dispose();
  }
}

export async function generateWithVsCodeLm(
  prompt: string,
): Promise<ProviderRawResponse> {
  const model = await selectPreferredModel();
  if (!model) {
    throw new Error(
      'No VS Code language model is currently available. Sign in/configure an available VS Code model, or choose Ollama in FLUSEC settings.',
    );
  }

  const messages = [vscode.LanguageModelChatMessage.User(prompt)];
  const raw = await sendRequest(model, messages);

  return {
    raw,
    modelLabel: modelLabel(model),
  };
}

/**
 * Explicit command-time test. This is also a convenient first-use action for
 * model access/consent because it is directly initiated by the user.
 */
export async function testVsCodeLmProvider(): Promise<ProviderTestResult> {
  try {
    const model = await selectPreferredModel();
    if (!model) {
      return {
        ok: false,
        provider: 'vscode',
        providerLabel: 'VS Code Language Model',
        message: 'No VS Code language model is currently available.',
      };
    }

    const messages = [
      vscode.LanguageModelChatMessage.User(
        'This is a connectivity test from the FLUSEC VS Code extension. Reply with exactly FLUSEC_READY and nothing else.',
      ),
    ];

    const reply = await sendRequest(model, messages);
    return {
      ok: true,
      provider: 'vscode',
      providerLabel: 'VS Code Language Model',
      modelLabel: modelLabel(model),
      message: reply.includes('FLUSEC_READY')
        ? 'VS Code Language Model is ready.'
        : 'VS Code Language Model responded successfully.',
    };
  } catch (error) {
    return {
      ok: false,
      provider: 'vscode',
      providerLabel: 'VS Code Language Model',
      message: languageModelErrorMessage(error),
    };
  }
}
