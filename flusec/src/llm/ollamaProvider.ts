// src/llm/ollamaProvider.ts
// Optional local Ollama provider for FLUSEC educational feedback.

import * as vscode from 'vscode';
import fetch from 'node-fetch';
import type { ProviderRawResponse, ProviderTestResult } from './types.js';

interface OllamaGenerateResponse {
  response?: string
}

interface OllamaTagsResponse {
  models?: Array<{
    name?: string
    model?: string
  }>
}

function config() {
  return vscode.workspace.getConfiguration('flusec');
}

function getEndpoint(): string {
  const raw = config().get<string>('ollamaEndpoint', 'http://localhost:11434').trim();
  return (raw || 'http://localhost:11434').replace(/\/+$/, '');
}

function getModel(): string {
  return config().get<string>('ollamaModel', 'llama3.2:latest').trim() || 'llama3.2:latest';
}

function getTimeoutMs(): number {
  const seconds = config().get<number>('llmTimeoutSeconds', 60);
  const safeSeconds = Number.isFinite(seconds) ? Math.min(Math.max(seconds, 5), 180) : 60;
  return safeSeconds * 1000;
}

function friendlyFetchError(error: unknown): string {
  if (error instanceof Error) {
    if (/ECONNREFUSED|ENOTFOUND|ETIMEDOUT|network/i.test(error.message)) {
      return `Could not reach Ollama at ${getEndpoint()}. Make sure Ollama is installed and running.`;
    }
    return error.message;
  }
  return String(error);
}

export async function generateWithOllama(
  prompt: string,
): Promise<ProviderRawResponse> {
  const endpoint = getEndpoint();
  const model = getModel();

  let response;
  try {
    response = await fetch(`${endpoint}/api/generate`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      timeout: getTimeoutMs(),
      body: JSON.stringify({
        model,
        stream: false,
        keep_alive: '30m',
        format: 'json',
        prompt,
        options: {
          num_ctx: 2048,
          num_predict: 320,
          temperature: 0.1,
          top_p: 0.9,
          repeat_penalty: 1.05,
        },
      }),
    });
  } catch (error) {
    throw new Error(friendlyFetchError(error));
  }

  if (!response.ok) {
    const body = await response.text().catch(() => '');
    const suffix = body.trim() ? ` ${body.trim().slice(0, 240)}` : '';
    throw new Error(
      `Ollama request failed (${response.status} ${response.statusText}).${suffix}`,
    );
  }

  const data = (await response.json()) as OllamaGenerateResponse;
  const raw = String(data.response ?? '').trim();
  if (!raw) {
    throw new Error('Ollama returned an empty response.');
  }

  return {
    raw,
    modelLabel: model,
  };
}

export async function testOllamaProvider(): Promise<ProviderTestResult> {
  const endpoint = getEndpoint();
  const model = getModel();

  try {
    const response = await fetch(`${endpoint}/api/tags`, {
      method: 'GET',
      timeout: Math.min(getTimeoutMs(), 15_000),
    });

    if (!response.ok) {
      return {
        ok: false,
        provider: 'ollama',
        providerLabel: 'Ollama',
        modelLabel: model,
        message: `Ollama responded with ${response.status} ${response.statusText}.`,
      };
    }

    const data = (await response.json()) as OllamaTagsResponse;
    const installed = (data.models ?? [])
      .map((item) => String(item.name ?? item.model ?? '').trim())
      .filter(Boolean);

    const modelAvailable = installed.some(
      (name) => name === model || name.replace(/:latest$/, '') === model.replace(/:latest$/, ''),
    );

    if (!modelAvailable) {
      return {
        ok: false,
        provider: 'ollama',
        providerLabel: 'Ollama',
        modelLabel: model,
        message: `Ollama is running, but model "${model}" is not installed. Run: ollama pull ${model}`,
      };
    }

    return {
      ok: true,
      provider: 'ollama',
      providerLabel: 'Ollama',
      modelLabel: model,
      message: `Ollama is ready with ${model}.`,
    };
  } catch (error) {
    return {
      ok: false,
      provider: 'ollama',
      providerLabel: 'Ollama',
      modelLabel: model,
      message: friendlyFetchError(error),
    };
  }
}
