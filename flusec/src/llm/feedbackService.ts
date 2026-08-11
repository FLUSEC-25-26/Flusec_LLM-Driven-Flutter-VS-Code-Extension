// src/llm/feedbackService.ts
// Provider-agnostic educational-feedback service for FLUSEC.
//
// Default provider: VS Code Language Model API
// Optional provider: Ollama
// Disabled: static analysis continues normally with no LLM call

import * as vscode from 'vscode';
import { buildEducationalFeedbackPrompt } from './promptBuilder.js';
import { generateWithOllama, testOllamaProvider } from './ollamaProvider.js';
import { generateWithVsCodeLm, testVsCodeLmProvider } from './vscodeLmProvider.js';
import type {
  EducationalFeedback,
  LlmComponent,
  LlmFeedbackResult,
  LlmProviderId,
  ProviderRawResponse,
  ProviderTestResult,
} from './types.js';

export function getConfiguredLlmProvider(): LlmProviderId {
  const raw = vscode.workspace
    .getConfiguration('flusec')
    .get<string>('llmProvider', 'vscode')
    .trim()
    .toLowerCase();

  if (raw === 'ollama' || raw === 'disabled') { return raw; }
  return 'vscode';
}

export function getLlmProviderDisplayName(provider: LlmProviderId): string {
  switch (provider) {
    case 'vscode':
      return 'VS Code Language Model';
    case 'ollama':
      return 'Ollama';
    case 'disabled':
      return 'Disabled';
  }
}

function extractJsonObject(raw: string): string | null {
  const cleaned = raw
    .replace(/^\s*```(?:json)?\s*/i, '')
    .replace(/\s*```\s*$/i, '')
    .trim();

  const first = cleaned.indexOf('{');
  const last = cleaned.lastIndexOf('}');
  if (first < 0 || last <= first) { return null; }
  return cleaned.slice(first, last + 1);
}

function asShortText(value: unknown, maxLength: number): string {
  const text = String(value ?? '').trim();
  if (!text) { return ''; }
  return text.length <= maxLength ? text : `${text.slice(0, maxLength)}…`;
}

function parseEducationalFeedback(raw: string): EducationalFeedback {
  const candidate = extractJsonObject(raw);
  if (!candidate) {
    throw new Error('The language model did not return the expected JSON feedback format.');
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(candidate) as unknown;
  } catch {
    throw new Error('The language model returned invalid JSON feedback.');
  }

  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new Error('The language model returned an invalid feedback object.');
  }

  const object = parsed as Record<string, unknown>;
  const fix = Array.isArray(object.fix)
    ? object.fix
        .map((item) => asShortText(item, 220))
        .filter(Boolean)
        .slice(0, 3)
    : [];

  const feedback: EducationalFeedback = {
    why: asShortText(object.why, 700),
    risk: asShortText(object.risk, 450),
    fix,
    example: asShortText(object.example, 1800),
  };

  if (!feedback.why && !feedback.risk && !feedback.fix.length && !feedback.example) {
    throw new Error('The language model returned an empty feedback object.');
  }

  return feedback;
}

async function callProvider(
  provider: Exclude<LlmProviderId, 'disabled'>,
  prompt: string,
): Promise<ProviderRawResponse> {
  if (provider === 'ollama') {
    return generateWithOllama(prompt);
  }
  return generateWithVsCodeLm(prompt);
}

export async function requestEducationalFeedback(
  component: LlmComponent,
  issueMessage: string,
  codeSnippet?: string,
): Promise<LlmFeedbackResult> {
  const provider = getConfiguredLlmProvider();

  if (provider === 'disabled') {
    return {
      status: 'disabled',
      provider: 'disabled',
      providerLabel: 'Disabled',
      message: 'LLM educational feedback is disabled. FLUSEC static-analysis findings are unaffected.',
    };
  }

  const providerLabel = getLlmProviderDisplayName(provider);
  const prompt = buildEducationalFeedbackPrompt(component, issueMessage, codeSnippet);

  try {
    const response = await callProvider(provider, prompt);
    const feedback = parseEducationalFeedback(response.raw);

    return {
      status: 'ok',
      provider,
      providerLabel,
      modelLabel: response.modelLabel,
      feedback,
    };
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    const unavailable = /no .*model|not available|could not reach|ECONNREFUSED|not installed/i.test(message);

    if (unavailable) {
      return {
        status: 'unavailable',
        provider,
        providerLabel,
        message,
      };
    }

    return {
      status: 'error',
      provider,
      providerLabel,
      message,
    };
  }
}

export async function testConfiguredLlmProvider(): Promise<ProviderTestResult> {
  const provider = getConfiguredLlmProvider();

  if (provider === 'disabled') {
    return {
      ok: true,
      provider: 'disabled',
      providerLabel: 'Disabled',
      message: 'LLM feedback is disabled. FLUSEC static analysis remains available.',
    };
  }

  return provider === 'ollama'
    ? testOllamaProvider()
    : testVsCodeLmProvider();
}
