// src/llm/promptBuilder.ts
// Builds small, component-aware prompts for educational feedback.
// Detection is already complete before this layer runs. The LLM must never
// decide whether a FLUSEC finding exists or alter its severity/confidence.

import type { LlmComponent } from './types.js';

const MAX_SNIPPET_CHARS = 4000;

function trimSnippet(codeSnippet?: string): string {
  return String(codeSnippet ?? '').slice(0, MAX_SNIPPET_CHARS).trim();
}

/**
 * HSD findings can contain real credentials in the source line. Never send
 * literal string contents to any LLM provider. The finding message already
 * contains enough classification context for educational feedback.
 */
function redactHsdStringLiterals(codeSnippet: string): string {
  return codeSnippet
    .replace(/'(?:\\.|[^'\\])*'/g, "'[REDACTED]'")
    .replace(/"(?:\\.|[^"\\])*"/g, '"[REDACTED]"')
    .replace(/`(?:\\.|[^`\\])*`/g, '`[REDACTED]`');
}

export function sanitizeCodeSnippet(
  component: LlmComponent,
  codeSnippet?: string,
): string {
  const trimmed = trimSnippet(codeSnippet);
  if (!trimmed) { return '// No source-code context provided.'; }

  if (component === 'hsd') {
    return redactHsdStringLiterals(trimmed);
  }

  return trimmed;
}

function componentGuidance(component: LlmComponent): string {
  switch (component) {
    case 'hsd':
      return [
        'Topic: hardcoded secrets and credentials in Flutter/Dart client code.',
        'Never reproduce, reconstruct, guess, or expose a credential value.',
        'For private/server credentials, explain that client applications cannot safely keep them secret and recommend moving privileged operations to a trusted backend.',
        'When exposure is plausible, recommend rotating/revoking the credential.',
        'Do not present client-side encryption or moving the same secret to another Dart file as the main fix.',
      ].join('\n');

    case 'net':
      return [
        'Topic: insecure network communication in Flutter/Dart.',
        'Focus on transport security such as HTTPS/WSS, TLS certificate validation, secure gRPC channels, downgrade prevention, modern TLS versions, and WebView mixed-content protection as relevant to the supplied finding.',
      ].join('\n');

    case 'ids':
      return [
        'Topic: insecure data storage in Flutter/Dart.',
        'Focus on protecting sensitive data at rest, platform-backed secure storage, encrypted databases/files when appropriate, application-private storage, and avoiding sensitive WebView/cache/external-storage persistence as relevant to the supplied finding.',
      ].join('\n');

    case 'iiv':
      return [
        'Topic: insufficient input validation in Flutter/Dart.',
        'Focus only on the supplied rule, such as parameterized SQL, strict allow-listing for process arguments/files/deep links, or explicit form validation.',
        'Do not invent a different vulnerability category that is not supported by the supplied finding.',
      ].join('\n');
  }
}

export function buildEducationalFeedbackPrompt(
  component: LlmComponent,
  issueMessage: string,
  codeSnippet?: string,
): string {
  const code = sanitizeCodeSnippet(component, codeSnippet);

  return `
You are the educational-feedback layer of FLUSEC, a Flutter/Dart static-analysis VS Code extension.

IMPORTANT BOUNDARY:
- FLUSEC's deterministic static analyzer has already detected the issue.
- Do NOT decide whether the issue exists.
- Do NOT change, recalculate, or challenge FLUSEC security severity, confidence, CWE, or maintainability metadata.
- Your task is only to explain the detected issue and provide concise secure-coding guidance.
- Do not output a risk score or probability.

${componentGuidance(component)}

Return ONLY one valid JSON object. Do not wrap it in Markdown or code fences:
{
  "why": "Two short sentences explaining why the detected pattern is insecure.",
  "risk": "One short sentence explaining a realistic security impact.",
  "fix": [
    "Short practical fix 1",
    "Short practical fix 2",
    "Short practical fix 3"
  ],
  "example": "A short secure Flutter/Dart example relevant to this exact finding."
}

Rules for the response:
- Keep the whole response concise and educational.
- Use Flutter/Dart-oriented remediation where applicable.
- Do not claim the LLM performed vulnerability detection.
- Do not include a credential, token, password, private key, or reconstructed secret in the response.
- If source context contains [REDACTED], leave it redacted and never try to infer the original value.

FLUSEC finding:
${issueMessage}

Minimal source context:
${code}
  `.trim();
}
