// src/llm/types.ts
// Shared contracts for FLUSEC educational-feedback providers.

export type LlmComponent = 'hsd' | 'net' | 'ids' | 'iiv'

export type LlmProviderId = 'vscode' | 'ollama' | 'disabled'

export interface EducationalFeedback {
  why: string
  risk: string
  fix: string[]
  example: string
}

export interface LlmFeedbackSuccess {
  status: 'ok'
  provider: Exclude<LlmProviderId, 'disabled'>
  providerLabel: string
  modelLabel: string
  feedback: EducationalFeedback
}

export interface LlmFeedbackUnavailable {
  status: 'unavailable'
  provider: Exclude<LlmProviderId, 'disabled'>
  providerLabel: string
  message: string
}

export interface LlmFeedbackError {
  status: 'error'
  provider: Exclude<LlmProviderId, 'disabled'>
  providerLabel: string
  message: string
}

export interface LlmFeedbackDisabled {
  status: 'disabled'
  provider: 'disabled'
  providerLabel: 'Disabled'
  message: string
}

export type LlmFeedbackResult =
  | LlmFeedbackSuccess
  | LlmFeedbackUnavailable
  | LlmFeedbackError
  | LlmFeedbackDisabled

export interface ProviderRawResponse {
  raw: string
  modelLabel: string
}

export interface ProviderTestResult {
  ok: boolean
  provider: LlmProviderId
  providerLabel: string
  modelLabel?: string
  message: string
}
