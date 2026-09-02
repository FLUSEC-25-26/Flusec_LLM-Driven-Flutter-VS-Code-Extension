import * as vscode from 'vscode';
import * as fs from 'node:fs/promises';
import * as path from 'node:path';
import { createHash } from 'node:crypto';
import { performance } from 'node:perf_hooks';
import { diagCollection } from '../analyzer/findingsStore.js';
import { buildEducationalFeedbackPrompt } from '../llm/promptBuilder.js';
import { generateWithOllama } from '../llm/ollamaProvider.js';
import type { LlmComponent, ProviderRawResponse } from '../llm/types.js';
import { generateWithVsCodeLm } from '../llm/vscodeLmProvider.js';
import {
  inspectResponse,
  meanPairwiseSimilarity,
  summarizeNumbers,
  toCsv,
} from './evaluationMetrics.js';

type EvaluationProvider = 'vscode' | 'ollama'

interface EvaluationCase {
  caseId: string
  findingId: string
  component: LlmComponent
  ruleId: string
  issueMessage: string
  codeSnippet: string
  sourceFile?: string
  sourceLine?: number
  tags?: string[]
  canary?: string
  repetitions?: number
}

interface CaseFile {
  schemaVersion?: number
  description?: string
  cases: EvaluationCase[]
}

interface EvaluationRun {
  responseId: string
  caseId: string
  findingId: string
  component: LlmComponent
  ruleId: string
  provider: EvaluationProvider
  providerLabel: string
  modelLabel: string
  repetition: number
  tags: string[]
  sourceFile: string
  sourceLine: number | null
  promptFile: string
  rawOutputFile: string
  startedAt: string
  latencyMilliseconds: number
  status: 'ok' | 'error'
  error: string
  validJson: boolean
  productionParseable: boolean
  whyPresent: boolean
  riskPresent: boolean
  fixPresent: boolean
  examplePresent: boolean
  fieldCompletionRate: number
  promptContainsCanary: boolean | null
  responseContainsCanary: boolean | null
  diagnosticsBeforeHash: string
  diagnosticsAfterHash: string
  diagnosticsPreserved: boolean
  automaticSimilarity: number | null
}

interface WarmupResult {
  provider: EvaluationProvider
  providerLabel: string
  status: 'ok' | 'error'
  modelLabel: string
  latencyMilliseconds: number
  error: string
}

const providerLabels: Record<EvaluationProvider, string> = {
  vscode: 'VS Code LM',
  ollama: 'Ollama',
};

function isComponent(value: unknown): value is LlmComponent {
  return value === 'hsd' || value === 'net' || value === 'ids' || value === 'iiv';
}

function safeFilePart(value: string): string {
  return value.replace(/[^a-zA-Z0-9._-]+/g, '_').slice(0, 120) || 'item';
}

function errorText(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

async function writeJson(filePath: string, value: unknown): Promise<void> {
  await fs.writeFile(filePath, `${JSON.stringify(value, null, 2)}\n`, 'utf8');
}

async function loadCases(filePath: string): Promise<CaseFile> {
  const raw = (await fs.readFile(filePath, 'utf8')).replace(/^\uFEFF/, '');
  const parsed = JSON.parse(raw) as CaseFile | EvaluationCase[];
  const caseFile: CaseFile = Array.isArray(parsed) ? { cases: parsed } : parsed;
  if (!Array.isArray(caseFile.cases) || caseFile.cases.length === 0) {
    throw new Error('The selected case file has no evaluation cases.');
  }

  const seen = new Set<string>();
  caseFile.cases.forEach((item, index) => {
    if (!item || typeof item !== 'object') {
      throw new Error(`Case ${index + 1} is not an object.`);
    }
    if (!String(item.caseId ?? '').trim()) {
      throw new Error(`Case ${index + 1} has no caseId.`);
    }
    if (seen.has(item.caseId)) {
      throw new Error(`Duplicate caseId: ${item.caseId}`);
    }
    seen.add(item.caseId);
    if (!isComponent(item.component)) {
      throw new Error(`Case ${item.caseId} has an invalid component.`);
    }
    if (!String(item.issueMessage ?? '').trim()) {
      throw new Error(`Case ${item.caseId} has no issueMessage.`);
    }
    if (item.repetitions !== undefined
      && (!Number.isInteger(item.repetitions) || item.repetitions < 1 || item.repetitions > 20)) {
      throw new Error(`Case ${item.caseId} has invalid repetitions (allowed: 1-20).`);
    }
  });

  return caseFile;
}

function diagnosticsHash(): string {
  const rows: string[] = [];
  diagCollection.forEach((uri, diagnostics) => {
    for (const diagnostic of diagnostics) {
      rows.push([
        uri.toString(),
        diagnostic.range.start.line,
        diagnostic.range.start.character,
        diagnostic.range.end.line,
        diagnostic.range.end.character,
        diagnostic.severity,
        diagnostic.code === undefined ? '' : String(diagnostic.code),
        diagnostic.source ?? '',
        diagnostic.message,
      ].join('|'));
    }
  });
  rows.sort();
  return createHash('sha256').update(rows.join('\n'), 'utf8').digest('hex');
}

async function callProvider(
  provider: EvaluationProvider,
  prompt: string,
): Promise<ProviderRawResponse> {
  return provider === 'vscode'
    ? generateWithVsCodeLm(prompt)
    : generateWithOllama(prompt);
}

function runKey(run: EvaluationRun): string {
  return `${run.caseId}\u0000${run.provider}`;
}

function attachSimilarity(runs: EvaluationRun[], rawByResponse: Map<string, string>): void {
  const grouped = new Map<string, EvaluationRun[]>();
  for (const run of runs) {
    if (run.status !== 'ok') { continue; }
    const list = grouped.get(runKey(run)) ?? [];
    list.push(run);
    grouped.set(runKey(run), list);
  }

  for (const group of grouped.values()) {
    const raw = group
      .map((run) => rawByResponse.get(run.responseId) ?? '')
      .filter(Boolean);
    const similarity = meanPairwiseSimilarity(raw);
    for (const run of group) { run.automaticSimilarity = similarity; }
  }
}

function buildSummary(runs: EvaluationRun[]) {
  const byProvider = (['vscode', 'ollama'] as EvaluationProvider[])
    .filter((provider) => runs.some((run) => run.provider === provider))
    .map((provider) => {
      const selected = runs.filter((run) => run.provider === provider);
      const successful = selected.filter((run) => run.status === 'ok');
      const canary = selected.filter((run) => run.responseContainsCanary !== null);
      const similarities = selected
        .map((run) => run.automaticSimilarity)
        .filter((value): value is number => value !== null);

      return {
        provider,
        providerLabel: providerLabels[provider],
        modelLabels: [...new Set(selected.map((run) => run.modelLabel).filter(Boolean))],
        requests: selected.length,
        successfulRequests: successful.length,
        errors: selected.length - successful.length,
        successRate: selected.length ? successful.length / selected.length : null,
        validJsonRate: successful.length
          ? successful.filter((run) => run.validJson).length / successful.length
          : null,
        productionParseableRate: successful.length
          ? successful.filter((run) => run.productionParseable).length / successful.length
          : null,
        fullFieldCompletionRate: successful.length
          ? successful.filter((run) => run.fieldCompletionRate === 1).length / successful.length
          : null,
        meanFieldCompletionRate: successful.length
          ? successful.reduce((sum, run) => sum + run.fieldCompletionRate, 0) / successful.length
          : null,
        latencyMilliseconds: summarizeNumbers(
          successful.map((run) => run.latencyMilliseconds),
        ),
        canaryTests: canary.length,
        canaryLeaks: canary.filter((run) => run.responseContainsCanary).length,
        canaryLeakageRate: canary.length
          ? canary.filter((run) => run.responseContainsCanary).length / canary.length
          : null,
        diagnosticsPreservationRate: selected.length
          ? selected.filter((run) => run.diagnosticsPreserved).length / selected.length
          : null,
        meanTokenJaccardSimilarity: similarities.length
          ? similarities.reduce((sum, value) => sum + value, 0) / similarities.length
          : null,
      };
    });

  return {
    generatedAt: new Date().toISOString(),
    note: 'Token Jaccard similarity is an automatic repeatability indicator, not a human quality or semantic-consistency score.',
    totalRequests: runs.length,
    providers: byProvider,
  };
}

async function chooseProviders(): Promise<EvaluationProvider[] | undefined> {
  const choice = await vscode.window.showQuickPick(
    [
      { label: 'Both providers', description: 'VS Code LM and Ollama', value: 'both' },
      { label: 'VS Code LM only', value: 'vscode' },
      { label: 'Ollama only', value: 'ollama' },
    ],
    {
      title: 'FLUSEC automated LLM evaluation',
      placeHolder: 'Select the providers to evaluate',
    },
  );
  if (!choice) { return undefined; }
  return choice.value === 'both'
    ? ['vscode', 'ollama']
    : [choice.value as EvaluationProvider];
}

async function writeCsvOutputs(outputDir: string, runs: EvaluationRun[]): Promise<void> {
  const automaticHeaders = [
    'ResponseID', 'CaseID', 'FindingID', 'Domain', 'RuleID', 'Provider', 'Model',
    'Run', 'Status', 'Error', 'LatencyMilliseconds', 'ValidJSON',
    'ProductionParseable', 'WhyPresent',
    'RiskPresent', 'FixPresent', 'ExamplePresent', 'FieldCompletionRate',
    'AutomaticSimilarity', 'PromptContainsCanary', 'ResponseContainsCanary',
    'DiagnosticsPreserved', 'PromptFile', 'RawOutputFile', 'SourceFile', 'SourceLine',
  ];
  const automaticRows = runs.map((run) => ({
    ResponseID: run.responseId,
    CaseID: run.caseId,
    FindingID: run.findingId,
    Domain: run.component.toUpperCase(),
    RuleID: run.ruleId,
    Provider: run.providerLabel,
    Model: run.modelLabel,
    Run: run.repetition,
    Status: run.status,
    Error: run.error,
    LatencyMilliseconds: run.latencyMilliseconds.toFixed(3),
    ValidJSON: run.validJson ? 'Yes' : 'No',
    ProductionParseable: run.productionParseable ? 'Yes' : 'No',
    WhyPresent: run.whyPresent ? 'Yes' : 'No',
    RiskPresent: run.riskPresent ? 'Yes' : 'No',
    FixPresent: run.fixPresent ? 'Yes' : 'No',
    ExamplePresent: run.examplePresent ? 'Yes' : 'No',
    FieldCompletionRate: run.fieldCompletionRate.toFixed(4),
    AutomaticSimilarity: run.automaticSimilarity === null
      ? ''
      : run.automaticSimilarity.toFixed(4),
    PromptContainsCanary: run.promptContainsCanary === null
      ? 'Not Tested'
      : run.promptContainsCanary ? 'Yes' : 'No',
    ResponseContainsCanary: run.responseContainsCanary === null
      ? 'Not Tested'
      : run.responseContainsCanary ? 'Yes' : 'No',
    DiagnosticsPreserved: run.diagnosticsPreserved ? 'Yes' : 'No',
    PromptFile: run.promptFile,
    RawOutputFile: run.rawOutputFile,
    SourceFile: run.sourceFile,
    SourceLine: run.sourceLine ?? '',
  }));
  await fs.writeFile(
    path.join(outputDir, 'response_results.csv'),
    toCsv(automaticHeaders, automaticRows),
    'utf8',
  );

  const manualHeaders = [
    'ResponseID', 'FindingID', 'Domain', 'Provider', 'Run', 'LatencySeconds',
    'ValidJSON', 'WhyPresent', 'RiskPresent', 'FixPresent', 'ExamplePresent',
    'ExplanationScore', 'RemediationScore', 'ExampleSafetyScore',
    'ConsistencyScore', 'HallucinatedAPI', 'SecretLeakage', 'RawOutputFile',
    'AutomaticSimilarity', 'DiagnosticsPreserved', 'Notes',
  ];
  const manualRows = runs
    .filter((run) => !run.tags.includes('redaction'))
    .map((run) => ({
      ResponseID: run.responseId,
      FindingID: run.findingId,
      Domain: run.component.toUpperCase(),
      Provider: run.providerLabel,
      Run: run.repetition,
      LatencySeconds: (run.latencyMilliseconds / 1000).toFixed(3),
      ValidJSON: run.validJson ? 1 : 0,
      WhyPresent: run.whyPresent ? 1 : 0,
      RiskPresent: run.riskPresent ? 1 : 0,
      FixPresent: run.fixPresent ? 1 : 0,
      ExamplePresent: run.examplePresent ? 1 : 0,
      ExplanationScore: '',
      RemediationScore: '',
      ExampleSafetyScore: '',
      ConsistencyScore: '',
      HallucinatedAPI: '',
      SecretLeakage: run.responseContainsCanary === null
        ? 'Not Tested'
        : run.responseContainsCanary ? 'Yes' : 'No',
      RawOutputFile: run.rawOutputFile,
      AutomaticSimilarity: run.automaticSimilarity === null
        ? ''
        : run.automaticSimilarity.toFixed(4),
      DiagnosticsPreserved: run.diagnosticsPreserved ? 'Yes' : 'No',
      Notes: '',
    }));
  await fs.writeFile(
    path.join(outputDir, 'manual_scoring.csv'),
    toCsv(manualHeaders, manualRows),
    'utf8',
  );

  const canaryRuns = runs.filter((run) => run.responseContainsCanary !== null);
  const redactionHeaders = [
    'ResponseID', 'CaseID', 'FindingID', 'Provider', 'Run', 'PromptRedacted',
    'ResponseLeakedCanary', 'Status', 'Error', 'DiagnosticsPreserved',
  ];
  const redactionRows = canaryRuns.map((run) => ({
    ResponseID: run.responseId,
    CaseID: run.caseId,
    FindingID: run.findingId,
    Provider: run.providerLabel,
    Run: run.repetition,
    PromptRedacted: run.promptContainsCanary ? 'No' : 'Yes',
    ResponseLeakedCanary: run.responseContainsCanary ? 'Yes' : 'No',
    Status: run.status,
    Error: run.error,
    DiagnosticsPreserved: run.diagnosticsPreserved ? 'Yes' : 'No',
  }));
  await fs.writeFile(
    path.join(outputDir, 'redaction_results.csv'),
    toCsv(redactionHeaders, redactionRows),
    'utf8',
  );
}

async function runEvaluation(context: vscode.ExtensionContext): Promise<void> {
  const selectedCases = await vscode.window.showOpenDialog({
    canSelectMany: false,
    canSelectFiles: true,
    canSelectFolders: false,
    filters: { 'FLUSEC evaluation cases': ['json'] },
    openLabel: 'Select evaluation cases',
    title: 'FLUSEC automated LLM evaluation: select cases JSON',
  });
  if (!selectedCases?.[0]) { return; }

  let caseFile: CaseFile;
  try {
    caseFile = await loadCases(selectedCases[0].fsPath);
  } catch (error) {
    vscode.window.showErrorMessage(`FLUSEC evaluation: invalid case file. ${errorText(error)}`);
    return;
  }

  const providers = await chooseProviders();
  if (!providers) { return; }

  const repetitionsText = await vscode.window.showInputBox({
    title: 'FLUSEC automated LLM evaluation',
    prompt: 'Repetitions per quality case (case-specific overrides still apply)',
    value: '3',
    validateInput: (value) => {
      const parsed = Number(value);
      return Number.isInteger(parsed) && parsed >= 1 && parsed <= 20
        ? undefined
        : 'Enter a whole number from 1 to 20.';
    },
  });
  if (repetitionsText === undefined) { return; }
  const defaultRepetitions = Number(repetitionsText);

  const selectedOutput = await vscode.window.showOpenDialog({
    canSelectMany: false,
    canSelectFiles: false,
    canSelectFolders: true,
    openLabel: 'Select output folder',
    title: 'FLUSEC automated LLM evaluation: select output parent folder',
  });
  if (!selectedOutput?.[0]) { return; }

  const qualityCases = caseFile.cases.filter((item) => !(item.tags ?? []).includes('redaction'));
  const redactionCases = caseFile.cases.filter((item) => (item.tags ?? []).includes('redaction'));
  const plannedRequests = providers.length * caseFile.cases.reduce(
    (sum, item) => sum + (item.repetitions ?? defaultRepetitions),
    0,
  );
  const consent = await vscode.window.showWarningMessage(
    [
      `This user-initiated evaluation will make ${plannedRequests} measured LLM requests plus one warm-up per provider.`,
      `Cases: ${qualityCases.length} quality and ${redactionCases.length} synthetic redaction.`,
      'Non-HSD source snippets may be sent to the selected configured model provider.',
      'Continue only with approved or synthetic code.',
    ].join(' '),
    { modal: true },
    'Run evaluation',
  );
  if (consent !== 'Run evaluation') { return; }

  const stamp = new Date().toISOString().replace(/[:.]/g, '-');
  const outputDir = path.join(selectedOutput[0].fsPath, `flusec-llm-evaluation-${stamp}`);
  const promptDir = path.join(outputDir, 'prompts');
  const rawDir = path.join(outputDir, 'raw-responses');
  await fs.mkdir(promptDir, { recursive: true });
  await fs.mkdir(rawDir, { recursive: true });

  const promptFiles = new Map<string, string>();
  for (const evaluationCase of caseFile.cases) {
    const prompt = buildEducationalFeedbackPrompt(
      evaluationCase.component,
      evaluationCase.issueMessage,
      evaluationCase.codeSnippet,
    );
    const relative = path.join('prompts', `${safeFilePart(evaluationCase.caseId)}.txt`);
    await fs.writeFile(path.join(outputDir, relative), `${prompt}\n`, 'utf8');
    promptFiles.set(evaluationCase.caseId, relative.replace(/\\/g, '/'));
  }

  const manifest = {
    schemaVersion: 1,
    extensionName: String(context.extension.packageJSON.name ?? 'flusec'),
    extensionVersion: String(context.extension.packageJSON.version ?? 'unknown'),
    startedAt: new Date().toISOString(),
    casesFile: selectedCases[0].fsPath,
    caseDescription: caseFile.description ?? '',
    providers,
    defaultRepetitions,
    plannedRequests,
    qualityCaseCount: qualityCases.length,
    redactionCaseCount: redactionCases.length,
    note: 'LLM feedback is measured after deterministic findings are supplied. The runner does not perform or alter vulnerability detection.',
  };
  await writeJson(path.join(outputDir, 'manifest.json'), manifest);

  const runs: EvaluationRun[] = [];
  const rawByResponse = new Map<string, string>();
  const warmups: WarmupResult[] = [];
  let cancelled = false;

  await vscode.window.withProgress(
    {
      location: vscode.ProgressLocation.Notification,
      title: 'FLUSEC: Running automated LLM evaluation',
      cancellable: true,
    },
    async (progress, cancellationToken) => {
      const warmupCase = qualityCases[0] ?? caseFile.cases[0];
      const warmupPrompt = buildEducationalFeedbackPrompt(
        warmupCase.component,
        warmupCase.issueMessage,
        warmupCase.codeSnippet,
      );

      for (const provider of providers) {
        if (cancellationToken.isCancellationRequested) {
          cancelled = true;
          break;
        }
        progress.report({ message: `Warming up ${providerLabels[provider]}…` });
        const started = performance.now();
        try {
          const response = await callProvider(provider, warmupPrompt);
          warmups.push({
            provider,
            providerLabel: providerLabels[provider],
            status: 'ok',
            modelLabel: response.modelLabel,
            latencyMilliseconds: performance.now() - started,
            error: '',
          });
        } catch (error) {
          warmups.push({
            provider,
            providerLabel: providerLabels[provider],
            status: 'error',
            modelLabel: '',
            latencyMilliseconds: performance.now() - started,
            error: errorText(error),
          });
        }
      }

      let completed = 0;
      for (const evaluationCase of caseFile.cases) {
        const promptRelative = promptFiles.get(evaluationCase.caseId) ?? '';
        const prompt = await fs.readFile(path.join(outputDir, promptRelative), 'utf8');
        for (const provider of providers) {
          const repetitions = evaluationCase.repetitions ?? defaultRepetitions;
          for (let repetition = 1; repetition <= repetitions; repetition += 1) {
            if (cancellationToken.isCancellationRequested) {
              cancelled = true;
              break;
            }

            const responseId = [
              safeFilePart(evaluationCase.caseId),
              provider,
              String(repetition).padStart(2, '0'),
            ].join('-');
            progress.report({
              message: `${completed + 1}/${plannedRequests}: ${evaluationCase.caseId} · ${providerLabels[provider]} · run ${repetition}`,
              increment: 100 / plannedRequests,
            });

            const beforeHash = diagnosticsHash();
            const startedAt = new Date().toISOString();
            const started = performance.now();
            let raw = '';
            let modelLabel = '';
            let status: 'ok' | 'error' = 'ok';
            let error = '';
            try {
              const response = await callProvider(provider, prompt);
              raw = response.raw;
              modelLabel = response.modelLabel;
            } catch (caught) {
              status = 'error';
              error = errorText(caught);
            }
            const latencyMilliseconds = performance.now() - started;
            const afterHash = diagnosticsHash();
            const inspection = inspectResponse(raw);
            const canary = evaluationCase.canary?.trim() || '';
            const rawRelative = path.join(
              'raw-responses',
              `${safeFilePart(responseId)}.${status === 'ok' ? 'json.txt' : 'error.txt'}`,
            ).replace(/\\/g, '/');
            await fs.writeFile(
              path.join(outputDir, rawRelative),
              status === 'ok' ? `${raw}\n` : `${error}\n`,
              'utf8',
            );

            const run: EvaluationRun = {
              responseId,
              caseId: evaluationCase.caseId,
              findingId: evaluationCase.findingId || evaluationCase.caseId,
              component: evaluationCase.component,
              ruleId: evaluationCase.ruleId,
              provider,
              providerLabel: providerLabels[provider],
              modelLabel,
              repetition,
              tags: evaluationCase.tags ?? [],
              sourceFile: evaluationCase.sourceFile ?? '',
              sourceLine: evaluationCase.sourceLine ?? null,
              promptFile: promptRelative,
              rawOutputFile: rawRelative,
              startedAt,
              latencyMilliseconds,
              status,
              error,
              validJson: inspection.validJson,
              productionParseable: inspection.productionParseable,
              whyPresent: inspection.whyPresent,
              riskPresent: inspection.riskPresent,
              fixPresent: inspection.fixPresent,
              examplePresent: inspection.examplePresent,
              fieldCompletionRate: inspection.fieldCompletionRate,
              promptContainsCanary: canary ? prompt.includes(canary) : null,
              responseContainsCanary: canary ? raw.includes(canary) : null,
              diagnosticsBeforeHash: beforeHash,
              diagnosticsAfterHash: afterHash,
              diagnosticsPreserved: beforeHash === afterHash,
              automaticSimilarity: null,
            };
            runs.push(run);
            rawByResponse.set(responseId, raw);
            completed += 1;
            await writeJson(path.join(outputDir, 'runs.partial.json'), runs);
          }
          if (cancelled) { break; }
        }
        if (cancelled) { break; }
      }
    },
  );

  attachSimilarity(runs, rawByResponse);
  await writeJson(path.join(outputDir, 'runs.json'), runs);
  await writeJson(path.join(outputDir, 'warmups.json'), warmups);
  await writeJson(path.join(outputDir, 'summary.json'), buildSummary(runs));
  await writeCsvOutputs(outputDir, runs);
  await fs.rm(path.join(outputDir, 'runs.partial.json'), { force: true });

  const resultMessage = cancelled
    ? `Evaluation cancelled safely after ${runs.length} measured requests. Partial results were finalized.`
    : `Evaluation complete: ${runs.length} measured requests.`;
  const action = await vscode.window.showInformationMessage(
    `FLUSEC: ${resultMessage}`,
    'Open results folder',
  );
  if (action === 'Open results folder') {
    await vscode.commands.executeCommand('revealFileInOS', vscode.Uri.file(outputDir));
  }
}

export function registerLlmEvaluationCommand(context: vscode.ExtensionContext): void {
  context.subscriptions.push(
    vscode.commands.registerCommand('flusec.runLlmEvaluation', async () => {
      try {
        await runEvaluation(context);
      } catch (error) {
        vscode.window.showErrorMessage(`FLUSEC evaluation failed: ${errorText(error)}`);
      }
    }),
  );
}
