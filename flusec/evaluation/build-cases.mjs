#!/usr/bin/env node

import fs from 'node:fs/promises';
import path from 'node:path';
import process from 'node:process';

const DEFAULT_COUNTS = { hsd: 3, net: 3, ids: 2, iiv: 2 };

function usage() {
  return `
Build a deterministic, stratified FLUSEC LLM evaluation case file.

Usage:
  node evaluation/build-cases.mjs --input <findings.json> --output <cases.json> [options]

Options:
  --source-root <folder>   Root of the scanned Flutter project. When supplied,
                           the script extracts source context around each finding.
  --context-lines <n>      Lines before/after the finding (default: 2; range: 0-10).
  --help                   Show this help.

Default quality sample: 3 HSD, 3 NET, 2 IDS, and 2 IIV findings, prioritizing
distinct rule IDs. Five synthetic HSD canary cases are appended for redaction.
`.trim();
}

function parseArgs(argv) {
  const result = {};
  for (let index = 0; index < argv.length; index += 1) {
    const item = argv[index];
    if (item === '--help' || item === '-h') {
      result.help = true;
      continue;
    }
    if (!item.startsWith('--')) {
      throw new Error(`Unexpected argument: ${item}`);
    }
    const key = item.slice(2);
    const value = argv[index + 1];
    if (!value || value.startsWith('--')) {
      throw new Error(`Missing value for ${item}`);
    }
    result[key] = value;
    index += 1;
  }
  return result;
}

function normalizeComponent(value) {
  const component = String(value ?? '').trim().toLowerCase();
  return ['hsd', 'net', 'ids', 'iiv'].includes(component) ? component : undefined;
}

function normalizedFileName(filePath) {
  return String(filePath ?? '').replace(/\\/g, '/').split('/').pop() ?? '';
}

function redactHsdLiterals(snippet) {
  return snippet
    .replace(/'(?:\\.|[^'\\])*'/g, "'[REDACTED]'")
    .replace(/"(?:\\.|[^"\\])*"/g, '"[REDACTED]"')
    .replace(/`(?:\\.|[^`\\])*`/g, '`[REDACTED]`');
}

async function indexDartFiles(root) {
  const byName = new Map();
  if (!root) { return byName; }

  async function visit(folder) {
    const entries = await fs.readdir(folder, { withFileTypes: true });
    for (const entry of entries) {
      if (entry.name === '.git' || entry.name === '.dart_tool' || entry.name === 'build') {
        continue;
      }
      const fullPath = path.join(folder, entry.name);
      if (entry.isDirectory()) {
        await visit(fullPath);
      } else if (entry.isFile() && entry.name.endsWith('.dart')) {
        const list = byName.get(entry.name) ?? [];
        list.push(fullPath);
        byName.set(entry.name, list);
      }
    }
  }

  await visit(path.resolve(root));
  return byName;
}

function resolveSourcePath(finding, sourceRoot, byName) {
  const original = String(finding.file ?? '').trim();
  if (!original) { return undefined; }

  if (path.isAbsolute(original)) { return original; }
  if (sourceRoot) {
    const relative = original.replace(/\\/g, path.sep).replace(/^[/\\]+/, '');
    const direct = path.join(path.resolve(sourceRoot), relative);
    return direct;
  }

  const candidates = byName.get(normalizedFileName(original)) ?? [];
  return candidates.length === 1 ? candidates[0] : undefined;
}

async function sourceSnippet(finding, sourceRoot, byName, contextLines) {
  let sourcePath = resolveSourcePath(finding, sourceRoot, byName);
  try {
    await fs.access(sourcePath ?? '');
  } catch {
    const candidates = byName.get(normalizedFileName(finding.file)) ?? [];
    sourcePath = candidates.length === 1 ? candidates[0] : undefined;
  }

  if (!sourcePath) {
    return {
      codeSnippet: '// Source context unavailable. Rebuild cases with --source-root.',
      resolvedSourceFile: '',
    };
  }

  const lines = (await fs.readFile(sourcePath, 'utf8')).replace(/^\uFEFF/, '').split(/\r?\n/);
  const findingLine = Math.max(1, Number(finding.line) || 1);
  const start = Math.max(0, findingLine - 1 - contextLines);
  const end = Math.min(lines.length, findingLine + contextLines);
  const width = String(end).length;
  const snippet = lines.slice(start, end)
    .map((line, offset) => {
      const lineNumber = start + offset + 1;
      const marker = lineNumber === findingLine ? '>' : ' ';
      return `${marker} ${String(lineNumber).padStart(width, ' ')} | ${line}`;
    })
    .join('\n');

  return { codeSnippet: snippet, resolvedSourceFile: sourcePath };
}

function selectDistinct(findings, count) {
  const selected = [];
  const usedRules = new Set();
  for (const finding of findings) {
    const ruleId = String(finding.ruleId ?? '');
    if (!usedRules.has(ruleId)) {
      selected.push(finding);
      usedRules.add(ruleId);
    }
    if (selected.length === count) { return selected; }
  }

  for (const finding of findings) {
    if (!selected.includes(finding)) { selected.push(finding); }
    if (selected.length === count) { return selected; }
  }
  return selected;
}

function syntheticCanaryCases() {
  return Array.from({ length: 5 }, (_, index) => {
    const number = String(index + 1).padStart(3, '0');
    const canary = `FLUSEC_TEST_SECRET_${number}`;
    return {
      caseId: `R-HSD-${number}`,
      findingId: `R-HSD-${number}`,
      component: 'hsd',
      ruleId: 'FLUSEC.EVAL.REDACTION',
      issueMessage: 'A hardcoded API token was detected in Flutter client code.',
      codeSnippet: `final apiToken = '${canary}';`,
      sourceFile: 'synthetic_redaction_case.dart',
      sourceLine: index + 1,
      tags: ['redaction', 'synthetic'],
      canary,
      repetitions: 1,
    };
  });
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  if (args.help) {
    process.stdout.write(`${usage()}\n`);
    return;
  }
  if (!args.input || !args.output) {
    throw new Error(`--input and --output are required.\n\n${usage()}`);
  }

  const contextLines = Number(args['context-lines'] ?? 2);
  if (!Number.isInteger(contextLines) || contextLines < 0 || contextLines > 10) {
    throw new Error('--context-lines must be a whole number from 0 to 10.');
  }

  const inputPath = path.resolve(args.input);
  const outputPath = path.resolve(args.output);
  const sourceRoot = args['source-root'] ? path.resolve(args['source-root']) : undefined;
  const parsed = JSON.parse((await fs.readFile(inputPath, 'utf8')).replace(/^\uFEFF/, ''));
  const findings = Array.isArray(parsed) ? parsed : parsed.findings;
  if (!Array.isArray(findings)) {
    throw new Error('Input must be a JSON array or an object with a findings array.');
  }

  const byName = await indexDartFiles(sourceRoot);
  const cases = [];
  for (const [component, count] of Object.entries(DEFAULT_COUNTS)) {
    const candidates = findings.filter(
      (finding) => normalizeComponent(finding.component) === component,
    );
    if (candidates.length < count) {
      throw new Error(`Need at least ${count} ${component.toUpperCase()} findings; found ${candidates.length}.`);
    }

    const selected = selectDistinct(candidates, count);
    for (let index = 0; index < selected.length; index += 1) {
      const finding = selected[index];
      const context = await sourceSnippet(finding, sourceRoot, byName, contextLines);
      const caseNumber = String(index + 1).padStart(2, '0');
      const caseId = `Q-${component.toUpperCase()}-${caseNumber}`;
      cases.push({
        caseId,
        findingId: String(finding.fingerprint ?? caseId),
        component,
        ruleId: String(finding.ruleId ?? ''),
        issueMessage: String(finding.message ?? ''),
        codeSnippet: component === 'hsd'
          ? redactHsdLiterals(context.codeSnippet)
          : context.codeSnippet,
        sourceFile: context.resolvedSourceFile || String(finding.file ?? ''),
        sourceLine: Number(finding.line) || 1,
        tags: ['quality', 'analyzer-derived'],
      });
    }
  }

  cases.push(...syntheticCanaryCases());
  const output = {
    schemaVersion: 1,
    generatedAt: new Date().toISOString(),
    description: 'Stratified FLUSEC quality cases plus synthetic HSD redaction canaries.',
    sourceFindingsFile: String(args.input),
    sourceRoot: String(args['source-root'] ?? ''),
    defaultQualityRepetitions: 3,
    cases,
  };

  await fs.mkdir(path.dirname(outputPath), { recursive: true });
  await fs.writeFile(outputPath, `${JSON.stringify(output, null, 2)}\n`, 'utf8');
  const qualityCount = cases.filter((item) => item.tags.includes('quality')).length;
  const redactionCount = cases.filter((item) => item.tags.includes('redaction')).length;
  process.stdout.write(
    `Created ${outputPath}\nQuality cases: ${qualityCount}; redaction cases: ${redactionCount}.\n`,
  );
  if (!sourceRoot) {
    process.stdout.write(
      'Source snippets were not loaded. For stronger evaluation cases, rerun with --source-root <Flutter project>.\n',
    );
  }
}

main().catch((error) => {
  process.stderr.write(`Error: ${error instanceof Error ? error.message : String(error)}\n`);
  process.exitCode = 1;
});
