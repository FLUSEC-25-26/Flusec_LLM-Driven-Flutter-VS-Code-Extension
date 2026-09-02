export interface ResponseInspection {
  validJson: boolean
  productionParseable: boolean
  whyPresent: boolean
  riskPresent: boolean
  fixPresent: boolean
  examplePresent: boolean
  completedFields: number
  fieldCompletionRate: number
  parsedFeedback?: {
    why: string
    risk: string
    fix: string[]
    example: string
  }
  parseError?: string
}

export interface NumberSummary {
  count: number
  mean: number | null
  median: number | null
  minimum: number | null
  maximum: number | null
  sampleStandardDeviation: number | null
}

export function extractJsonObject(raw: string): string | undefined {
  const trimmed = raw.trim();
  if (!trimmed) { return undefined; }

  if (trimmed.startsWith('{') && trimmed.endsWith('}')) {
    return trimmed;
  }

  const first = trimmed.indexOf('{');
  const last = trimmed.lastIndexOf('}');
  if (first >= 0 && last > first) {
    return trimmed.slice(first, last + 1);
  }

  return undefined;
}

function nonEmptyString(value: unknown): value is string {
  return typeof value === 'string' && value.trim().length > 0;
}

export function inspectResponse(raw: string): ResponseInspection {
  const candidate = extractJsonObject(raw);
  if (!candidate) {
    return {
      validJson: false,
      productionParseable: false,
      whyPresent: false,
      riskPresent: false,
      fixPresent: false,
      examplePresent: false,
      completedFields: 0,
      fieldCompletionRate: 0,
      parseError: 'No JSON object was found in the response.',
    };
  }

  try {
    const parsed = JSON.parse(candidate) as Record<string, unknown>;
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
      throw new Error('The recovered JSON value is not an object.');
    }
    let validJson = false;
    try {
      const strict = JSON.parse(raw.trim()) as unknown;
      validJson = Boolean(strict && typeof strict === 'object' && !Array.isArray(strict));
    } catch {
      validJson = false;
    }
    const whyPresent = nonEmptyString(parsed.why);
    const riskPresent = nonEmptyString(parsed.risk);
    const fixPresent = Array.isArray(parsed.fix)
      && parsed.fix.length > 0
      && parsed.fix.every(nonEmptyString);
    const examplePresent = nonEmptyString(parsed.example);
    const completedFields = [whyPresent, riskPresent, fixPresent, examplePresent]
      .filter(Boolean).length;

    const result: ResponseInspection = {
      validJson,
      productionParseable: true,
      whyPresent,
      riskPresent,
      fixPresent,
      examplePresent,
      completedFields,
      fieldCompletionRate: completedFields / 4,
    };

    if (whyPresent && riskPresent && fixPresent && examplePresent) {
      result.parsedFeedback = {
        why: String(parsed.why).trim(),
        risk: String(parsed.risk).trim(),
        fix: (parsed.fix as string[]).map((item) => item.trim()),
        example: String(parsed.example).trim(),
      };
    }

    return result;
  } catch (error) {
    return {
      validJson: false,
      productionParseable: false,
      whyPresent: false,
      riskPresent: false,
      fixPresent: false,
      examplePresent: false,
      completedFields: 0,
      fieldCompletionRate: 0,
      parseError: error instanceof Error ? error.message : String(error),
    };
  }
}

function tokens(value: string): Set<string> {
  const normalized = value
    .toLowerCase()
    .replace(/[^a-z0-9_]+/g, ' ')
    .trim();
  return new Set(normalized ? normalized.split(/\s+/) : []);
}

export function jaccardSimilarity(left: string, right: string): number {
  const a = tokens(left);
  const b = tokens(right);
  if (a.size === 0 && b.size === 0) { return 1; }

  let intersection = 0;
  for (const item of a) {
    if (b.has(item)) { intersection += 1; }
  }

  const union = new Set([...a, ...b]).size;
  return union === 0 ? 1 : intersection / union;
}

export function meanPairwiseSimilarity(values: string[]): number | null {
  if (values.length < 2) { return null; }

  const similarities: number[] = [];
  for (let left = 0; left < values.length; left += 1) {
    for (let right = left + 1; right < values.length; right += 1) {
      similarities.push(jaccardSimilarity(values[left], values[right]));
    }
  }

  return similarities.reduce((sum, value) => sum + value, 0) / similarities.length;
}

export function summarizeNumbers(values: number[]): NumberSummary {
  const finite = values.filter(Number.isFinite).sort((a, b) => a - b);
  if (finite.length === 0) {
    return {
      count: 0,
      mean: null,
      median: null,
      minimum: null,
      maximum: null,
      sampleStandardDeviation: null,
    };
  }

  const mean = finite.reduce((sum, value) => sum + value, 0) / finite.length;
  const middle = Math.floor(finite.length / 2);
  const median = finite.length % 2 === 0
    ? (finite[middle - 1] + finite[middle]) / 2
    : finite[middle];
  const sampleStandardDeviation = finite.length < 2
    ? null
    : Math.sqrt(
      finite.reduce((sum, value) => sum + ((value - mean) ** 2), 0)
        / (finite.length - 1),
    );

  return {
    count: finite.length,
    mean,
    median,
    minimum: finite[0],
    maximum: finite[finite.length - 1],
    sampleStandardDeviation,
  };
}

function csvCell(value: unknown): string {
  if (value === null || value === undefined) { return ''; }
  const text = String(value);
  return /[",\r\n]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text;
}

export function toCsv(
  headers: string[],
  rows: Array<Record<string, unknown>>,
): string {
  const lines = [headers.map(csvCell).join(',')];
  for (const row of rows) {
    lines.push(headers.map((header) => csvCell(row[header])).join(','));
  }
  return `${lines.join('\n')}\n`;
}
