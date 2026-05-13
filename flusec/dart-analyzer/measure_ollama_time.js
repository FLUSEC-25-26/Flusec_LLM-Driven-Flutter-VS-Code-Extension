const fs = require("fs");
const path = require("path");

const OLLAMA_URL = "http://127.0.0.1:11434/api/generate";
const MODEL = "llama3.2:latest";

const RESULTS_FILE = path.join(
  __dirname,
  "eval_results",
  "project_results_v3_utf8.json"
);

const SAMPLE_SIZE = 10;

function buildPrompt(finding) {
  return `
You are FLUSEC, a Flutter/Dart security education assistant.

Explain this security finding in simple developer-friendly language.

Finding:
- Component: ${finding.component}
- Rule ID: ${finding.ruleId}
- Severity: ${finding.severity}
- Message: ${finding.message}
- File: ${finding.file}
- Line: ${finding.line}
- Function: ${finding.functionName || "N/A"}

Provide:
1. Why this is a security concern
2. How it can affect a Flutter/Dart application
3. Recommended remediation steps

Keep the explanation concise.
`;
}

async function generateExplanation(prompt) {
  const response = await fetch(OLLAMA_URL, {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      model: MODEL,
      prompt: prompt,
      stream: false
    })
  });

  if (!response.ok) {
    throw new Error(`Ollama request failed: ${response.status} ${response.statusText}`);
  }

  return await response.json();
}

async function main() {
  if (!fs.existsSync(RESULTS_FILE)) {
    console.error(`Results file not found: ${RESULTS_FILE}`);
    process.exit(1);
  }

  let raw = fs.readFileSync(RESULTS_FILE, "utf8");

  // Remove UTF-8 BOM if present
  raw = raw.replace(/^\uFEFF/, "");

  const findings = JSON.parse(raw);

  if (!Array.isArray(findings) || findings.length === 0) {
    console.error("No findings found in project_results_v3_utf8.json");
    process.exit(1);
  }

  const sample = findings.slice(0, SAMPLE_SIZE);
  const times = [];

  console.log(`Testing ${sample.length} findings with Ollama model: ${MODEL}`);
  console.log("--------------------------------------------------");

  for (let i = 0; i < sample.length; i++) {
    const finding = sample[i];
    const prompt = buildPrompt(finding);

    const start = performance.now();

    try {
      await generateExplanation(prompt);
      const end = performance.now();

      const timeMs = end - start;
      times.push(timeMs);

      console.log(
        `Finding ${i + 1}: ${finding.component} | ${finding.ruleId} | ${timeMs.toFixed(2)} ms`
      );
    } catch (error) {
      console.error(`Finding ${i + 1} failed: ${error.message}`);
    }
  }

  if (times.length === 0) {
    console.error("No successful explanation timings collected.");
    process.exit(1);
  }

  const total = times.reduce((sum, t) => sum + t, 0);
  const avg = total / times.length;
  const min = Math.min(...times);
  const max = Math.max(...times);

  console.log("--------------------------------------------------");
  console.log("LLM Explanation Timing Result");
  console.log(`Successful explanations: ${times.length}`);
  console.log(`Total time: ${(total / 1000).toFixed(2)} s`);
  console.log(`Average time: ${(avg / 1000).toFixed(2)} s`);
  console.log(`Minimum time: ${(min / 1000).toFixed(2)} s`);
  console.log(`Maximum time: ${(max / 1000).toFixed(2)} s`);

  const output = {
    model: MODEL,
    testedFindings: times.length,
    totalTimeSeconds: Number((total / 1000).toFixed(2)),
    averageTimeSeconds: Number((avg / 1000).toFixed(2)),
    minimumTimeSeconds: Number((min / 1000).toFixed(2)),
    maximumTimeSeconds: Number((max / 1000).toFixed(2)),
    rawTimesMilliseconds: times.map((t) => Number(t.toFixed(2)))
  };

  fs.writeFileSync(
    path.join(__dirname, "eval_results", "llm_timing_result.json"),
    JSON.stringify(output, null, 2)
  );

  console.log("Saved result to eval_results/llm_timing_result.json");
}

main();
