# FLUSEC automated LLM evaluation

This evaluation uses FLUSEC's production prompt builder and provider adapters.
It measures the educational-feedback layer after a deterministic finding has
already been supplied. It does not change or re-evaluate analyzer findings.

## What is automated

- complete request latency, provider/model label, success, and provider errors;
- strict JSON-only compliance, production parseability, and completion of
  `why`, `risk`, `fix`, and `example`;
- exact synthetic-canary presence before and after the provider boundary;
- diagnostic-state hashes before and after every request;
- pairwise token Jaccard similarity across repeated responses;
- raw prompts, raw responses, a machine-readable summary, and CSV evidence.

The automatic similarity value is only a repeatability indicator. It is not a
human judgment of correctness or semantic consistency. Explanation quality,
remediation quality, example safety, hallucinated APIs, and the final
consistency score remain blank in `manual_scoring.csv` for later review.

## 1. Build evaluation cases

From the FLUSEC extension root:

```bash
node evaluation/build-cases.mjs \
  --input dart-analyzer/eval_results/project_results_v3_utf8.json \
  --output evaluation/cases.generated.json \
  --source-root /path/to/flusec_evaluation_project
```

`--source-root` is strongly recommended because it extracts a small source
window around each analyzer finding. Without it, the finding message is still
evaluated, but the source context is recorded as unavailable. The builder
selects ten deterministic, stratified cases: 3 HSD, 3 NET, 2 IDS, and 2 IIV,
prioritizing different rule IDs. It also appends five synthetic HSD canaries.
No real credential should be placed in an evaluation case.

## 2. Build and launch the extension

```bash
npm install
npm run compile
```

Open the extension project in VS Code and press **F5** to start the Extension
Development Host. Ensure a VS Code language model is available and/or start the
configured Ollama model. The active settings are:

- `flusec.vscodeLmVendor` and `flusec.vscodeLmModelId`;
- `flusec.ollamaEndpoint` and `flusec.ollamaModel`;
- `flusec.llmTimeoutSeconds`.

## 3. Run the evaluator

In the Extension Development Host, open the Command Palette and run:

`FLUSEC: Run Automated LLM Evaluation`

Then:

1. select `evaluation/cases.generated.json`;
2. choose both providers (or one provider);
3. enter `3` repetitions;
4. select an output parent folder;
5. review the modal data-sharing notice and start the run.

The five redaction cases have a case-specific single repetition. With ten
quality cases, three repetitions, five redaction cases, and both providers, the
runner performs 70 measured requests plus one unmeasured warm-up per provider.
Cancellation stops future requests and safely finalizes the collected results.

## 4. Result files

- `summary.json`: aggregate provider metrics;
- `response_results.csv`: one row per measured request;
- `manual_scoring.csv`: compatible evidence rows with subjective cells blank;
- `redaction_results.csv`: synthetic-canary boundary results;
- `runs.json`: full structured run records and diagnostic hashes;
- `warmups.json`: excluded warm-up status and timings;
- `manifest.json`: extension version and experiment configuration;
- `prompts/` and `raw-responses/`: auditable raw evidence.

Keep the complete timestamped folder. Do not report warm-up timings as measured
latency, and do not silently exclude errors.

## Failure-isolation check

To collect a controlled provider-failure observation, run an Ollama-only
evaluation while Ollama is stopped (or while a deliberately invalid test
endpoint is configured). The runner records the error and compares FLUSEC's
diagnostic hash before and after each failed request. Restore the normal endpoint
after the test. The runner never changes provider configuration automatically.

Web synchronization failure is a separate system test: disable the backend,
perform a local scan, and verify that local diagnostics remain available. The
web application is not involved in LLM generation and is intentionally not
modified by this evaluation kit.
