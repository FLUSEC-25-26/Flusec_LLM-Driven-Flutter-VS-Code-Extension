// src/llm.ts
//
// Local Ollama client for FLUSEC educational feedback.
// Uses llama3.2 via Ollama HTTP API and returns a JSON string
// that hoverLLM.ts will parse into a rich hover.
//
// We try to:
// - keep responses short (fast)
// - enforce JSON format using Ollama's `format: "json"`
// - be robust if the model still returns junk.

const fetch = require("node-fetch");

// Type matching Ollama server response (simplified)
type OllamaServerResponse = {
  response?: string;
  done?: boolean;
};

// Try to extract the first top-level JSON object from raw text.
function extractJsonObject(raw: string): string | null {
  const first = raw.indexOf("{");
  const last = raw.lastIndexOf("}");
  if (first === -1 || last === -1 || last <= first) {
    return null;
  }
  return raw.slice(first, last + 1);
}

/**
 * Get educational feedback from Ollama.
 * Returns a string that is ideally a JSON object as text.
 */
export async function getLLMFeedback(
  issueMessage: string,
  codeSnippet?: string
): Promise<string> {
  try {
    const res = await fetch("http://localhost:11434/api/generate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        model: "llama3.2:latest",
        stream: false,
        keep_alive: "30m",

        // Ask Ollama to produce strict JSON output.
        format: "json",

        // Prompt kept tight to avoid long responses.
        prompt: `
        You are a Flutter/Dart security assistant integrated into a VS Code extension for hardcoded secret detection.

        Return ONLY a single JSON object with these fields:

        {
          "why": "2 short sentences explaining the security problem and 1 short sentence on impact.",
          "fix": ["3 very short, practical Flutter/Dart fixes as separate items."],
          "maintainability": "1 sentence starting with: 'Because complexity is X, nesting is Y, and size is Z, ...'",
          "example": "Very short best security practice Flutter/Dart example related to this issue"
        }

        Guidelines:
        - Context: This is Flutter/Dart mobile app code (APK/IPA can be reverse-engineered).
        - If it looks like an API key / token / credential / backend secret:
          - Say real secrets must live on the server or a secure backend config, not in the client.
          - Mention attackers can extract client-side secrets from APK/IPA.
        - DO NOT suggest hardcoding secrets anywhere (even in another file).
        - DO NOT suggest client-side encryption as the main solution.

        For maintainability:
        - Read X, Y, Z from the text in Issue details like:
          "Function complexity: medium, nesting: high, size: small".
        - Use those exact words.
        - Write exactly ONE sentence that starts with:
          "Because complexity is X, nesting is Y, and size is Z, "
          and then briefly say how hard or risky it is to refactor.

        Issue details:
        ${issueMessage}

        Code (Dart):
        ${codeSnippet || "// (no code snippet provided)"}
         `.trim(),

        // Balanced generation controls: short, deterministic, fast.
        options: {
          num_ctx: 2048,
          num_predict: 220,   // enough for the 4 fields, but not huge
          temperature: 0.1,   // low = more deterministic, better JSON
          top_p: 0.9,
          repeat_penalty: 1.05,
        },
      }),
    });

    if (!res.ok) {
      console.error("Ollama response not OK:", res.status, res.statusText);
      return "Could not get LLM feedback.";
    }

    const data: OllamaServerResponse = await res.json();
    const raw = (data.response || "").trim();

    if (!raw) {
      return "No feedback returned by LLM.";
    }

    // Try to isolate a proper JSON object.
    const jsonCandidate = extractJsonObject(raw);
    if (jsonCandidate) {
      return jsonCandidate;
    }

    // Fallback: just return raw text (hoverLLM will treat it as plain text).
    return raw;
  } catch (err) {
    console.error("Error fetching LLM feedback:", err);
    return "Error getting LLM feedback.";
  }
}
