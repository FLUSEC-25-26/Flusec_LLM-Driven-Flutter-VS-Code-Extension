// src/iiv/llm.ts
//
// Local Ollama client for FLUSEC educational feedback (Input Validation).
// Uses llama3.2 via Ollama HTTP API and returns a JSON string
// that hoverLLM.ts will parse into a rich hover.

const fetch = require("node-fetch");

type OllamaServerResponse = {
  response?: string;
  done?: boolean;
};

function extractJsonObject(raw: string): string | null {
  const first = raw.indexOf("{");
  const last = raw.lastIndexOf("}");
  if (first === -1 || last === -1 || last <= first) {
    return null;
  }
  return raw.slice(first, last + 1);
}

// FIXED: Renamed to match the import in hoverLLM.ts
export async function getIivLLMFeedback(
  issueMessage: string,
  codeSnippet?: string
): Promise<string> {
  try {
    const promptInstructions = `
      Context: Flutter/Dart Security (Input Validation).
      The user has a code vulnerability: ${issueMessage}.
      
      Guidelines:
      - Explain why this input is dangerous (SQLi, Command Injection, XSS, etc).
      - Suggest specific sanitization, allow-listing, or parameterized queries.
      - Focus strictly on data integrity and input handling.
    `;

    const res = await fetch("http://localhost:11434/api/generate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        model: "llama3.2:latest",
        stream: false,
        keep_alive: "30m",
        format: "json",
        prompt: `
        You are a Flutter/Dart security assistant specializing in Input Validation.
        ${promptInstructions}

        Return ONLY a single JSON object:
        {
          "why": "2 sentences explaining the vulnerability.",
          "risk": "1 sentence describing the security impact.", 
          "fix": ["3 short, practical Dart code steps to fix it."],
          "example": "Short, secure Dart code snippet fixing this specific issue"
        }

        Issue: ${issueMessage}
        Code: ${codeSnippet || "// no code"}
        `.trim(),
        options: {
          num_ctx: 2048,
          num_predict: 500,
          temperature: 0.1,
        },
      }),
    });

    if (!res.ok) {
      return "Could not get LLM feedback.";
    }

    const data: OllamaServerResponse = await res.json();
    const raw = (data.response || "").trim();
    const jsonCandidate = extractJsonObject(raw);
    return jsonCandidate || raw;

  } catch (err) {
    console.error("Error fetching IIV LLM feedback:", err);
    return "Error getting LLM feedback.";
  }
}