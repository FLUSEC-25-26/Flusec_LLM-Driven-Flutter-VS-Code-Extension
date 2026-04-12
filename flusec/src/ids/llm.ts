// src/ids/llm.ts
//
// LLM client for insecure data storage educational feedback.
// Uses a separate prompt tuned for storage security issues.
// Keeps the same Ollama local-only approach as HSD/NET but with
// storage-specific response shape and prompt focus.

const fetch = require("node-fetch");

// A typed structure for the educational feedback we expect from the LLM.
export type IdsLLMFeedback = {
  why: string;
  risk: string;
  fix: string[];
  example: string;
};

// Type matching the Ollama server response.
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

// Length limiter to keep hover compact
function truncate(s: string, n = 320): string {
  s = String(s).trim();
  return s.length > n ? s.slice(0, n) + "…" : s;
}

/**
 * Get educational feedback from Ollama for insecure data storage issues.
 * - Local-only (privacy)
 * - Parsed and validated JSON for clean rendering in hover
 */
export async function getIdsLLMFeedback(
  issueMessage: string
): Promise<IdsLLMFeedback | null> {
  try {
    const res = await fetch("http://localhost:11434/api/generate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        model: "llama3.2:latest",
        stream: false,

        // Keep model warm so repeated hovers are fast
        keep_alive: "30m",

        // Force Ollama to output strict JSON
        format: "json",

        // Storage-security-focused prompt
        prompt: `
You are a secure coding assistant for Flutter/Dart.
Focus on data storage security: encryption at rest, SharedPreferences,
SQLite, file storage, keychain/keystore, flutter_secure_storage,
external storage risks, logging sensitive data, cache protection.
Explain clearly and briefly.

Return ONLY a single JSON object with these fields:
{
  "why": "2-3 sentences explaining why this insecure storage pattern is dangerous",
  "risk": "1 sentence describing the impact (e.g. data theft from rooted device, backup extraction)",
  "fix": ["3 short steps to fix it"],
  "example": "very short Dart example showing the secure storage alternative"
}

Issue: ${issueMessage}
        `.trim(),

        // Ollama generation controls (balanced for storage feedback)
        options: {
          num_ctx: 2048,
          num_predict: 220,
          temperature: 0.1,
          top_p: 0.9,
          repeat_penalty: 1.05,
        },
      }),
    });

    if (!res.ok) {
      console.error("Ollama response not OK:", res.status, res.statusText);
      return null;
    }

    const data: OllamaServerResponse = await res.json();
    const raw = (data.response || "").trim();
    if (!raw) {
      return null;
    }

    // Parse JSON — try direct first, then fallback to extraction
    let parsed: any;
    try {
      parsed = JSON.parse(raw);
    } catch {
      // Fallback: try to extract JSON object from raw text
      const extracted = extractJsonObject(raw);
      if (extracted) {
        try {
          parsed = JSON.parse(extracted);
        } catch {
          console.error("IDS LLM returned non-JSON:", raw);
          return null;
        }
      } else {
        console.error("IDS LLM returned non-JSON:", raw);
        return null;
      }
    }

    // Normalize/validate shape
    const feedback: IdsLLMFeedback = {
      why: truncate(String(parsed.why ?? "")),
      risk: truncate(String(parsed.risk ?? ""), 200),
      fix: Array.isArray(parsed.fix)
        ? parsed.fix.map((step: unknown) => truncate(String(step), 160))
        : [],
      example: String(parsed.example ?? ""),
    };

    // Basic validation to avoid empty cards
    if (
      !feedback.why &&
      !feedback.risk &&
      feedback.fix.length === 0 &&
      !feedback.example
    ) {
      return null;
    }
    return feedback;
  } catch (err) {
    console.error("Error fetching IDS LLM feedback:", err);
    return null;
  }
}