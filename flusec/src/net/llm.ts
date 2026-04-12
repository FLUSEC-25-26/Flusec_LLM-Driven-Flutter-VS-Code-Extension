// src/net/llm.ts
//
// LLM client for network security educational feedback.
// Uses a separate prompt tuned for insecure network communication issues.
// Keeps the same Ollama local-only approach as HSD but with different
// response shape and prompt focus.

const fetch = require("node-fetch");

// A typed structure for the educational feedback we expect from the LLM.
export type LLMFeedback = {
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

/**
 * Get educational feedback from Ollama for network security issues.
 * - Local-only (privacy)
 * - Parsed and validated JSON for clean rendering in hover
 */
export async function getNetLLMFeedback(
  issueMessage: string
): Promise<LLMFeedback | null> {
  try {
    const res = await fetch("http://localhost:11434/api/generate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        model: "llama3.2:latest",
        stream: false,

        // Keep model warm so repeated hovers are fast
        keep_alive: "30m",

        // Network-security-focused prompt
        prompt: `
You are a secure coding assistant for Flutter/Dart.
Focus on network communication security: TLS/SSL, certificate pinning,
plaintext HTTP, insecure WebSocket, missing timeout, etc.
Explain clearly and briefly.

Return JSON only (no markdown, no extra text):
{
  "why": "2-3 sentences explaining why this is a network security problem",
  "risk": "1 sentence describing the impact (e.g. MITM, data leak)",
  "fix": ["3 short steps to fix it"],
  "example": "very short Dart example showing the secure alternative"
}

Issue: ${issueMessage}
        `.trim(),

        // Ollama generation controls (balanced)
        options: {
          num_ctx: 2048, // keep context small for speed
          num_predict: 160, // enough for educational content, still fast
          temperature: 0.15, // slight creativity, but not rambling
          top_p: 0.9,
          repeat_penalty: 1.1,
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

    // Parse JSON strictly
    let parsed: any;
    try {
      parsed = JSON.parse(raw);
    } catch (e) {
      console.error("NET LLM returned non-JSON:", raw);
      return null;
    }

    // Normalize/validate shape
    const feedback: LLMFeedback = {
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
    console.error("Error fetching NET LLM feedback:", err);
    return null;
  }
}

// Optional: length limiter to keep hover compact
function truncate(s: string, n = 320): string {
  s = String(s).trim();
  return s.length > n ? s.slice(0, n) + "…" : s;
}