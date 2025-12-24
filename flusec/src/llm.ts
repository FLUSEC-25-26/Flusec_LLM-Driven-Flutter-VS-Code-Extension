//llm.ts
const fetch = require("node-fetch");

// Type matching Ollama server response
type OllamaServerResponse = {
  response?: string;
  done?: boolean;
};

/**
 * Get educational feedback from Ollama (Option B: balanced).
 * - Still fast (short-ish output)
 * - More educational than the ultra-short version
 * - Local-only (privacy)
 */
export async function getLLMFeedback(issueMessage: string): Promise<string> {
  try {
    const res = await fetch("http://localhost:11434/api/generate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        model: "llama3.2:latest",
        stream: false,

        // Keep model warm so repeated hovers are fast
        keep_alive: "30m",

        // Balanced prompt: more educational, still constrained
        prompt: `
You are a secure coding assistant for Flutter/Dart.
Explain clearly and briefly.

Return JSON only (no markdown, no extra text):
{
  "why": "2-3 sentences explaining why this is a problem",
  "risk": "1 sentence describing impact",
  "fix": ["3 short steps to fix it"],
  "example": "very short Dart example"
}

Issue: ${issueMessage}
        `.trim(),

        // Ollama generation controls (balanced)
        options: {
          num_ctx: 2048,        // keep context small for speed
          num_predict: 160,     // enough for educational content, still fast
          temperature: 0.15,    // slight creativity, but not rambling
          top_p: 0.9,
          repeat_penalty: 1.1,
        },
      }),
    });

    if (!res.ok) {
      console.error("Ollama response not OK:", res.status, res.statusText);
      {return "Could not get LLM feedback.";}
    }

    const data: OllamaServerResponse = await res.json();
    const raw = (data.response || "").trim();

    if (!raw) {return "No feedback returned by LLM.";}

    return raw;
  } catch (err) {
    console.error("Error fetching LLM feedback:", err);
    {return "Error getting LLM feedback.";}
  }
}