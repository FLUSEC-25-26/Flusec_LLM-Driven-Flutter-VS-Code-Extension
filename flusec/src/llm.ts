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
export async function getLLMFeedback(issueMessage: string, codeSnippet?: string): Promise<string> {
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
        Return ONLY one valid JSON object (no markdown, no extra text) in this shape:
        {
          "why": "2 short sentences explaining the security problem and 1 short sentence on impact.",
          "fix": ["3 short, practical Flutter/Dart fixes."],
          "maintainability": "1 sentence starting with: 'Because complexity is X, nesting is Y, and size is Z, ...'",
          "example": "Very short safe Flutter/Dart example (no real secrets)."
        }

        Context:
        - This is Flutter/Dart mobile app code (APK/IPA can be reverse-engineered).
        - If it looks like an API key / token / credential / backend secret:
          - Say real secrets must live on the server or secure config, not in the client.
          - Mention attackers can extract client-side secrets from APK/IPA.
        - DO NOT suggest hardcoding secrets anywhere (even in another file).
        - Do NOT suggest client-side encryption as the main solution.

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

        // Ollama generation controls (balanced)
        options: {
          num_ctx: 2048,        // keep context small for speed
          num_predict: 200,     // enough for educational content, still fast
          temperature: 0.2,    // slight creativity, but not rambling
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
