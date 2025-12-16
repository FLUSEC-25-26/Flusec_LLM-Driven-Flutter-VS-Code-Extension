const fetch = require("node-fetch");

// Type matching Ollama server response
type OllamaServerResponse = {
  response?: string;
  done?: boolean;
};

export async function getLLMFeedback(issueMessage: string): Promise<string> {
  try {
    const res = await fetch("http://localhost:11434/api/generate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        model: "llama3.2:latest", // ✅ faster; change back if needed
        stream: false,

        // ✅ keep model warm so next hover is faster
        keep_alive: "10m",

        // ✅ short, structured prompt to reduce output time
        prompt: `
    You are a secure coding assistant for Flutter/Dart.
    Return JSON only (no markdown).

    {
      "why": "1 sentence why it is risky",
      "fix": ["1-3 short steps"],
      "example": "1 short example (optional)"
    }

    Issue: ${issueMessage}
            `.trim(),

        // ✅ Ollama token + speed controls (correct way)
        options: {
          num_predict: 120, // max tokens to generate
          temperature: 0.1, // less rambling
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
    console.log("LLM raw response:", data);

    const raw = (data.response || "").trim();
    if (!raw) {return "No feedback returned by LLM.";}

    // Optional: if model returns extra text, just return raw
    {return raw;}
  } catch (err) {
    console.error("Error fetching LLM feedback:", err);
    {return "Error getting LLM feedback.";}
  }
}
