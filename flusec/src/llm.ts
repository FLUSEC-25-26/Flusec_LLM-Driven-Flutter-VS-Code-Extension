const fetch = require("node-fetch");

type OllamaServerResponse = {
  response?: string;
};

export async function getLLMFeedback(issueMessage: string): Promise<string> {
  try {
    const res = await fetch("http://localhost:11434/api/generate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        model: "llama3.2:latest",
        stream: false,
        keep_alive: "30m",
        prompt: `
Return JSON only:
{"why":"1 sentence","fix":["step1","step2"],"example":""}
Issue: ${issueMessage}
        `.trim(),
        options: {
          num_ctx: 2048,
          num_predict: 80,
          temperature: 0.0,
          top_p: 0.9,
          repeat_penalty: 1.1,
        },
      }),
    });

    if (!res.ok) {
      console.error("Ollama response not OK:", res.status, res.statusText);
      return "Could not get LLM feedback.";
    }

    const data: OllamaServerResponse = await res.json();
    return (data.response || "").trim() || "No feedback returned by LLM.";
  } catch (err) {
    console.error("Error fetching LLM feedback:", err);
    return "Error getting LLM feedback.";
  }
}
