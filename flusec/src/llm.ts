const fetch = require("node-fetch");

// Type matching Ollama server response
type OllamaServerResponse = {
  response?: string;
  results?: { content?: string }[];
  output?: string;
};

/**
 * Get educational feedback from Ollama.
 */
export async function getLLMFeedback(issueMessage: string): Promise<string> {
  try {
    const res = await fetch("http://localhost:11434/api/generate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        model: "llama3.2",
        prompt: `Provide an educational feedback for the following Dart code issue: "${issueMessage}". Keep it short and clear.`,
        max_tokens: 150,
        temperature: 0.7,
        stream: false,
      }),
    });

    if (!res.ok) {
      console.error("Ollama response not OK:", res.statusText);
      return "Could not get LLM feedback.";
    }

    const data: OllamaServerResponse = await res.json();
    console.log("LLM raw response:", data);

    const feedback =
      data.response?.trim() ||
      data.results?.[0]?.content?.trim() ||
      data.output?.trim() ||
      "No feedback returned by LLM.";

    return feedback;
  } catch (err) {
    console.error("Error fetching LLM feedback:", err);
    return "Error getting LLM feedback.";
  }
}
