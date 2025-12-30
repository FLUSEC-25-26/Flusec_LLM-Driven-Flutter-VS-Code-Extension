//llm.ts
const fetch = require("node-fetch");

// Type matching Ollama server response
type OllamaServerResponse = {
  response?: string;
  done?: boolean;
};

// IDS metadata for context-aware feedback
interface IDSMetadata {
  riskLevel?: string;      // CRITICAL, HIGH, MEDIUM, LOW
  dataType?: string;       // CREDENTIALS, PII, FINANCIAL, HEALTH
  storageContext?: string; // shared_prefs, file, sqlite, etc.
  recommendation?: string; // Specific remediation
}

/**
 * Get educational feedback from Ollama with IDS context awareness.
 * - Fast and educational
 * - Context-aware based on risk level, data type, and storage
 * - Local-only (privacy)
 */
export async function getLLMFeedback(
  issueMessage: string,
  metadata?: IDSMetadata
): Promise<string> {
  try {
    // Build context information from IDS metadata
    const contextInfo = metadata ? `
Risk Level: ${metadata.riskLevel || 'MEDIUM'}
Data Type: ${metadata.dataType || 'Sensitive Data'}
Storage Context: ${metadata.storageContext || 'Unknown'}
` : '';

    const res = await fetch("http://localhost:11434/api/generate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        model: "llama3.2:latest",
        stream: false,

        // Keep model warm so repeated hovers are fast
        keep_alive: "30m",

        // Enhanced prompt with IDS context
        prompt: `
You are a Flutter security expert specializing in insecure data storage.

${contextInfo}
Issue: ${issueMessage}

Provide educational feedback in JSON format (no markdown, no extra text):
{
  "why": "Explain why this ${metadata?.riskLevel || 'issue'} risk is dangerous for ${metadata?.dataType || 'sensitive data'} in ${metadata?.storageContext || 'this storage'}. 2-3 sentences.",
  "risk": "Specific security impact for ${metadata?.dataType || 'this data'} stored in ${metadata?.storageContext || 'this location'}. 1 sentence.",
  "fix": ["3 concrete steps to fix, prioritized by ${metadata?.riskLevel || 'severity'}"],
  "example": "Short secure Dart code example for ${metadata?.storageContext || 'this scenario'}"
}

Be specific to the storage type (${metadata?.storageContext || 'storage mechanism'}) and data sensitivity (${metadata?.dataType || 'data type'}).
        `.trim(),

        // Ollama generation controls (optimized for IDS feedback)
        options: {
          num_ctx: 2048,        // keep context small for speed
          num_predict: 200,     // increased for richer context
          temperature: 0.15,    // slight creativity, but not rambling
          top_p: 0.9,
          repeat_penalty: 1.1,
        },
      }),
    });

    if (!res.ok) {
      console.error("Ollama response not OK:", res.status, res.statusText);
      { return "Could not get LLM feedback."; }
    }

    const data: OllamaServerResponse = await res.json();
    const raw = (data.response || "").trim();

    if (!raw) { return "No feedback returned by LLM."; }

    return raw;
  } catch (err) {
    console.error("Error fetching LLM feedback:", err);
    { return "Error getting LLM feedback."; }
  }
}
