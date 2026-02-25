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

        // Enhanced prompt with IDS context - strict JSON formatting
        prompt: `You are a Flutter security expert. Analyze this security issue and respond ONLY with valid JSON.

${contextInfo}
Issue: ${issueMessage}

IMPORTANT: Your response must be ONLY valid JSON with this exact structure:
{
  "title": "Brief security issue title (max 10 words)",
  "severity": "${metadata?.riskLevel || 'MEDIUM'}",
  "category": "${metadata?.dataType || 'Sensitive Data'}",
  "why": "Clear explanation of why this is dangerous (2-3 sentences, focus on ${metadata?.storageContext || 'this storage context'})",
  "risk": "Specific attack scenario or security impact (1-2 sentences)",
  "fix": [
    "First concrete remediation step",
    "Second concrete remediation step",
    "Third concrete remediation step"
  ],
  "example": "// Secure implementation example\nfinal secureStorage = FlutterSecureStorage();\nawait secureStorage.write(key: 'token', value: sensitiveData);",
  "references": ["OWASP Mobile Top 10 - M2: Insecure Data Storage"]
}

Rules:
- Return ONLY the JSON object, no markdown, no explanations
- Use double quotes for all strings
- Keep code examples concise (3-5 lines max)
- Focus on ${metadata?.storageContext || 'the storage mechanism'} and ${metadata?.dataType || 'data type'}
- Ensure all JSON is properly escaped`.trim(),

        // Ollama generation controls (optimized for IDS feedback)
        options: {
          num_ctx: 2048,        // keep context small for speed
          num_predict: 350,     // increased for structured JSON response
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
    let raw = (data.response || "").trim();

    if (!raw) { return JSON.stringify({ error: "No feedback returned by LLM." }); }

    // Extract JSON from markdown code blocks if present
    const jsonMatch = raw.match(/```(?:json)?\s*([\s\S]*?)```/);
    if (jsonMatch) {
      raw = jsonMatch[1].trim();
    }

    // Validate JSON structure
    try {
      const parsed = JSON.parse(raw);
      // Ensure required fields exist
      if (!parsed.why || !parsed.risk || !parsed.fix) {
        console.warn("LLM response missing required fields, using raw response");
      }
      return raw; // Return valid JSON string
    } catch (parseError) {
      console.error("LLM returned invalid JSON:", raw);
      // Return a structured error response
      return JSON.stringify({
        error: "Invalid response format",
        rawResponse: raw.substring(0, 200) // Truncate for safety
      });
    }
  } catch (err) {
    console.error("Error fetching LLM feedback:", err);
    { return "Error getting LLM feedback."; }
  }
}
