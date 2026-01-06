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

export async function getLLMFeedback(
  issueMessage: string,
  codeSnippet?: string
): Promise<string> {
  try {
    // 1. Detect if this is an Input Validation issue or a Secret issue
    const isIVD = issueMessage.includes("Injection") || 
                  issueMessage.includes("Validation") || 
                  issueMessage.includes("Upload") || 
                  issueMessage.includes("Deep Link");

    // 2. Dynamic System Prompt
    let promptInstructions = "";

    if (isIVD) {
      // INSTRUCTIONS FOR IVD
      promptInstructions = `
        Context: Flutter/Dart Security (Input Validation).
        The user has a code vulnerability: ${issueMessage}.
        
        Guidelines:
        - Explain why this input is dangerous (SQLi, Command Injection, XSS, etc).
        - Suggest sanitization or parameterized queries.
        - DO NOT talk about "rotating secrets" here. Talk about validating input.
      `;
    } else {
      // INSTRUCTIONS FOR HSD (Existing)
      promptInstructions = `
        Context: Flutter/Dart Security (Hardcoded Secrets).
        If it looks like an API key/token:
        - Say real secrets must live on backend.
        - Mention attackers can extract strings from APK/IPA.
        - DO NOT suggest hardcoding secrets anywhere.
      `;
    }

    const res = await fetch("http://localhost:11434/api/generate", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        model: "llama3.2:latest",
        stream: false,
        keep_alive: "30m",
        format: "json",
        prompt: `
        You are a Flutter/Dart security assistant.
        ${promptInstructions}

        Return ONLY a single JSON object:
        {
          "why": "2 sentences explaining the vulnerability.",
          "fix": ["3 short, practical Dart code steps to fix it."],
          "maintainability": "1 sentence starting with 'Because complexity is X...' based on provided metrics.",
          "example": "Short, secure Dart code snippet fixing this specific issue"
        }

        Issue: ${issueMessage}
        Code: ${codeSnippet || "// no code"}
        `.trim(),
        options: {
          num_ctx: 2048,
          num_predict: 250,
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
    console.error("Error fetching LLM feedback:", err);
    return "Error getting LLM feedback.";
  }
}