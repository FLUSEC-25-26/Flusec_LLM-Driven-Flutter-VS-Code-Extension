// src/hover/hoverProvider.ts
//
// Hover provider reads diagnostics in the editor.
// If the cursor is on a diagnostic range, it will show LLM feedback.
//
// ✅ Works automatically for all components because diagnostics are shared.

import * as vscode from "vscode";
import { enqueueLLMRequest, getCachedFeedback, makeKey } from "./llmQueue";
import { formatFeedbackForHover } from "./format";

export function registerHoverProvider(context: vscode.ExtensionContext) {
  const provider = vscode.languages.registerHoverProvider("dart", {
    provideHover: async (document, position) => {
      const diags = vscode.languages.getDiagnostics(document.uri);

      for (const diag of diags) {
        if (diag.range.contains(position)) {
          const key = makeKey(document.uri, diag.range);

          const cached = getCachedFeedback(key);
          if (cached) {
            return new vscode.Hover(formatFeedbackForHover(cached));
          }

          enqueueLLMRequest(key, diag.message);
          return new vscode.Hover("💡 Loading feedback from LLM...");
        }
      }

      return undefined;
    },
  });

  context.subscriptions.push(provider);
}
