// src/hover/format.ts
//
// Formats hover output nicely.
// If LLM returns JSON (why/fix/example), we render Markdown.
// If it returns plain text, we render plain markdown text.

import * as vscode from "vscode";

export function formatFeedbackForHover(raw: string): vscode.MarkdownString {
  const md = new vscode.MarkdownString();
  md.isTrusted = false;

  try {
    const obj = JSON.parse(raw);

    md.appendMarkdown(`### 💡 Educational feedback\n\n`);

    if (obj.why) {
      md.appendMarkdown(`**Why**: ${obj.why}\n\n`);
    }

    if (Array.isArray(obj.fix) && obj.fix.length > 0) {
      md.appendMarkdown(`**Fix**:\n`);
      for (const step of obj.fix.slice(0, 3)) {
        md.appendMarkdown(`- ${String(step).replace(/^\d+\.\s*/, "")}\n`);
      }
      md.appendMarkdown(`\n`);
    }

    if (obj.example && String(obj.example).trim()) {
      md.appendMarkdown(`**Example**:\n\n`);
      md.appendCodeblock(String(obj.example), "dart");
    }

    return md;
  } catch {
    // fallback if JSON parsing fails
    md.appendMarkdown(`### 💡 Educational feedback\n\n`);
    md.appendMarkdown(raw);
    return md;
  }
}
