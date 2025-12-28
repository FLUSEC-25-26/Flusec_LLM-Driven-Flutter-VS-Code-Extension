// src/ui/dashboard.ts
//
// Webview dashboard for showing all findings from findings.json.
// - Reads findings.json (same path as analyzer)
// - Shows charts + maintainability hotspots + full table
// - Exports a PDF report (summary + charts data + findings table)

import * as vscode from "vscode";
import * as fs from "fs";
import * as path from "path";
import { findingsPathForFolder } from "../../analyzer/runAnalyzer.js";

/**
 * Generate a simple PDF report:
 * - Summary stats
 * - Complexity buckets
 * - Top rules / top files
 * - Truncated findings table
 */
// async function generatePdfReport(
//   filePath: string,
//   findings: any[]
// ): Promise<void> {
//   // 1) Create PDF and embed font
//   const pdfDoc = await PDFDocument.create();
//   const page = pdfDoc.addPage();
//   const font = await pdfDoc.embedFont(StandardFonts.Helvetica);

//   const { width, height } = page.getSize();
//   let y = height - 40;
//   const marginX = 40;
//   const lineGap = 14;

//   function drawLine(text: string, opts: { size?: number; color?: any } = {}) {
//     const size = opts.size ?? 12;
//     const color = opts.color ?? rgb(0, 0, 0);

//     // Basic wrapping: if line is too long, split by spaces
//     const maxWidth = width - marginX * 2;
//     const words = text.split(" ");
//     let line = "";
//     for (const w of words) {
//       const testLine = line ? line + " " + w : w;
//       const textWidth = font.widthOfTextAtSize(testLine, size);
//       if (textWidth > maxWidth) {
//         page.drawText(line, {
//           x: marginX,
//           y,
//           size,
//           font,
//           color,
//         });
//         y -= lineGap;
//         line = w;
//       } else {
//         line = testLine;
//       }
//     }
//     if (line) {
//       page.drawText(line, {
//         x: marginX,
//         y,
//         size,
//         font,
//         color,
//       });
//       y -= lineGap;
//     }

//     // New page if we go too low
//     if (y < 60) {
//       y = height - 40;
//       pdfDoc.addPage();
//     }
//   }

//   // --- Compute stats (same as before) ---
//   const total = findings.length;
//   const errors = findings.filter(
//     (f) => String(f.severity || "").toLowerCase() === "error"
//   ).length;
//   const warnings = total - errors;

//   let lowCx = 0,
//     medCx = 0,
//     highCx = 0;

//   const ruleCount = new Map<string, number>();
//   const fileCount = new Map<string, number>();
//   let testSecrets = 0;

//   findings.forEach((f) => {
//     const cx = typeof f.complexity === "number" ? f.complexity : 0;
//     const file = String(f.file || "");

//     if (cx > 0 && cx <= 5) {lowCx++;}
//     else if (cx > 5 && cx <= 10) {medCx++;}
//     else if (cx > 10) {highCx++;}

//     if (file.endsWith("_test.dart")) {
//       testSecrets++;
//     }

//     const ruleKey = String(f.ruleName || f.ruleId || "unknown");
//     ruleCount.set(ruleKey, (ruleCount.get(ruleKey) || 0) + 1);
//     fileCount.set(file, (fileCount.get(file) || 0) + 1);
//   });

//   const topN = 5;
//   const topRules = Array.from(ruleCount.entries())
//     .sort((a, b) => b[1] - a[1])
//     .slice(0, topN);
//   const topFiles = Array.from(fileCount.entries())
//     .sort((a, b) => b[1] - a[1])
//     .slice(0, topN);

//   // --- Title ---
//   drawLine("Flusec Findings Report", { size: 18 });
//   y -= 6;

//   // --- Summary ---
//   drawLine("Summary", { size: 14 });
//   drawLine(`Total findings: ${total}`);
//   drawLine(`Errors: ${errors}`);
//   drawLine(`Warnings: ${warnings}`);
//   drawLine(
//     `Secrets by function complexity: low=${lowCx}, medium=${medCx}, high=${highCx}`
//   );
//   drawLine(`Secrets in test files (*_test.dart): ${testSecrets}`);
//   y -= 6;

//   // --- Top Rules ---
//   drawLine("Top Rules", { size: 14 });
//   if (topRules.length === 0) {
//     drawLine("No rules.");
//   } else {
//     topRules.forEach(([rule, count]) => {
//       drawLine(`- ${rule}: ${count}`);
//     });
//   }
//   y -= 6;

//   // --- Top Files ---
//   drawLine("Top Files", { size: 14 });
//   if (topFiles.length === 0) {
//     drawLine("No files.");
//   } else {
//     topFiles.forEach(([file, count]) => {
//       drawLine(`- ${file || "<unknown>"}: ${count}`);
//     });
//   }
//   y -= 6;

//   // --- Findings Table (truncated) ---
//   drawLine("Findings (first 40)", { size: 14 });
//   const maxRows = 40;
//   const rows = findings.slice(0, maxRows);

//   rows.forEach((f, idx) => {
//     const sev = f.severity || "";
//     const rule = f.ruleName || f.ruleId || "";
//     const msg = f.message || "";
//     const file = f.file || "";
//     const line = f.line || "";
//     const fn = f.functionName || "";
//     const cx =
//       typeof f.complexity === "number" ? `Cx=${f.complexity}` : "";
//     const depth =
//       typeof f.nestingDepth === "number" ? `,Depth=${f.nestingDepth}` : "";
//     const size =
//       typeof f.functionLoc === "number" ? `,Size=${f.functionLoc} LOC` : "";
//     const metrics = cx || depth || size ? cx + depth + size : "";

//     drawLine(
//       `${idx + 1}. [${sev}] [${rule}] ${msg}`
//     );
//     drawLine(
//       `    File: ${file}  Line: ${line}  Function: ${fn}  Metrics: ${metrics}`
//     );
//   });

//   if (findings.length > maxRows) {
//     drawLine(
//       `(+ ${findings.length - maxRows} more findings not shown in this PDF)`
//     );
//   }

//   // 2) Save to disk
//   const pdfBytes = await pdfDoc.save();
//   fs.writeFileSync(filePath, pdfBytes);
// }




/**
 * Open the Flusec Findings dashboard webview.
 */
export function openDashboard(context: vscode.ExtensionContext) {
  const panel = vscode.window.createWebviewPanel(
    "flusecDashboard",
    "Flusec Findings",
    vscode.ViewColumn.Beside,
    {
      enableScripts: true,
      retainContextWhenHidden: true,
    }
  );

  const webview = panel.webview;

  // Root folder for dashboard assets
  const hsdRoot = vscode.Uri.joinPath(
    context.extensionUri,
    "src",
    "web",
    "hsd"
  );

  const styleRoot = vscode.Uri.joinPath(
    context.extensionUri,
    "src",
    "web"
  );

  const htmlPath = vscode.Uri.joinPath(hsdRoot, "dashboard.html");
  const cssPath = vscode.Uri.joinPath(styleRoot, "css", "dashboard.css");
  const jsPath = vscode.Uri.joinPath(styleRoot, "js", "dashboard.js");

  const cssUri = webview.asWebviewUri(cssPath);
  const jsUri = webview.asWebviewUri(jsPath);

  let html = "<html><body>Dashboard not found</body></html>";
  if (fs.existsSync(htmlPath.fsPath)) {
    try {
      const raw = fs.readFileSync(htmlPath.fsPath, "utf8");
      html = raw
        .replace(/{{cssUri}}/g, cssUri.toString())
        .replace(/{{jsUri}}/g, jsUri.toString())
        .replace(/{{cspSource}}/g, webview.cspSource);
    } catch {
      html = "<html><body>Failed to load dashboard template</body></html>";
    }
  }

  panel.webview.html = html;

  // Decide which workspace folder to read findings from.
  const folder = vscode.workspace.workspaceFolders?.[0];
  if (!folder) {
    panel.webview.postMessage({ command: "loadFindings", data: [] });
    return;
  }

  // MUST match the path logic used in the analyzer.
  const findingsPath = findingsPathForFolder(folder);

  /**
   * Read findings.json and send data to the webview.
   */
  const sendFindings = () => {
    let data: any[] = [];
    if (fs.existsSync(findingsPath)) {
      try {
        data = JSON.parse(fs.readFileSync(findingsPath, "utf8"));
        if (!Array.isArray(data)) {
          data = [];
        }
      } catch {
        data = [];
      }
    }
    panel.webview.postMessage({ command: "loadFindings", data });
  };

  // Send once when opened.
  sendFindings();

  // Optional: refresh when the dashboard becomes visible again.
  panel.onDidChangeViewState(() => {
    if (panel.visible) {
      sendFindings();
    }
  });

  // Handle messages from the webview (e.g., "reveal" or "exportPdf").
  // Handle messages from the webview (e.g., "reveal").
panel.webview.onDidReceiveMessage(async (msg) => {
  if (msg?.command === "reveal") {
    const file = String(msg.file || "");
    const line = Math.max(0, (msg.line ?? 1) - 1);
    const col = Math.max(0, (msg.column ?? 1) - 1);

    try {
      const doc = await vscode.workspace.openTextDocument(
        vscode.Uri.file(file)
      );
      const editor = await vscode.window.showTextDocument(doc, {
        preview: false,
      });
      const pos = new vscode.Position(line, col);
      editor.selection = new vscode.Selection(pos, pos);
      editor.revealRange(
        new vscode.Range(pos, pos),
        vscode.TextEditorRevealType.InCenter
      );
    } catch (e) {
      vscode.window.showErrorMessage(
        "Failed to open file from dashboard: " + String(e)
      );
    }
  }
});

}
