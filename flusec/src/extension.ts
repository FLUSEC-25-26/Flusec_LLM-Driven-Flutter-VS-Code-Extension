// src/extension.ts
//
// This is the main entry point for the VS Code extension.
// We keep it very small: it just activates components (HSD now; later Network/Storage/Validation).
//
// ✅ WHY do this?
// - When you add the other 3 components, you won't touch the HSD logic.
// - Each component registers its own commands and wiring.
// - Shared services (diagnostics, dashboard, hover, runner) are reused.

import * as vscode from "vscode";
import { registerHsdComponent } from "./components/hsd/index";
import { registerHoverProvider } from "./hover/hoverProvider";
import { disposeDiagnostics } from "./shared/diagnostics";

export function activate(context: vscode.ExtensionContext) {
  // ✅ Component registration
  // Your component (HSD) registers:
  // - flusec.scanFile
  // - flusec.manageRules
  // - flusec.openFindings
  // - auto scan on save + typing (debounced)
  registerHsdComponent(context);

  // ✅ Shared hover provider (LLM feedback) for ALL components
  // Later, even if Network/Storage/Validation produce diagnostics,
  // hover will work automatically because it reads diagnostics.
  registerHoverProvider(context);

  // When you implement other components, you do:
  // registerNetworkComponent(context);
  // registerStorageComponent(context);
  // registerValidationComponent(context);
}

export function deactivate() {
  // Always dispose diagnostics cleanly
  disposeDiagnostics();
}
