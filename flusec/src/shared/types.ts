// src/shared/types.ts
//
// Shared types used by ALL components.
//
// ✅ Finding = one detected issue from analyzer stdout.
// Your Dart analyzer prints JSON objects like:
// { ruleId, severity, message, line, column, functionName?, complexity? }
//
// Extension enriches and stores them per file for dashboard & history.

export type Severity = "warning" | "error";

export interface Finding {
  // Which Dart file has the issue
  file: string;

  // Location (1-based from analyzer)
  line: number;
  column: number;

  // Rule metadata
  ruleId: string;
  severity: Severity;

  // Human-readable message from analyzer
  message: string;

  // Optional extras (your analyzer now supports these)
  functionName?: string;
  complexity?: number;

  // Optional (if you later decide to store snippet/endColumn etc.)
  snippet?: string;
  endColumn?: number;

  // Component ID (so you can separate findings by component)
  // Example: "hsd", "network", "storage", "validation"
  component?: string;
}
