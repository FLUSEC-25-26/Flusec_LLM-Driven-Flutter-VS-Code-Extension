// src/analyzer/findingTypes.ts
// Shared TypeScript contract for analyzer output.

export type FlusecComponent = "hsd" | "net" | "ids" | "iiv";
export type DiagnosticSeverityName =
  | "error"
  | "warning"
  | "information"
  | "hint";
export type SecuritySeverity = "critical" | "high" | "medium" | "low";
export type DetectionConfidence = "high" | "medium" | "low";
export type FindingCategory =
  | "vulnerability"
  | "secure_coding"
  | "maintainability";

export interface AnalyzerFinding {
  file?: string;
  ruleId: string;
  message: string;
  severity: DiagnosticSeverityName | string;
  securitySeverity?: SecuritySeverity | string | null;
  confidence?: DetectionConfidence | string | null;
  category?: FindingCategory | string | null;
  remediation?: string | null;
  cwe?: string | null;
  evidence?: Record<string, unknown> | null;
  line: number;
  column: number;
  component?: FlusecComponent | string;

  functionName?: string | null;
  complexity?: number | null;
  nestingDepth?: number | null;
  functionLoc?: number | null;
  secretType?: string | null;
  taintFlow?: unknown[] | null;

  riskLevel?: string | null;
  dataType?: string | null;
  storageContext?: string | null;
}
