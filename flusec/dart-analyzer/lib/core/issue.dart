// lib/core/issue.dart
//
// Shared finding model used by all FLUSEC analyzer components.
//
// IMPORTANT:
// - severity is the VS Code diagnostic severity: error | warning | information | hint
// - securitySeverity is the security impact: critical | high | medium | low
// - confidence is how certain FLUSEC is that the reported pattern is a true issue
//
// Keeping these values separate prevents a detector-confidence value from being
// confused with vulnerability impact.

class Issue {
  final String filePath;
  final String ruleId;
  final String message;

  /// VS Code diagnostic presentation severity.
  final String severity;

  final int line;
  final int column;

  /// Common security metadata.
  final String? securitySeverity;
  final String? confidence;
  final String? category;
  final String? remediation;
  final String? cwe;
  final Map<String, dynamic>? evidence;

  // HSD contribution.
  final String? functionName;
  final int? complexity;
  final int? nestingDepth;
  final int? functionLoc;
  final String? secretType;
  final List<Map<String, dynamic>>? taintFlow;

  // IDS contribution.
  final String? riskLevel;
  final String? dataType;
  final String? storageContext;

  /// Component that produced this issue: hsd | net | ids | iiv.
  final String component;

  Issue(
    this.filePath,
    this.ruleId,
    this.message,
    this.severity,
    this.line,
    this.column, {
    this.securitySeverity,
    this.confidence,
    this.category,
    this.remediation,
    this.cwe,
    this.evidence,
    this.functionName,
    this.complexity,
    this.nestingDepth,
    this.functionLoc,
    this.secretType,
    this.taintFlow,
    this.riskLevel,
    this.dataType,
    this.storageContext,
    this.component = 'hsd',
  });
}
