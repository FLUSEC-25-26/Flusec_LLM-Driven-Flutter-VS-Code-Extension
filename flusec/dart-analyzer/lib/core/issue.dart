// lib/core/issue.dart
//
// Shared finding model used by all FLUSEC analyzer components.
//
// IMPORTANT:
// - severity is the VS Code diagnostic severity.
// - securitySeverity is the security impact.
// - confidence is how certain FLUSEC is that the reported pattern is real.
// - maintainabilityScore/Level describe surrounding code context only.

/// During the current FLUSEC research phase all security findings are shown as
/// VS Code warnings. Security impact is carried separately in
/// [Issue.securitySeverity].
const String flusecSecurityDiagnosticSeverity = 'warning';

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

  /// Shared function-level maintainability context. These fields are omitted
  /// when the finding is not inside an executable function/method/constructor.
  final String? functionName;
  final int? complexity;
  final int? nestingDepth;
  final int? functionLoc;
  final int? maintainabilityScore;
  final String? maintainabilityLevel;

  // HSD-only contribution.
  final String? secretType;
  final List<Map<String, dynamic>>? taintFlow;

  // IDS-only contribution.
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
    this.maintainabilityScore,
    this.maintainabilityLevel,
    this.secretType,
    this.taintFlow,
    this.dataType,
    this.storageContext,
    this.component = 'hsd',
  });
}
